from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login, logout, get_user_model, authenticate
from django.contrib.auth.decorators import login_required, permission_required
from django.contrib.auth.views import LoginView
from django.contrib.auth.forms import SetPasswordForm, AuthenticationForm
from django.contrib import messages
from django.http import JsonResponse, HttpResponse, FileResponse
from django.urls import reverse_lazy
from django.utils import timezone
from django.views.decorators.http import require_POST
from django.core.paginator import Paginator, PageNotAnInteger, EmptyPage
from django.db.models import Q, Sum, Avg, F, DurationField, ExpressionWrapper
from django.views.generic import FormView
from django.contrib.auth.forms import PasswordResetForm
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.views.generic.base import TemplateView
from django.utils.translation import gettext_lazy as _
from django.utils.decorators import method_decorator
from django.core.exceptions import ValidationError
from django.contrib.sessions.models import Session
from django.conf import settings
from django.core.cache import cache
from django.db import transaction
import logging
import json
import csv
from io import StringIO, BytesIO
from datetime import datetime, timedelta
import os
import hashlib
import base64
import pyotp
import qrcode
import qrcode.image.svg
from functools import wraps
from .models import (
    Role, AuditLog, DataRequest, DataCategory,
    DataBreach, BreachTimeline, CrossBorderTransfer,
    CookieConsent, DataTransfer, ProcessingActivity,
    DataProcessingActivity, ProcessingRequirement,
    UserSession, PrivacyPolicy, UserPrivacyPolicyConsent,
    DataExport, TwoFactorAuth, TrustedDevice, TrustSettings,
    ActivityLog, DeletionTask, BreachNotification,
    ConsentRecord, Task, Report, ReportSchedule, SystemSettings
)
from .forms import (
    RegistrationForm, DataRequestForm, CookiePreferencesForm,
    CrossBorderTransferForm, TwoFactorSetupForm
)
from .monitoring import breach_monitor
from django_otp.plugins.otp_totp.models import TOTPDevice
from django_otp.util import random_hex
from .decorators import (
    role_required, permission_required, dpo_required,
    admin_required, compliance_officer_required, any_staff_role_required
)
from .services.compliance_checker import ComplianceCheckerService
import pytz
from celery import shared_task
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table
from reportlab.lib.styles import getSampleStyleSheet
from .utils import get_client_ip
from django.template import TemplateDoesNotExist
from django.conf import settings as django_settings
import xml.etree.ElementTree as ET
import io
from django.contrib.auth.models import Group
from django.contrib.auth.models import Permission

User = get_user_model()
logger = logging.getLogger(__name__)

def rate_limit(key_prefix, limit=5, period=300):
    """
    Rate limiting decorator
    :param key_prefix: Prefix for the cache key
    :param limit: Number of allowed requests
    :param period: Time period in seconds
    """
    def decorator(func):
        @wraps(func)
        def wrapper(request, *args, **kwargs):
            client_ip = request.META.get('REMOTE_ADDR', '')
            cache_key = f"{key_prefix}:{client_ip}"
            
            # Get current request count
            requests = cache.get(cache_key, 0)
            
            if requests >= limit:
                messages.error(request, _('Too many attempts. Please try again later.'))
                return redirect('gdpr_platform:login')
            
            # Increment request count
            cache.set(cache_key, requests + 1, period)
            
            return func(request, *args, **kwargs)
        return wrapper
    return decorator

class CustomPasswordResetView(FormView):
    template_name = 'registration/password_reset_form.html'
    form_class = PasswordResetForm
    success_url = reverse_lazy('gdpr_platform:custom_password_reset_done')
    email_template_name = 'emails/password_reset_email.html'
    subject_template_name = 'emails/password_reset_subject.txt'
    
    @method_decorator(rate_limit('password_reset', limit=3, period=3600))
    def post(self, request, *args, **kwargs):
        return super().post(request, *args, **kwargs)
    
    def form_valid(self, form):
        """Add AI security checks and rate limiting before processing the reset request"""
        email = form.cleaned_data['email']
        user_ip = self.request.META.get('REMOTE_ADDR', '')
        
        # Hash the IP for security logging
        hashed_ip = hashlib.sha256(user_ip.encode()).hexdigest()
        
        # Log the reset attempt for AI monitoring
        AuditLog.objects.create(
            user=None,
            action='password_reset_requested',
            resource_type='user',
            resource_id=email,
            ip_address=hashed_ip,  # Store hashed IP
            user_agent=self.request.META.get('HTTP_USER_AGENT', ''),
            details={
                'email': email,
                'timestamp': str(timezone.now()),
                'request_origin': hashed_ip
            }
        )
        
        # Process the password reset
        opts = {
            'use_https': self.request.is_secure(),
            'token_generator': default_token_generator,
            'email_template_name': self.email_template_name,
            'subject_template_name': self.subject_template_name,
            'request': self.request,
            'extra_email_context': {
                'user_ip': hashed_ip,
                'timestamp': timezone.now().strftime('%Y-%m-%d %H:%M:%S UTC'),
                'security_level': 'Enhanced',
                'ai_verified': True
            }
        }
        
        try:
            form.save(**opts)
        except Exception as e:
            logger.error(f"Password reset error for {email}: {str(e)}")
            # Don't reveal if the email exists
            pass
        
        return super().form_valid(form)

class PasswordResetConfirmView(FormView):
    template_name = 'registration/password_reset_confirm.html'
    form_class = SetPasswordForm
    success_url = reverse_lazy('gdpr_platform:custom_password_reset_complete')
    token_generator = default_token_generator

    def get_user(self, uidb64):
        try:
            uid = urlsafe_base64_decode(uidb64).decode()
            user = User.objects.get(pk=uid)
            if not user.is_active:
                return None
            return user
        except (TypeError, ValueError, OverflowError, User.DoesNotExist, ValidationError):
            return None

    def get_form(self, form_class=None):
        user = self.get_user(self.kwargs.get('uidb64'))
        token = self.kwargs.get('token')
        
        if user is not None and self.token_generator.check_token(user, token):
            return self.form_class(user, **self.get_form_kwargs())
        return None

    @method_decorator(rate_limit('password_reset_confirm', limit=3, period=3600))
    def post(self, request, *args, **kwargs):
        return super().post(request, *args, **kwargs)

    def form_valid(self, form):
        user = form.user
        new_password = form.cleaned_data['new_password1']
        
        try:
        # Set the new password
            form.save()
            
            # Invalidate all existing sessions for security
            Session.objects.filter(expire_date__gte=timezone.now()).delete()
        
        # Log the successful password reset
            AuditLog.objects.create(
                user=user,
                action='password_reset_completed',
                resource_type='user',
                resource_id=str(user.id),
                    ip_address=hashlib.sha256(self.request.META.get('REMOTE_ADDR', '').encode()).hexdigest(),
                user_agent=self.request.META.get('HTTP_USER_AGENT', ''),
                details={
                    'timestamp': str(timezone.now()),
                        'security_measures': ['password_changed', 'sessions_terminated', 'security_logs_updated']
                    }
                )
                
            messages.success(self.request, _('Your password has been successfully reset.'))
            return super().form_valid(form)
            
        except Exception as e:
            logger.error(f"Password reset confirmation error for user {user.id}: {str(e)}")
            messages.error(self.request, _('An error occurred. Please try again.'))
            return self.form_invalid(form)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        user = self.get_user(self.kwargs.get('uidb64'))
        token = self.kwargs.get('token')
        
        if user is not None and self.token_generator.check_token(user, token):
            context['validlink'] = True
        else:
            context['validlink'] = False
            
        return context

@login_required
@role_required('admin', 'compliance_officer', 'dpo', 'user')
def handle_data_deletion(request):
    """Handle user data deletion requests with comprehensive tracking and transparency"""
    if request.method == 'POST':
        try:
            with transaction.atomic():
                user = request.user
                
                # Get selected categories
                categories = request.POST.getlist('data_categories', [])
                if not categories:
                    messages.error(request, _('Please select at least one data category to delete.'))
                    return redirect('gdpr_platform:data_deletion')
                
                # Create data deletion request with detailed tracking
            deletion_request = DataRequest.objects.create(
                    user=user,
                request_type='deletion',
                status='pending',
                    data_categories=categories,
                    description=request.POST.get('deletion_reason', ''),
                    notes=f"IP: {request.META.get('REMOTE_ADDR', '')}, UA: {request.META.get('HTTP_USER_AGENT', '')}"
                )
                
                # Log the deletion request with comprehensive audit trail
            AuditLog.objects.create(
                    user=user,
                action='data_deletion_requested',
                    resource_type='user',
                    resource_id=str(user.id),
                    ip_address=request.META.get('REMOTE_ADDR', ''),
                    user_agent=request.META.get('HTTP_USER_AGENT', ''),
                    details={
                    'request_id': str(deletion_request.id),
                        'timestamp': str(timezone.now()),
                        'deletion_scope': categories,
                        'immediate_deletion': request.POST.get('immediate_deletion', False),
                        'retention_policy_applied': True,
                        'backup_deletion_scheduled': True
                    }
                )
                
                # Calculate deletion schedule based on retention policies
            retention_period = 30  # Default retention period
            try:
                if isinstance(user.data_retention_policy, dict):
                    personal_info = user.data_retention_policy.get('personal_info', {})
                    if isinstance(personal_info, dict):
                        retention_period = int(personal_info.get('retention_period', 30))
            except (AttributeError, TypeError, ValueError):
                pass  # Use default retention period
                
            deletion_date = timezone.now() + timedelta(days=retention_period)
            
                # Handle immediate deletion requests if allowed
            if request.POST.get('immediate_deletion') and user.has_permission('immediate_deletion'):
                deletion_date = timezone.now()
            
            # Update user status
            user.account_status = 'pending_deletion'
            user.deletion_scheduled_date = deletion_date
            user.save()
                
            # Schedule data deletion tasks
            schedule_data_deletion_tasks(user, deletion_date, deletion_request.id)
            
            # Revoke all sessions
            Session.objects.filter(expire_date__gte=timezone.now()).delete()
            
            # Send confirmation email
            send_deletion_confirmation_email(user, deletion_request, deletion_date)
                
            messages.success(request, _(
                'Your data deletion request has been received and will be processed. '
                'You will receive a confirmation email with further details.'
            ))
            return redirect('gdpr_platform:logout')
                    
        except Exception as e:
            logger.error(f"Data deletion error for user {request.user.id}: {str(e)}")
            messages.error(request, _('An error occurred processing your request. Please try again.'))
            return redirect('gdpr_platform:dashboard')
            
    # Get available data categories for deletion
    data_categories = get_exportable_data_categories()
    
    # Get retention policies with proper type checking
    retention_policies = {}
    try:
        if hasattr(django_settings, 'GDPR_RETENTION_PERIODS'):
            retention_periods = getattr(django_settings, 'GDPR_RETENTION_PERIODS', {})
            if isinstance(retention_periods, dict):
                retention_policies = {str(k): v for k, v in retention_periods.items()}
    except Exception as e:
        logger.error(f"Error getting retention policies: {str(e)}")
    
    return render(request, 'user_templates/data_deletion.html', {
        'title': _('Request Data Deletion'),
        'data_categories': data_categories,
        'retention_policies': retention_policies,
        'can_request_immediate': request.user.has_permission('immediate_deletion')
    })

def schedule_data_deletion_tasks(user, deletion_date, request_id):
    """Schedule comprehensive data deletion tasks"""
    tasks = [
        ('user_account', 'Delete user account and profile'),
        ('personal_data', 'Delete personal information'),
        ('activity_logs', 'Anonymize activity logs'),
        ('analytics_data', 'Delete analytics data'),
        ('backup_data', 'Remove from backups'),
        ('third_party', 'Notify third-party processors'),
        ('audit_trail', 'Create deletion audit trail')
    ]
    
    for task_type, description in tasks:
        DeletionTask.objects.create(
            user=user,
            request_id=request_id,
            task_type=task_type,
            description=description,
            scheduled_date=deletion_date,
            status='scheduled'
        )

def get_user_data_categories(user):
    """Get user data organized by categories"""
    return {
        'personal_info': {
            'username': user.username,
            'email': user.email,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'date_joined': str(user.date_joined),
            'last_login': str(user.last_login),
            'phone_number': user.phone_number,
            'address': user.address,
            'city': user.city,
            'country': user.country,
            'postal_code': user.postal_code,
            'language_preference': user.preferred_language
        },
        'privacy_settings': {
            'marketing_preferences': user.marketing_preferences,
            'privacy_settings': user.privacy_settings,
            'data_retention_policy': user.data_retention_policy,
            'cookie_preferences': get_current_cookie_preferences(user),
            'privacy_policy_consents': get_privacy_policy_consents(user)
        },
        'security_settings': {
            'two_factor_enabled': user.two_factor_enabled,
            'last_login_ip': user.last_login_ip,
            'account_status': user.account_status,
            'security_preferences': get_security_preferences(user)
        },
        'activity_history': {
            'login_history': list(UserSession.objects.filter(user=user).values(
                'login_time', 'last_activity', 'ip_address', 'user_agent', 'is_active'
            )),
            'data_requests': list(DataRequest.objects.filter(user=user).values(
                'request_type', 'status', 'request_date', 'completion_date', 'description'
            )),
            'consent_history': list(ConsentRecord.objects.filter(user=user).values(
                'consent_type', 'status', 'granted_at', 'withdrawn_at', 'purpose'
            ))
        }
    }

def send_deletion_confirmation_email(user, deletion_request, deletion_date):
    """Send detailed deletion confirmation email"""
    try:
        subject = _('Your Data Deletion Request Confirmation')
        message = render_to_string('emails/deletion_confirmation.html', {
            'user': user,
            'request_id': deletion_request.tracking_id,
            'deletion_date': deletion_date,
            'data_categories': deletion_request.data_categories,
            'retention_period': django_settings.GDPR_RETENTION_PERIODS['personal_info'],
            'contact_email': django_settings.SUPPORT_EMAIL
        })
        
        send_mail(
            subject=subject,
            message=strip_tags(message),
            from_email=django_settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            html_message=message
        )
    except Exception as e:
        logger.error(f"Failed to send deletion confirmation email to {user.email}: {str(e)}")

@login_required
@role_required('admin', 'compliance_officer', 'dpo', 'user')
def data_deletion(request):
    """Redirect to handle_data_deletion for backward compatibility"""
    return handle_data_deletion(request)

@login_required
@role_required('admin', 'compliance_officer', 'user')
def update_cookie_consent(request):
    """Handle cookie consent updates with full transparency and granular control"""
    if request.method == 'POST':
        try:
            form = CookiePreferencesForm(request.POST)
            if form.is_valid():
                    with transaction.atomic():
                    # Create new consent record with detailed tracking
                        new_consent = CookieConsent.objects.create(
                            user=request.user,
                            necessary_cookies=True,  # Always required
                            analytics_cookies=form.cleaned_data.get('analytics_cookies', False),
                            marketing_cookies=form.cleaned_data.get('marketing_cookies', False),
                            functional_cookies=form.cleaned_data.get('functional_cookies', False),
                            ip_address=request.META.get('REMOTE_ADDR', ''),
                        user_agent=request.META.get('HTTP_USER_AGENT', ''),
                        consent_version=django_settings.COOKIE_POLICY_VERSION,
                        consent_method='explicit',
                        consent_timestamp=timezone.now(),
                        consent_expiry=timezone.now() + timedelta(days=django_settings.COOKIE_CONSENT_EXPIRY),
                        consent_details={
                            'form_submitted': True,
                            'source': 'web_form',
                            'explicit_action': True,
                            'policy_version': django_settings.COOKIE_POLICY_VERSION,
                            'browser_info': request.META.get('HTTP_USER_AGENT', ''),
                            'screen_resolution': request.POST.get('screen_resolution', ''),
                            'consent_language': request.LANGUAGE_CODE,
                            'geo_location': get_location_from_ip(request.META.get('REMOTE_ADDR', '')),
                        }
                    )
                    
                    # Log consent update with detailed audit trail
                        AuditLog.objects.create(
                            user=request.user,
                            action='cookie_preferences_updated',
                            resource_type='cookie_consent',
                            resource_id=str(new_consent.id),
                            ip_address=request.META.get('REMOTE_ADDR', ''),
                            user_agent=request.META.get('HTTP_USER_AGENT', ''),
                            details={
                                'new_consent_id': str(new_consent.id),
                                'changes': {
                                    'analytics': new_consent.analytics_cookies,
                                    'marketing': new_consent.marketing_cookies,
                                    'functional': new_consent.functional_cookies
                            },
                            'previous_settings': get_previous_consent_settings(request.user),
                            'consent_version': django_settings.COOKIE_POLICY_VERSION,
                            'expiry_date': str(new_consent.consent_expiry),
                            'consent_method': 'explicit',
                            'user_notification': True
                        }
                    )
                    
                    # Send confirmation email
                    send_consent_confirmation_email(request.user, new_consent)
                    
                    messages.success(request, _('Your cookie preferences have been updated. You can modify these settings at any time.'))
                    return JsonResponse({
                        'status': 'success',
                        'message': _('Cookie preferences updated successfully'),
                        'details': {
                            'consent_id': str(new_consent.id),
                            'expiry_date': str(new_consent.consent_expiry),
                            'settings': {
                                'necessary': True,
                                'analytics': new_consent.analytics_cookies,
                                'marketing': new_consent.marketing_cookies,
                                'functional': new_consent.functional_cookies
                            }
                        }
                    })
            else:
                return JsonResponse({
                    'status': 'error',
                    'errors': form.errors,
                    'message': _('Please review your consent selections')
                }, status=400)
                
        except Exception as e:
            logger.error(f"Cookie consent update error for user {request.user.id}: {str(e)}")
            return JsonResponse({
                'status': 'error',
                'message': _('An error occurred updating your preferences.')
            }, status=500)
    
    return JsonResponse({'status': 'error', 'message': _('Invalid request method.')}, status=405)

def get_previous_consent_settings(user):
    """Get user's previous consent settings for audit trail"""
    previous_consent = CookieConsent.objects.filter(
        user=user
    ).exclude(
        consent_version=django_settings.COOKIE_POLICY_VERSION
    ).order_by('-consent_timestamp').first()
    
    if previous_consent:
        return {
            'analytics': previous_consent.analytics_cookies,
            'marketing': previous_consent.marketing_cookies,
            'functional': previous_consent.functional_cookies,
            'version': previous_consent.consent_version,
            'timestamp': str(previous_consent.consent_timestamp)
        }
    return None

def send_consent_confirmation_email(user, consent):
    """Send confirmation email for consent updates"""
    try:
        subject = _('Your Privacy Settings Have Been Updated')
        message = render_to_string('emails/consent_confirmation.html', {
            'user': user,
            'consent': consent,
            'settings_url': reverse('gdpr_platform:privacy_settings'),
            'timestamp': timezone.now(),
        })
        
        send_mail(
            subject=subject,
            message=strip_tags(message),
            from_email=django_settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            html_message=message
        )
    except Exception as e:
        logger.error(f"Failed to send consent confirmation email to {user.email}: {str(e)}")

@login_required
@role_required('admin', 'compliance_officer', 'user')
def privacy_settings(request):
    """Handle privacy settings"""
    try:
        if request.method == 'POST':
            # Update privacy settings
            privacy_settings = request.user.privacy_settings if hasattr(request.user, 'privacy_settings') else {}
            privacy_settings.update({
                'marketing_emails': request.POST.get('marketing_emails') == 'on',
                'data_sharing': request.POST.get('data_sharing') == 'on',
                'analytics': request.POST.get('analytics') == 'on',
                'last_updated': str(timezone.now())
            })
            request.user.privacy_settings = privacy_settings
            request.user.save()
            
            # Log the update
            AuditLog.objects.create(
                user=request.user,
                action='privacy_settings_updated',
                resource_type='privacy_settings',
                resource_id=str(request.user.id)
            )
            
            messages.success(request, _('Your privacy settings have been updated.'))
            return redirect('gdpr_platform:privacy_settings')
        
        return render(request, 'user_templates/privacy_settings.html', {
            'title': _('Privacy Settings'),
            'privacy_settings': request.user.privacy_settings if hasattr(request.user, 'privacy_settings') else {}
        })
    except Exception as e:
        logger.error(f"Privacy settings error for user {request.user.id}: {str(e)}")
        messages.error(request, _('An error occurred while updating your privacy settings.'))
        return redirect('gdpr_platform:dashboard')

def landing(request):
    """Landing page view"""
    if request.user.is_authenticated:
        return redirect('gdpr_platform:dashboard')
    return render(request, 'landing.html', {
        'title': 'Welcome to GDPR Platform'
    })

def custom_login(request):
    """Custom login view with security features"""
    try:
        next_url = request.GET.get('next', '')
        is_admin = next_url and next_url.startswith('/admin/')
        
        if request.user.is_authenticated:
                # Assign default role if needed
            assign_default_role(request.user)
                    
            if request.user.is_staff:
                    return redirect('gdpr_platform:admin_dashboard')
            return redirect('gdpr_platform:dashboard')
            
        if request.method == 'POST':
            username = request.POST.get('username')
            password = request.POST.get('password')
            user = authenticate(request, username=username, password=password)
            
            if user is not None:
                if user.is_active:
                    # Check if 2FA is required
                    if user.two_factor_enabled:
                        request.session['2fa_user_id'] = user.id
                        request.session['2fa_redirect_url'] = next_url
                        return redirect('gdpr_platform:two_factor_verify')
                    
                    # Log the successful login
                    login(request, user)
                    logger.info(f"Successful login for user: {username}")
                            
                            # Assign default role if needed
                    assign_default_role(user)
                    
                    # Update last login and create session record
                    user.last_login = timezone.now()
                    user.save(update_fields=['last_login'])
                    
                    # Create session record
                    if not request.session.session_key:
                        request.session.save()
                    
                    UserSession.objects.create(
                        user=user,
                        session_key=request.session.session_key,
                        ip_address=get_client_ip(request),
                        user_agent=request.META.get('HTTP_USER_AGENT', '')
                    )
                    
                    # Handle redirection
                    if user.is_staff:
                        return redirect('gdpr_platform:admin_dashboard')
                    return redirect('gdpr_platform:dashboard')
                else:
                    messages.error(request, _('Your account is inactive. Please contact support.'))
            else:
                # Log failed login attempt
                logger.warning(f"Failed login attempt for username: {username}")
                breach_monitor.log_failed_login(username, get_client_ip(request))
                messages.error(request, _('Invalid username or password.'))
        
        return render(request, 'registration/login.html', {
            'title': 'Admin Login' if is_admin else 'Login',
            'form': AuthenticationForm(),
            'show_register': not is_admin,
            'show_password_reset': True,
            'is_admin': is_admin,
            'next': next_url
        })
    except Exception as e:
        logger.error(f"Error in custom_login: {str(e)}")
        messages.error(request, _('An error occurred while logging in. Please try again later.'))
        return redirect('gdpr_platform:landing')

def get_location_from_ip(ip):
    """Get location information from IP address"""
    # This is a placeholder. In production, you would use a geolocation service
    return {
        'country': 'Unknown',
        'city': 'Unknown',
        'region': 'Unknown'
    }

@login_required
def custom_logout(request):
    """Custom logout view that handles cleanup and logging"""
    try:
        # Log the logout action
        AuditLog.objects.create(
            user=request.user,
            action='LOGOUT',
            status='SUCCESS',
            ip_address=get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', '')
        )
        
        # Perform logout
        logout(request)
        return redirect('gdpr_platform:landing')
    except Exception as e:
        logger.error(f"Error during logout for {request.user.id}: {str(e)}")
        logout(request)
        return redirect('gdpr_platform:landing')

def register(request):
    """Handle user registration with GDPR compliance"""
    if request.user.is_authenticated:
        return redirect('gdpr_platform:user_dashboard')

    if request.method == 'POST':
        form = RegistrationForm(request.POST, request.FILES)
        if form.is_valid():
            try:
                with transaction.atomic():
                    user = form.save()
                    
                    # Assign default user role
                    regular_user_role = Role.objects.get(name='user')
                    user.roles.add(regular_user_role)
                    
                    AuditLog.objects.create(
                        user=user,
                        action='user_registration',
                        resource_type='user',
                        resource_id=str(user.id),
                        ip_address=get_client_ip(request),
                        user_agent=request.META.get('HTTP_USER_AGENT', ''),
                        details={
                            'timestamp': str(timezone.now()),
                            'consents': {
                                'privacy_policy': form.cleaned_data.get('privacy_policy_consent'),
                                'data_processing': form.cleaned_data.get('data_processing_consent'),
                                'marketing': form.cleaned_data.get('marketing_consent', False)
                            }
                        }
                    )
                    
                    CookieConsent.objects.create(
                        user=user,
                        necessary_cookies=True,
                        analytics_cookies=False,
                        marketing_cookies=form.cleaned_data.get('marketing_consent', False),
                        functional_cookies=True,
                        ip_address=get_client_ip(request),
                        user_agent=request.META.get('HTTP_USER_AGENT', '')
                    )
                    
                    current_policy = PrivacyPolicy.objects.filter(is_active=True).first()
                    if current_policy:
                        UserPrivacyPolicyConsent.objects.create(
                            user=user,
                            policy=current_policy,
                            ip_address=get_client_ip(request),
                            user_agent=request.META.get('HTTP_USER_AGENT', '')
                        )
                    
                    login(request, user)
                    
                    # Ensure session is created and saved
                    if not request.session.session_key:
                        request.session.save()
                    
                    UserSession.objects.create(
                        user=user,
                        session_key=request.session.session_key,
                        ip_address=get_client_ip(request),
                        user_agent=request.META.get('HTTP_USER_AGENT', '')
                    )
                    
                    try:
                        # Get DPO email from settings or use default
                        dpo_email = getattr(django_settings, 'DPO_EMAIL', 'dpo@gdprplatform.com')
                        
                        # Prepare email context
                        email_context = {
                            'user': user,
                            'site_name': getattr(django_settings, 'SITE_NAME', 'GDPR Platform'),
                            'dpo_email': dpo_email,
                            'request': request,
                        }
                        
                        # Get email settings with defaults
                        from_email = getattr(django_settings, 'DEFAULT_FROM_EMAIL', 'noreply@gdprplatform.com')
                        
                        send_mail(
                            subject=_('Welcome to GDPR Platform'),
                            message=render_to_string('emails/welcome_email.txt', email_context),
                            from_email=from_email,
                            recipient_list=[user.email],
                            html_message=render_to_string('emails/welcome_email.html', email_context)
                        )
                    except Exception as e:
                        logger.error(f"Failed to send welcome email to {user.email}: {str(e)}")
                    
                    messages.success(request, _('Registration successful. Welcome!'))
                    
                    # Redirect directly to user dashboard for new users
                    return redirect('gdpr_platform:user_dashboard')
                    
            except Exception as e:
                logger.error(f"Registration error: {str(e)}")
                messages.error(request, _('An error occurred during registration. Please try again.'))
        else:
            # Log form validation errors
            logger.error(f"Registration form validation errors: {form.errors}")
            for field, errors in form.errors.items():
                for error in errors:
                    messages.error(request, f"{field}: {error}")
    else:
        form = RegistrationForm()
    
    return render(request, 'registration/register.html', {
        'form': form,
        'title': _('Register'),
        'privacy_policy': PrivacyPolicy.objects.filter(is_active=True).first()
    })

@login_required
@role_required('admin', 'compliance_officer', 'dpo', 'user')
def data_rights_dashboard(request):
    """Display user's data rights and GDPR information"""
    try:
        # Get user's data requests, ordered by request date
        user_requests = DataRequest.objects.filter(user=request.user).order_by('-request_date')
        
        # Get latest cookie consent
        cookie_consent = CookieConsent.objects.filter(user=request.user).order_by('-timestamp').first()
        
        # Prepare context with user data
        context = {
            'title': _('Data Rights Dashboard'),
            'user': request.user,  # Use user instead of user_profile
            'user_requests': user_requests,
            'cookie_consent': cookie_consent,
            'two_factor_enabled': request.user.two_factor_enabled,
            'recent_activity': ActivityLog.objects.filter(user=request.user).order_by('-timestamp')[:5],
            'active_sessions': UserSession.objects.filter(user=request.user, is_active=True).order_by('-last_activity'),
            'breach_notifications': BreachNotification.objects.filter(
                recipient=request.user,
                status__in=['pending', 'sent']
            ).order_by('-created_at'),
            'data_processing': DataProcessingActivity.objects.filter(
                processor=request.user,
                is_active=True
            ).order_by('-created_at'),
            'retention_settings': request.user.data_retention_policy,
            'open_tickets': SupportTicket.objects.filter(
                user=request.user,
                status__in=['open', 'in_progress']
            ).order_by('-created_at'),
            'user_rights': {
                'access': True,
                'rectification': True,
                'erasure': True,
                'portability': True,
                'object': True,
                'restrict_processing': True
            }
        }
        
        # Choose template based on user role
        if request.user.has_role('admin'):
            template = 'admin_templates/admin_dashboard.html'
            context.update({
                'total_users': CustomUser.objects.count(),
                'pending_requests': DataRequest.objects.filter(status='pending').count(),
                'compliance_score': calculate_compliance_score(),
                'recent_breaches': DataBreach.objects.filter(
                    resolved=False
                ).order_by('-date_discovered')[:5],
            })
        else:
            template = 'user_templates/dashboard.html'
        
        return render(request, template, context)
        
    except Exception as e:
        logger.error(f"Dashboard error for user {request.user.id}: {str(e)}")
        messages.error(request, _('An error occurred loading the dashboard.'))
        return render(request, 'user_templates/dashboard.html', {
            'error': True,
            'title': 'Dashboard',
            'user': request.user  # Include user in error context
    })

@login_required
def extend_session(request):
    """Extend user session if active"""
    if request.method == 'POST':
        try:
            request.session.modified = True
            return JsonResponse({'status': 'success'})
        except Exception as e:
            logger.error(f"Session extension error for user {request.user.id}: {str(e)}")
            return JsonResponse({'status': 'error'}, status=500)
    return JsonResponse({'status': 'error', 'message': 'Invalid request method'}, status=405)

@login_required
@role_required('admin', 'compliance_officer', 'dpo', 'user')
def export_user_data(request):
    """Handle user data export requests"""
    try:
        if request.method == 'POST':
            # Get selected format and categories
            export_format = request.POST.get('format', 'json')
            categories = request.POST.getlist('categories', [])  # Changed from data_categories to categories
            
            # Get user data
            user_data = get_user_data_categories(request.user)
            
            # Filter data based on selected categories if specific categories were selected
            if categories:
                filtered_data = {}
                for category in categories:
                    if category in user_data:
                        filtered_data[category] = user_data[category]
                user_data = filtered_data
            
            try:
                # Create the export based on the requested format
                if export_format == 'json':
                            export_data = create_json_export(user_data)
                            content_type = 'application/json'
                elif export_format == 'csv':
                            export_data = create_csv_export(user_data)
                            content_type = 'text/csv'
                elif export_format == 'xml':
                            export_data = create_xml_export(user_data)
                            content_type = 'application/xml'
                else:
                    raise ValueError(f"Unsupported export format: {export_format}")
        
                # Create export record
                export_request = DataRequest.objects.create(
                    user=request.user,
                                request_type='export',
                                status='completed',
                                file_format=export_format,
                                data_categories=categories,
                                description=f"Data export in {export_format.upper()} format"
                )
                
                # Send notification email
                send_export_notification_email(request.user, export_request)
            
                        # Return the exported data
                response = HttpResponse(export_data, content_type=content_type)
                response['Content-Disposition'] = f'attachment; filename="user_data_{timezone.now().strftime("%Y%m%d_%H%M%S")}.{export_format}"'
                return response
            
            except Exception as e:
                logger.error(f"Data export error for user {request.user.id}: {str(e)}")
                messages.error(request, _("An error occurred while exporting your data. Please try again."))
                return redirect('gdpr_platform:data_export')
        
        # Get previous exports for GET request
        previous_exports = DataRequest.objects.filter(
                user=request.user,
                request_type='export'
            ).order_by('-request_date')[:5]
        
        return render(request, 'gdpr/data_export.html', {  # Changed from user_templates to gdpr
            'title': _("Export Your Data"),
            'previous_exports': previous_exports,
            'exportable_categories': get_exportable_data_categories()  # Changed from data_categories to exportable_categories
        })
        
    except Exception as e:
        logger.error(f"Data export error for user {request.user.id}: {str(e)}")
        messages.error(request, _("An error occurred while processing your request. Please try again."))
        return redirect('gdpr_platform:dashboard')

def get_current_cookie_preferences(user):
    """Get user's current cookie preferences"""
    consent = CookieConsent.objects.filter(user=user).order_by('-timestamp').first()
    if consent:
        return {
            'necessary': consent.necessary_cookies,
            'analytics': consent.analytics_cookies,
            'marketing': consent.marketing_cookies,
            'functional': consent.functional_cookies,
            'last_updated': str(consent.timestamp)
        }
    return None

def get_privacy_policy_consents(user):
    """Get user's privacy policy consent history"""
    return list(UserPrivacyPolicyConsent.objects.filter(user=user).values(
        'policy__version',
        'consent_date',
        'ip_address',
        'user_agent'
    ))

def get_security_preferences(user):
    """Get user's security preferences"""
    return {
        'two_factor_auth': user.two_factor_enabled,
        'trusted_devices_enabled': hasattr(user, 'trust_settings'),
        'session_timeout': getattr(user, 'session_timeout', django_settings.SESSION_COOKIE_AGE),
        'login_notification': getattr(user, 'login_notification_enabled', False)
    }

def create_json_export(data):
    """Create JSON export of user data"""
    return json.dumps(data, indent=2, default=str)

def create_csv_export(data):
    """Create CSV export of user data"""
    output = StringIO()
    writer = csv.writer(output)
    
    for category, category_data in data.items():
        writer.writerow([f"--- {category.upper()} ---"])
        if isinstance(category_data, dict):
            for key, value in category_data.items():
                if isinstance(value, (list, dict)):
                    writer.writerow([key])
                    if isinstance(value, list):
                        # Handle list of dictionaries
                        if value and isinstance(value[0], dict):
                            headers = value[0].keys()
                            writer.writerow(headers)
                            for item in value:
                                if isinstance(item, dict):
                                    writer.writerow([str(item.get(h, '')) for h in headers])
                                else:
                                    writer.writerow([str(item)])
                        else:
                            # Handle list of non-dictionary items
                            for item in value:
                                writer.writerow([str(item)])
                    else:
                        # Handle nested dictionary
                        for k, v in value.items():
                            writer.writerow([k, str(v)])
                else:
                    writer.writerow([key, str(value)])
        else:
            # Handle non-dictionary category data
            writer.writerow(['Value', str(category_data)])
        writer.writerow([])  # Empty row between categories
    
    return output.getvalue()

def create_xml_export(data):
    """Create XML export of user data"""
    root = ET.Element("user_data")
    
    def dict_to_xml(parent, dictionary):
        for key, value in dictionary.items():
            child = ET.SubElement(parent, key.replace(' ', '_'))
            if isinstance(value, dict):
                dict_to_xml(child, value)
            elif isinstance(value, list):
                for item in value:
                    item_elem = ET.SubElement(child, "item")
                    if isinstance(item, dict):
                        dict_to_xml(item_elem, item)
                    else:
                        item_elem.text = str(item)
            else:
                child.text = str(value)
    
    dict_to_xml(root, data)
    return ET.tostring(root, encoding='unicode', method='xml', pretty_print=True)

def get_exportable_data_categories():
    """Get available data categories for export"""
    return [
        {
            'id': 'personal_info',
            'name': _('Personal Information'),
            'description': _('Your basic account and profile information')
        },
        {
            'id': 'privacy_settings',
            'name': _('Privacy Settings'),
            'description': _('Your privacy preferences and consents')
        },
        {
            'id': 'activity_history',
            'name': _('Activity History'),
            'description': _('Your activity logs and data requests')
        },
        {
            'id': 'data_processing',
            'name': _('Data Processing'),
            'description': _('Information about how your data is processed')
        },
        {
            'id': 'security_settings',
            'name': _('Security Settings'),
            'description': _('Your security preferences and trusted devices')
        }
    ]

def send_export_notification_email(user, export_request):
    """Send export notification email"""
    try:
        subject = _('Your Data Export is Ready')
        message = render_to_string('emails/export_notification.html', {
            'user': user,
            'request_id': export_request.id,
            'export_date': timezone.now(),
            'categories': export_request.data_categories,
            'format': export_request.file_format,
            'download_url': reverse('gdpr_platform:download_export', args=[export_request.id])
        })
        
        send_mail(
            subject=subject,
            message=strip_tags(message),
            from_email=django_settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            html_message=message
        )
    except Exception as e:
        logger.error(f"Failed to send export notification email to {user.email}: {str(e)}")

@login_required
@role_required('admin', 'compliance_officer', 'dpo', 'user')
def rectify_user_data(request):
    """Handle user data rectification requests"""
    try:
        if request.method == 'POST':
                corrections = json.loads(request.POST.get('corrections', '{}'))
                
                with transaction.atomic():
                    # Create rectification request
                    rectification_request = DataRequest.objects.create(
                        user=request.user,
                        request_type='rectification',
                        status='processing',
                        details={'corrections': corrections}
                    )
                    
                    # Apply corrections
                    user = request.user
                    for field, value in corrections.items():
                        if hasattr(user, field):
                            setattr(user, field, value)
        user.save()
        
                # Log the rectification
        AuditLog.objects.create(
            user=user,
                    action='data_rectified',
                    resource_type='user_data',
            resource_id=str(user.id),
                    ip_address=get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
                    details={'fields_updated': list(corrections.keys())}
                )
                
        rectification_request.status = 'completed'
        rectification_request.save()
                
        messages.success(request, _('Your data has been updated successfully.'))
        return JsonResponse({'status': 'success'})
                
    except Exception as e:
        logger.error(f"Data rectification error for user {request.user.id}: {str(e)}")
        return JsonResponse({
            'status': 'error',
            'message': _('An error occurred updating your data.')
        }, status=500)
            
    return JsonResponse({'status': 'error', 'message': 'Invalid request method'}, status=405)

@login_required
@role_required('admin', 'compliance_officer', 'dpo', 'user')
def activity_log(request):
    """
    View for displaying activity logs with filtering and pagination.
    """
    # Get filter parameters
    start_date = request.GET.get('start_date')
    end_date = request.GET.get('end_date')
    action_type = request.GET.get('action_type')
    user_id = request.GET.get('user_id')
    
    # Base queryset
    logs = ActivityLog.objects.all().order_by('-timestamp')
    
    # Apply filters
    if start_date:
        logs = logs.filter(timestamp__gte=start_date)
    if end_date:
        logs = logs.filter(timestamp__lte=end_date)
    if action_type:
        logs = logs.filter(action_type=action_type)
    if user_id:
        logs = logs.filter(user_id=user_id)
        
    # Pagination
    paginator = Paginator(logs, 10)
    page = request.GET.get('page')
    try:
        activity_logs = paginator.page(page)
    except PageNotAnInteger:
        activity_logs = paginator.page(1)
    except EmptyPage:
        activity_logs = paginator.page(paginator.num_pages)
    
    # Process logs for display
    for log in activity_logs:
        log.formatted_timestamp = log.timestamp.strftime('%Y-%m-%d %H:%M:%S')
    
    context = {
        'activity_logs': activity_logs,
        'start_date': start_date,
        'end_date': end_date,
        'action_type': action_type,
        'user_id': user_id,
    }
    
    return render(request, 'compliance_officer_templates/activity_log.html', context)

def export_activity_log(request):
    """
    View for exporting activity logs to CSV.
    """
    # Get filter parameters (same as activity_log view)
    start_date = request.GET.get('start_date')
    end_date = request.GET.get('end_date')
    action_type = request.GET.get('action_type')
    user_id = request.GET.get('user_id')
    
    # Base queryset
    logs = ActivityLog.objects.all().order_by('-timestamp')
    
    # Apply filters (same as activity_log view)
    if start_date:
        logs = logs.filter(timestamp__gte=start_date)
    if end_date:
        logs = logs.filter(timestamp__lte=end_date)
    if action_type:
        logs = logs.filter(action_type=action_type)
    if user_id:
        logs = logs.filter(user_id=user_id)
    
    # Create the HttpResponse object with CSV header
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="activity_log.csv"'

    # Create CSV writer
    writer = csv.writer(response)
    writer.writerow([
        'Timestamp',
        'User',
        'Action',
        'Resource Type',
        'Resource ID',
        'IP Address',
        'User Agent',
        'Status',
        'Details'
    ])

    # Write data
    for log in logs:
        writer.writerow([
            log.formatted_timestamp,
            log.user.email,
            log.get_action_display(),
            log.resource_type,
            log.resource_id,
            log.ip_address,
            log.user_agent,
            log.get_status_display(),
            json.dumps(log.details)
        ])

    return response

@login_required
@role_required('admin', 'compliance_officer', 'dpo', 'user')
def security_dashboard(request):
    """Display security dashboard with enhanced monitoring"""
    try:
        # Get user's security status
        try:
            two_factor_enabled = hasattr(request.user, 'totp_device')
            logger.debug(f"Two-factor status for user {request.user.id}: {two_factor_enabled}")
        except Exception as e:
            logger.error(f"Error checking 2FA status: {str(e)}")
            two_factor_enabled = False

        try:
            active_sessions = UserSession.objects.filter(
                user=request.user,
                is_active=True
            ).order_by('-login_time')
            logger.debug(f"Found {active_sessions.count()} active sessions for user {request.user.id}")
        except Exception as e:
            logger.error(f"Error retrieving active sessions: {str(e)}")
            active_sessions = UserSession.objects.none()
        
        try:
            security_logs = ActivityLog.objects.filter(
                user=request.user,
                action_type__in=['login', 'password', '2fa', 'security']
            ).order_by('-timestamp')[:10]
            logger.debug(f"Found {security_logs.count()} security logs for user {request.user.id}")
        except Exception as e:
            logger.error(f"Error retrieving security logs: {str(e)}")
            security_logs = ActivityLog.objects.none()
        
        try:
            trusted_devices = TrustedDevice.objects.filter(
                user=request.user,
                expires_at__gt=timezone.now()
            ).order_by('-last_used')
            logger.debug(f"Found {trusted_devices.count()} trusted devices for user {request.user.id}")
        except Exception as e:
            logger.error(f"Error retrieving trusted devices: {str(e)}")
            trusted_devices = TrustedDevice.objects.none()

        try:
            login_history = ActivityLog.objects.filter(
                user=request.user,
                action_type='login'
            ).order_by('-timestamp')[:10]
            logger.debug(f"Found {login_history.count()} login history entries for user {request.user.id}")
        except Exception as e:
            logger.error(f"Error retrieving login history: {str(e)}")
            login_history = ActivityLog.objects.none()

        # Calculate security score based on available factors
        security_score = 0
        try:
            if two_factor_enabled:
                security_score += 40
            if trusted_devices.exists():
                security_score += 20
            if request.user.last_password_change:
                days_since_password_change = (timezone.now() - request.user.last_password_change).days
                if days_since_password_change <= 90:
                    security_score += 20
            if active_sessions.count() <= 3:  # Not too many active sessions
                security_score += 20
            logger.debug(f"Calculated security score for user {request.user.id}: {security_score}")
        except Exception as e:
            logger.error(f"Error calculating security score: {str(e)}")
            security_score = 0
        
        context = {
            'title': _('Security Dashboard'),
            'two_factor_enabled': two_factor_enabled,
            'active_sessions': active_sessions,
            'security_logs': security_logs,
            'trusted_devices': trusted_devices,
            'trusted_devices_count': trusted_devices.count(),
            'security_score': security_score,
            'login_history': login_history,
            'user': request.user
        }
        
        return render(request, 'security/security_dashboard.html', context)
        
    except Exception as e:
        logger.error(f"Security dashboard error for user {request.user.id}: {str(e)}", exc_info=True)
        messages.error(request, _('An error occurred loading the security dashboard.'))
        return redirect('gdpr_platform:dashboard')

@login_required
@role_required('admin', 'compliance_officer', 'dpo', 'user')
def data_processing(request):
    """Handle data processing activities and cross-border transfers."""
    
    # Get processing activities
    activities = DataProcessingActivity.objects.filter(is_active=True).order_by('-created_at')
    processing_activities = [{
        'activity_type': activity.title,
        'description': activity.description,
        'timestamp': activity.created_at
    } for activity in activities]

    # Get transfers
    transfers_qs = DataTransfer.objects.filter(status='active').order_by('-created_at')
    transfers = [{
        'recipient_organization': transfer.destination_system,
        'recipient_country': transfer.destination_system,
        'data_categories': transfer.data_categories,
        'transfer_date': transfer.created_at
    } for transfer in transfers_qs]

    # Get retention settings
    retention_settings = {
        'personal_data': {'retention_period': 24, 'unit': 'months'},
        'sensitive_data': {'retention_period': 12, 'unit': 'months'},
        'financial_data': {'retention_period': 84, 'unit': 'months'},
        'communication_data': {'retention_period': 36, 'unit': 'months'}
    }
        
    context = {
        'title': _('Data Processing Activities'),
        'processing_activities': processing_activities,
        'transfers': transfers,
        'retention_settings': retention_settings
        }
        
    return render(request, 'dpo_templates/data_processing.html', context)

@login_required
@role_required('admin', 'compliance_officer', 'user')
def privacy_policy(request):
    """Display and manage privacy policy"""
    try:
        # Get the latest active policy
        try:
            current_policy = PrivacyPolicy.objects.filter(is_active=True).latest('effective_date')
        except PrivacyPolicy.DoesNotExist:
            # Create a default policy if none exists
            current_policy = PrivacyPolicy.objects.create(
                title=_('Privacy Policy'),
                content=render_to_string('gdpr/default_privacy_policy.html'),
                version='1.0',
                is_active=True,
                effective_date=timezone.now()
            )
        
        # Get user's consent status
        user_consent = UserPrivacyPolicyConsent.objects.filter(
            user=request.user,
            policy=current_policy
        ).first()
        
        context = {
            'title': _('Privacy Policy'),
            'policy': current_policy,
            'has_consented': bool(user_consent),
            'consent_date': user_consent.consented_at if user_consent else None,
            'show_consent_banner': not bool(user_consent)
        }
        
        return render(request, 'gdpr/privacy_policy.html', context)
            
    except Exception as e:
        logger.error(f"Privacy policy view error: {str(e)}")
        messages.error(request, _('An error occurred while loading the privacy policy.'))
        return redirect('gdpr_platform:dashboard')

@login_required
@role_required('admin', 'compliance_officer', 'user')
def update_privacy_policy_consent(request):
    """Handle privacy policy consent updates"""
    if request.method == 'POST':
        try:
            current_policy = PrivacyPolicy.objects.filter(is_active=True).first()
            if not current_policy:
                return JsonResponse({
                    'status': 'error',
                    'message': _('No active privacy policy found.')
                }, status=400)
            
            # Create or update consent
            consent, created = UserPrivacyPolicyConsent.objects.get_or_create(
                user=request.user,
                policy=current_policy,
                defaults={
                    'ip_address': get_client_ip(request),
                    'user_agent': request.META.get('HTTP_USER_AGENT', '')
                }
            )
            
            if not created:
                consent.ip_address = get_client_ip(request)
                consent.user_agent = request.META.get('HTTP_USER_AGENT', '')
                consent.consented_at = timezone.now()
                consent.save()
            
            # Log the consent
            AuditLog.objects.create(
                user=request.user,
                action='privacy_policy_consent_updated',
                resource_type='privacy_policy',
                resource_id=str(current_policy.id),
                ip_address=get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', '')
            )
            
            messages.success(request, _('Your privacy policy consent has been updated.'))
            return JsonResponse({'status': 'success'})
            
        except Exception as e:
            logger.error(f"Privacy policy consent update error for user {request.user.id}: {str(e)}")
            return JsonResponse({
                'status': 'error',
                'message': _('An error occurred updating your consent.')
            }, status=500)
            
    return JsonResponse({'status': 'error', 'message': 'Invalid request method'}, status=405)

@login_required
def setup_2fa(request):
    """Handle 2FA setup"""
    if request.method == 'POST':
        form = TwoFactorSetupForm(request.POST)
        if form.is_valid():
            try:
    # Get or create TOTP device
                device, created = TOTPDevice.objects.get_or_create(
                    user=request.user,
                    defaults={'confirmed': False}
                )
                
                if not device.confirmed:
                    # Verify the token
                    if device.verify_token(form.cleaned_data['verification_code']):
                        device.confirmed = True
                        device.save()
            
                        # Update user's 2FA status
                        request.user.two_factor_enabled = True
                        request.user.save()
                        
                        # Log the setup
                        AuditLog.objects.create(
                                        user=request.user,
                            action='2fa_enabled',
                            resource_type='security',
                                        resource_id=str(request.user.id),
                                        ip_address=get_client_ip(request),
                                        user_agent=request.META.get('HTTP_USER_AGENT', '')
                                    )
                                    
                        messages.success(request, _('Two-factor authentication has been enabled.'))
                        return redirect('gdpr_platform:security_settings')
                    else:
                        messages.error(request, _('Invalid verification code.'))
                else:
                    messages.error(request, _('Two-factor authentication is already set up.'))
            except Exception as e:
                logger.error(f"2FA setup error for user {request.user.id}: {str(e)}")
                messages.error(request, _('An error occurred during 2FA setup.'))
        else:
            form = TwoFactorSetupForm()
            
            # Generate new secret key if needed
            device, created = TOTPDevice.objects.get_or_create(
                user=request.user,
                defaults={'confirmed': False}
            )
            
            if created or not device.confirmed:
        # Generate QR code
                qr = qrcode.QRCode(
                    version=1,
                    error_correction=qrcode.constants.ERROR_CORRECT_L,
                    box_size=10,
                    border=4,
                )
        provisioning_uri = device.config_url
        qr.add_data(provisioning_uri)
        qr.make(fit=True)
        
                # Create SVG QR code
        img = qr.make_image(image_factory=qrcode.image.svg.SvgImage)
        stream = BytesIO()
        img.save(stream)
        qr_code = stream.getvalue().decode()
                
        context = {
            'form': form,
            'qr_code': qr_code,
            'secret_key': device.key,
            'title': 'Setup Two-Factor Authentication'
            }
                
        return render(request, 'security/setup_2fa.html', context)
        
    return redirect('gdpr_platform:security_settings')

@login_required
def disable_2fa(request):
    """Handle 2FA disablement"""
    if request.method == 'POST':
        try:
            # Remove TOTP devices
            TOTPDevice.objects.filter(user=request.user).delete()
            
            
            # Update user's 2FA status
            request.user.two_factor_enabled = False
            request.user.save()
            
            # Log the disablement
            AuditLog.objects.create(
                user=request.user,
                action='2fa_disabled',
                resource_type='security',
                resource_id=str(request.user.id),
                ip_address=get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', '')
            )
            
            # Invalidate all sessions for security
            Session.objects.filter(expire_date__gte=timezone.now()).delete()
            
            messages.success(request, _('Two-factor authentication has been disabled.'))
            return redirect('gdpr_platform:login')
            
        except Exception as e:
            logger.error(f"2FA disable error for user {request.user.id}: {str(e)}")
            messages.error(request, _('An error occurred disabling 2FA.'))
            
    return redirect('gdpr_platform:security_settings')

@login_required
def trusted_devices(request):
    """Handle trusted devices management"""
    try:
        logger.info(f"Loading trusted devices for user {request.user.id}")
        
        # Get user's active sessions
        try:
            active_sessions = UserSession.objects.filter(
                user=request.user,
                logout_time__isnull=True,
                is_active=True
            ).order_by('-login_time')
            logger.debug(f"Found {active_sessions.count()} active sessions for user {request.user.id}")
        except Exception as e:
            logger.error(f"Error retrieving active sessions for user {request.user.id}: {str(e)}")
            active_sessions = UserSession.objects.none()
        
        # Get trusted devices
        try:
            trusted_devices = TrustedDevice.objects.filter(
                user=request.user,
                expires_at__gt=timezone.now()
            ).order_by('-last_used')
            logger.debug(f"Found {trusted_devices.count()} trusted devices for user {request.user.id}")
        except Exception as e:
            logger.error(f"Error retrieving trusted devices for user {request.user.id}: {str(e)}")
            trusted_devices = TrustedDevice.objects.none()
        
        # Get current device info
        current_device = None
        try:
            if request.session.session_key:
                current_session = UserSession.objects.filter(
                    user=request.user,
                    session_key=request.session.session_key,
                    is_active=True
                ).first()
                if current_session:
                    current_device = {
                        'user_agent': current_session.user_agent,
                        'ip_address': current_session.ip_address,
                        'last_used': current_session.last_activity
                    }
                    logger.debug(f"Found current device info for user {request.user.id}")
        except Exception as e:
            logger.error(f"Error retrieving current device info for user {request.user.id}: {str(e)}")
        
        context = {
            'active_sessions': active_sessions,
            'trusted_devices': trusted_devices,
            'current_device': current_device,
            'current_session': request.session.session_key,
            'title': 'Trusted Devices'
        }
        
        logger.info(f"Successfully loaded trusted devices page for user {request.user.id}")
        return render(request, 'security/trusted_devices.html', context)
        
    except Exception as e:
        logger.error(f"Unexpected error in trusted devices view for user {request.user.id}: {str(e)}", exc_info=True)
        messages.error(request, _('An error occurred loading your devices.'))
        return redirect('gdpr_platform:dashboard')

# Define action types for audit log
ACTION_TYPES = [
    ('login', _('Login')),
    ('logout', _('Logout')),
    ('data_export', _('Data Export')),
    ('data_deletion', _('Data Deletion')),
    ('data_rectification', _('Data Rectification')),
    ('privacy_settings', _('Privacy Settings Update')),
    ('cookie_consent', _('Cookie Consent Update')),
    ('2fa_enabled', _('2FA Enabled')),
    ('2fa_disabled', _('2FA Disabled')),
    ('password_changed', _('Password Changed')),
    ('security_settings', _('Security Settings Update')),
]

@login_required
@role_required('admin', 'compliance_officer', 'dpo', 'user')
def cross_border_transfers(request):
    """Display and manage cross-border data transfers"""
    try:
        # Get filter parameters
        country = request.GET.get('country')
        mechanism = request.GET.get('mechanism')
        status = request.GET.get('status')
        date_range = request.GET.get('date_range', '30')  # Default to last 30 days

        # Base queryset
        transfers = CrossBorderTransfer.objects.all()

        # Apply filters
        if country:
            transfers = transfers.filter(recipient_country=country)
        if mechanism:
            transfers = transfers.filter(transfer_mechanism=mechanism)
        if status:
            transfers = transfers.filter(status=status)
        if date_range and date_range != 'all':
            days = int(date_range)
            start_date = timezone.now() - timezone.timedelta(days=days)
            transfers = transfers.filter(transfer_date__gte=start_date)

        # Order by most recent
        transfers = transfers.order_by('-transfer_date')

        # Calculate statistics
        active_transfers = transfers.filter(status='active').count()
        pending_transfers = transfers.filter(status='pending').count()
        recipient_countries = transfers.values('recipient_country').distinct().count()
        
        # Calculate risk score (example implementation)
        high_risk_transfers = transfers.filter(risk_level='high').count()
        total_transfers = transfers.count()
        risk_score = int((high_risk_transfers / total_transfers * 100) if total_transfers > 0 else 0)

        # Get unique countries and mechanisms for filters
        countries = transfers.values_list('recipient_country', flat=True).distinct()
        mechanisms = CrossBorderTransfer.TRANSFER_MECHANISM_CHOICES

        # Add status class for badges
        for transfer in transfers:
            transfer.status_class = {
                'active': 'success',
                'pending': 'warning',
                'completed': 'info',
                'suspended': 'danger',
                'expired': 'secondary'
            }.get(transfer.status, 'secondary')

        # Pagination
        paginator = Paginator(transfers, 10)
        page = request.GET.get('page', 1)
        try:
            transfers = paginator.page(page)
        except (PageNotAnInteger, EmptyPage):
            transfers = paginator.page(1)

        # Handle new transfer form
        if request.method == 'POST':
            form = CrossBorderTransferForm(request.POST)
            if form.is_valid():
                transfer = form.save(commit=False)
                transfer.user = request.user
                transfer.save()
                
                # Log the transfer
                AuditLog.objects.create(
                    user=request.user,
                    action='cross_border_transfer_created',
                    resource_type='transfer',
                    resource_id=str(transfer.id),
                    ip_address=get_client_ip(request),
                    user_agent=request.META.get('HTTP_USER_AGENT', ''),
                    details={
                        'recipient_country': transfer.recipient_country,
                        'recipient_organization': transfer.recipient_organization,
                        'transfer_date': str(transfer.transfer_date)
                    }
                )
                
                messages.success(request, _('Cross-border transfer record created successfully.'))
                return redirect('gdpr_platform:cross_border_transfers')
        else:
            form = CrossBorderTransferForm()
        
        context = {
            'transfers': transfers,
            'form': form,
            'title': 'Cross-Border Transfers',
            'active_transfers': active_transfers,
            'pending_transfers': pending_transfers,
            'recipient_countries': recipient_countries,
            'risk_score': risk_score,
            'countries': countries,
            'mechanisms': mechanisms,
            'selected_country': country,
            'selected_mechanism': mechanism,
            'selected_status': status,
            'selected_range': date_range
        }
        
        return render(request, 'dpo_templates/cross_border_transfers.html', context)
        
    except Exception as e:
        logger.error(f"Cross-border transfers view error for user {request.user.id}: {str(e)}")
        messages.error(request, _('An error occurred loading cross-border transfers.'))
        return redirect('gdpr_platform:dashboard')

@login_required
@role_required('admin', 'compliance_officer', 'dpo', 'user')
def data_export(request):
    """Handle user data export requests"""
    try:
        if request.method == 'POST':
            # Get selected format and categories
            export_format = request.POST.get('format', 'json')
            categories = request.POST.getlist('categories', [])  # Changed from data_categories to categories
            
            # Get user data
            user_data = get_user_data_categories(request.user)
            
            # Filter data based on selected categories if specific categories were selected
            if categories:
                filtered_data = {}
                for category in categories:
                    if category in user_data:
                        filtered_data[category] = user_data[category]
                user_data = filtered_data
            
            try:
                # Create the export based on the requested format
                if export_format == 'json':
                    export_data = create_json_export(user_data)
                    content_type = 'application/json'
                elif export_format == 'csv':
                    export_data = create_csv_export(user_data)
                    content_type = 'text/csv'
                elif export_format == 'xml':
                    export_data = create_xml_export(user_data)
                    content_type = 'application/xml'
                else:
                    raise ValueError(f"Unsupported export format: {export_format}")
        
                # Create export record
                export_request = DataRequest.objects.create(
                    user=request.user,
                    request_type='export',
                        status='completed',
                        file_format=export_format,
                        data_categories=categories,
                        description=f"Data export in {export_format.upper()} format"
                )
                
                # Send notification email
                send_export_notification_email(request.user, export_request)
            
                # Return the exported data
                response = HttpResponse(export_data, content_type=content_type)
                response['Content-Disposition'] = f'attachment; filename="user_data_{timezone.now().strftime("%Y%m%d_%H%M%S")}.{export_format}"'
                return response
            
            except Exception as e:
                logger.error(f"Data export error for user {request.user.id}: {str(e)}")
                messages.error(request, _("An error occurred while exporting your data. Please try again."))
                return redirect('gdpr_platform:data_export')
        
        # Get previous exports for GET request
        previous_exports = DataRequest.objects.filter(
            user=request.user,
            request_type='export'
        ).order_by('-request_date')[:5]
        
        return render(request, 'gdpr/data_export.html', {  # Changed from user_templates to gdpr
            'title': _("Export Your Data"),
            'previous_exports': previous_exports,
            'exportable_categories': get_exportable_data_categories()  # Changed from data_categories to exportable_categories
        })
    except Exception as e:
        logger.error(f"Data export error for user {request.user.id}: {str(e)}")
        messages.error(request, _("An error occurred while processing your request. Please try again."))
        return redirect('gdpr_platform:dashboard')
        
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login, logout, get_user_model, authenticate
from django.contrib.auth.decorators import login_required, permission_required
from django.contrib.auth.views import LoginView
from django.contrib.auth.forms import SetPasswordForm, AuthenticationForm
from django.contrib import messages
from django.http import JsonResponse, HttpResponse, FileResponse
from django.urls import reverse_lazy
from django.utils import timezone
from django.views.decorators.http import require_POST
from django.core.paginator import Paginator, PageNotAnInteger, EmptyPage
from django.db.models import Q, Sum, Avg, F, DurationField, ExpressionWrapper
from django.views.generic import FormView
from django.contrib.auth.forms import PasswordResetForm
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.views.generic.base import TemplateView
from django.utils.translation import gettext_lazy as _
from django.utils.decorators import method_decorator
from django.core.exceptions import ValidationError
from django.contrib.sessions.models import Session
from django.conf import settings
from django.core.cache import cache
from django.db import transaction
import logging
import json
import csv
from io import StringIO, BytesIO
from datetime import datetime, timedelta
import os
import hashlib
import base64
import pyotp
import qrcode
import qrcode.image.svg
from functools import wraps
from .models import (
    Role, AuditLog, DataRequest, DataCategory,
    DataBreach, BreachTimeline, CrossBorderTransfer,
    CookieConsent, DataTransfer, ProcessingActivity,
    DataProcessingActivity, ProcessingRequirement,
    UserSession, PrivacyPolicy, UserPrivacyPolicyConsent,
    DataExport, TwoFactorAuth, TrustedDevice, TrustSettings,
    ActivityLog, DeletionTask, BreachNotification,
    ConsentRecord, Task, Report, ReportSchedule, SystemSettings
)
from .forms import (
    RegistrationForm, DataRequestForm, CookiePreferencesForm,
    CrossBorderTransferForm, TwoFactorSetupForm
)
from .monitoring import breach_monitor
from django_otp.plugins.otp_totp.models import TOTPDevice
from django_otp.util import random_hex
from .decorators import (
    role_required, permission_required, dpo_required,
    admin_required, compliance_officer_required, any_staff_role_required
)
from .services.compliance_checker import ComplianceCheckerService
import pytz
from celery import shared_task
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table
from reportlab.lib.styles import getSampleStyleSheet
from .utils import get_client_ip
from django.template import TemplateDoesNotExist
from django.conf import settings as django_settings
import xml.etree.ElementTree as ET
import io
from django.contrib.auth.models import Group
from django.contrib.auth.models import Permission

User = get_user_model()
logger = logging.getLogger(__name__)

def rate_limit(key_prefix, limit=5, period=300):
    """
    Rate limiting decorator
    :param key_prefix: Prefix for the cache key
    :param limit: Number of allowed requests
    :param period: Time period in seconds
    """
    def decorator(func):
        @wraps(func)
        def wrapper(request, *args, **kwargs):
            client_ip = request.META.get('REMOTE_ADDR', '')
            cache_key = f"{key_prefix}:{client_ip}"
            
            # Get current request count
            requests = cache.get(cache_key, 0)
            
            if requests >= limit:
                messages.error(request, _('Too many attempts. Please try again later.'))
                return redirect('gdpr_platform:login')
            
            # Increment request count
            cache.set(cache_key, requests + 1, period)
            
            return func(request, *args, **kwargs)
        return wrapper
    return decorator

class CustomPasswordResetView(FormView):
    template_name = 'registration/password_reset_form.html'
    form_class = PasswordResetForm
    success_url = reverse_lazy('gdpr_platform:custom_password_reset_done')
    email_template_name = 'emails/password_reset_email.html'
    subject_template_name = 'emails/password_reset_subject.txt'
    
    @method_decorator(rate_limit('password_reset', limit=3, period=3600))
    def post(self, request, *args, **kwargs):
        return super().post(request, *args, **kwargs)
    
    def form_valid(self, form):
        """Add AI security checks and rate limiting before processing the reset request"""
        email = form.cleaned_data['email']
        user_ip = self.request.META.get('REMOTE_ADDR', '')
        
        # Hash the IP for security logging
        hashed_ip = hashlib.sha256(user_ip.encode()).hexdigest()
        
        # Log the reset attempt for AI monitoring
        AuditLog.objects.create(
            user=None,
            action='password_reset_requested',
            resource_type='user',
            resource_id=email,
            ip_address=hashed_ip,  # Store hashed IP
            user_agent=self.request.META.get('HTTP_USER_AGENT', ''),
            details={
                'email': email,
                'timestamp': str(timezone.now()),
                'request_origin': hashed_ip
            }
        )
        
        # Process the password reset
        opts = {
            'use_https': self.request.is_secure(),
            'token_generator': default_token_generator,
            'email_template_name': self.email_template_name,
            'subject_template_name': self.subject_template_name,
            'request': self.request,
            'extra_email_context': {
                'user_ip': hashed_ip,
                'timestamp': timezone.now().strftime('%Y-%m-%d %H:%M:%S UTC'),
                'security_level': 'Enhanced',
                'ai_verified': True
            }
        }
        
        try:
            form.save(**opts)
        except Exception as e:
            logger.error(f"Password reset error for {email}: {str(e)}")
            # Don't reveal if the email exists
            pass
        
        return super().form_valid(form)

class PasswordResetConfirmView(FormView):
    template_name = 'registration/password_reset_confirm.html'
    form_class = SetPasswordForm
    success_url = reverse_lazy('gdpr_platform:custom_password_reset_complete')
    token_generator = default_token_generator

    def get_user(self, uidb64):
        try:
            uid = urlsafe_base64_decode(uidb64).decode()
            user = User.objects.get(pk=uid)
            if not user.is_active:
                return None
            return user
        except (TypeError, ValueError, OverflowError, User.DoesNotExist, ValidationError):
            return None

    def get_form(self, form_class=None):
        user = self.get_user(self.kwargs.get('uidb64'))
        token = self.kwargs.get('token')
        
        if user is not None and self.token_generator.check_token(user, token):
            return self.form_class(user, **self.get_form_kwargs())
        return None

    @method_decorator(rate_limit('password_reset_confirm', limit=3, period=3600))
    def post(self, request, *args, **kwargs):
        return super().post(request, *args, **kwargs)

    def form_valid(self, form):
        user = form.user
        new_password = form.cleaned_data['new_password1']
        
        try:
        # Set the new password
            form.save()
            
            # Invalidate all existing sessions for security
            Session.objects.filter(expire_date__gte=timezone.now()).delete()
        
        # Log the successful password reset
            AuditLog.objects.create(
                user=user,
                action='password_reset_completed',
                resource_type='user',
                resource_id=str(user.id),
                    ip_address=hashlib.sha256(self.request.META.get('REMOTE_ADDR', '').encode()).hexdigest(),
                user_agent=self.request.META.get('HTTP_USER_AGENT', ''),
                details={
                    'timestamp': str(timezone.now()),
                        'security_measures': ['password_changed', 'sessions_terminated', 'security_logs_updated']
                    }
                )
                
            messages.success(self.request, _('Your password has been successfully reset.'))
            return super().form_valid(form)
            
        except Exception as e:
            logger.error(f"Password reset confirmation error for user {user.id}: {str(e)}")
            messages.error(self.request, _('An error occurred. Please try again.'))
            return self.form_invalid(form)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        user = self.get_user(self.kwargs.get('uidb64'))
        token = self.kwargs.get('token')
        
        if user is not None and self.token_generator.check_token(user, token):
            context['validlink'] = True
        else:
            context['validlink'] = False
            
        return context

@login_required
@role_required('admin', 'compliance_officer', 'dpo', 'user')
def handle_data_deletion(request):
    """Handle user data deletion requests with comprehensive tracking and transparency"""
    if request.method == 'POST':
        try:
            with transaction.atomic():
                user = request.user
                
                # Get selected categories
                categories = request.POST.getlist('data_categories', [])
                if not categories:
                    messages.error(request, _('Please select at least one data category to delete.'))
                    return redirect('gdpr_platform:data_deletion')
                
                # Create data deletion request with detailed tracking
            deletion_request = DataRequest.objects.create(
                    user=user,
                request_type='deletion',
                status='pending',
                    data_categories=categories,
                    description=request.POST.get('deletion_reason', ''),
                    notes=f"IP: {request.META.get('REMOTE_ADDR', '')}, UA: {request.META.get('HTTP_USER_AGENT', '')}"
                )
                
                # Log the deletion request with comprehensive audit trail
            AuditLog.objects.create(
                    user=user,
                action='data_deletion_requested',
                    resource_type='user',
                    resource_id=str(user.id),
                    ip_address=request.META.get('REMOTE_ADDR', ''),
                    user_agent=request.META.get('HTTP_USER_AGENT', ''),
                    details={
                    'request_id': str(deletion_request.id),
                        'timestamp': str(timezone.now()),
                        'deletion_scope': categories,
                        'immediate_deletion': request.POST.get('immediate_deletion', False),
                        'retention_policy_applied': True,
                        'backup_deletion_scheduled': True
                    }
                )
                
                # Calculate deletion schedule based on retention policies
            retention_period = 30  # Default retention period
            try:
                if isinstance(user.data_retention_policy, dict):
                    personal_info = user.data_retention_policy.get('personal_info', {})
                    if isinstance(personal_info, dict):
                        retention_period = int(personal_info.get('retention_period', 30))
            except (AttributeError, TypeError, ValueError):
                pass  # Use default retention period
                
            deletion_date = timezone.now() + timedelta(days=retention_period)
            
                # Handle immediate deletion requests if allowed
            if request.POST.get('immediate_deletion') and user.has_permission('immediate_deletion'):
                deletion_date = timezone.now()
            
            # Update user status
            user.account_status = 'pending_deletion'
            user.deletion_scheduled_date = deletion_date
            user.save()
                
            # Schedule data deletion tasks
            schedule_data_deletion_tasks(user, deletion_date, deletion_request.id)
            
            # Revoke all sessions
            Session.objects.filter(expire_date__gte=timezone.now()).delete()
            
            # Send confirmation email
            send_deletion_confirmation_email(user, deletion_request, deletion_date)
                
            messages.success(request, _(
                'Your data deletion request has been received and will be processed. '
                'You will receive a confirmation email with further details.'
            ))
            return redirect('gdpr_platform:logout')
                    
        except Exception as e:
            logger.error(f"Data deletion error for user {request.user.id}: {str(e)}")
            messages.error(request, _('An error occurred processing your request. Please try again.'))
            return redirect('gdpr_platform:dashboard')
            
    # Get available data categories for deletion
    data_categories = get_exportable_data_categories()
    
    # Get retention policies with proper type checking
    retention_policies = {}
    try:
        if hasattr(django_settings, 'GDPR_RETENTION_PERIODS'):
            retention_periods = getattr(django_settings, 'GDPR_RETENTION_PERIODS', {})
            if isinstance(retention_periods, dict):
                retention_policies = {str(k): v for k, v in retention_periods.items()}
    except Exception as e:
        logger.error(f"Error getting retention policies: {str(e)}")
    
    return render(request, 'user_templates/data_deletion.html', {
        'title': _('Request Data Deletion'),
        'data_categories': data_categories,
        'retention_policies': retention_policies,
        'can_request_immediate': request.user.has_permission('immediate_deletion')
    })

def schedule_data_deletion_tasks(user, deletion_date, request_id):
    """Schedule comprehensive data deletion tasks"""
    tasks = [
        ('user_account', 'Delete user account and profile'),
        ('personal_data', 'Delete personal information'),
        ('activity_logs', 'Anonymize activity logs'),
        ('analytics_data', 'Delete analytics data'),
        ('backup_data', 'Remove from backups'),
        ('third_party', 'Notify third-party processors'),
        ('audit_trail', 'Create deletion audit trail')
    ]
    
    for task_type, description in tasks:
        DeletionTask.objects.create(
            user=user,
            request_id=request_id,
            task_type=task_type,
            description=description,
            scheduled_date=deletion_date,
            status='scheduled'
        )

def get_user_data_categories(user):
    """Get user data organized by categories"""
    return {
        'personal_info': {
            'username': user.username,
            'email': user.email,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'date_joined': str(user.date_joined),
            'last_login': str(user.last_login),
            'phone_number': user.phone_number,
            'address': user.address,
            'city': user.city,
            'country': user.country,
            'postal_code': user.postal_code,
            'language_preference': user.preferred_language
        },
        'privacy_settings': {
            'marketing_preferences': user.marketing_preferences,
            'privacy_settings': user.privacy_settings,
            'data_retention_policy': user.data_retention_policy,
            'cookie_preferences': get_current_cookie_preferences(user),
            'privacy_policy_consents': get_privacy_policy_consents(user)
        },
        'security_settings': {
            'two_factor_enabled': user.two_factor_enabled,
            'last_login_ip': user.last_login_ip,
            'account_status': user.account_status,
            'security_preferences': get_security_preferences(user)
        },
        'activity_history': {
            'login_history': list(UserSession.objects.filter(user=user).values(
                'login_time', 'last_activity', 'ip_address', 'user_agent', 'is_active'
            )),
            'data_requests': list(DataRequest.objects.filter(user=user).values(
                'request_type', 'status', 'request_date', 'completion_date', 'description'
            )),
            'consent_history': list(ConsentRecord.objects.filter(user=user).values(
                'consent_type', 'status', 'granted_at', 'withdrawn_at', 'purpose'
            ))
        }
    }

def send_deletion_confirmation_email(user, deletion_request, deletion_date):
    """Send detailed deletion confirmation email"""
    try:
        subject = _('Your Data Deletion Request Confirmation')
        message = render_to_string('emails/deletion_confirmation.html', {
            'user': user,
            'request_id': deletion_request.tracking_id,
            'deletion_date': deletion_date,
            'data_categories': deletion_request.data_categories,
            'retention_period': django_settings.GDPR_RETENTION_PERIODS['personal_info'],
            'contact_email': django_settings.SUPPORT_EMAIL
        })
        
        send_mail(
            subject=subject,
            message=strip_tags(message),
            from_email=django_settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            html_message=message
        )
    except Exception as e:
        logger.error(f"Failed to send deletion confirmation email to {user.email}: {str(e)}")

@login_required
@role_required('admin', 'compliance_officer', 'dpo', 'user')
def data_deletion(request):
    """Redirect to handle_data_deletion for backward compatibility"""
    return handle_data_deletion(request)

@login_required
@role_required('admin', 'compliance_officer', 'user')
def update_cookie_consent(request):
    """Handle cookie consent updates with full transparency and granular control"""
    if request.method == 'POST':
        try:
            form = CookiePreferencesForm(request.POST)
            if form.is_valid():
                    with transaction.atomic():
                    # Create new consent record with detailed tracking
                        new_consent = CookieConsent.objects.create(
                            user=request.user,
                            necessary_cookies=True,  # Always required
                            analytics_cookies=form.cleaned_data.get('analytics_cookies', False),
                            marketing_cookies=form.cleaned_data.get('marketing_cookies', False),
                            functional_cookies=form.cleaned_data.get('functional_cookies', False),
                            ip_address=request.META.get('REMOTE_ADDR', ''),
                        user_agent=request.META.get('HTTP_USER_AGENT', ''),
                        consent_version=django_settings.COOKIE_POLICY_VERSION,
                        consent_method='explicit',
                        consent_timestamp=timezone.now(),
                        consent_expiry=timezone.now() + timedelta(days=django_settings.COOKIE_CONSENT_EXPIRY),
                        consent_details={
                            'form_submitted': True,
                            'source': 'web_form',
                            'explicit_action': True,
                            'policy_version': django_settings.COOKIE_POLICY_VERSION,
                            'browser_info': request.META.get('HTTP_USER_AGENT', ''),
                            'screen_resolution': request.POST.get('screen_resolution', ''),
                            'consent_language': request.LANGUAGE_CODE,
                            'geo_location': get_location_from_ip(request.META.get('REMOTE_ADDR', '')),
                        }
                    )
                    
                    # Log consent update with detailed audit trail
                        AuditLog.objects.create(
                            user=request.user,
                            action='cookie_preferences_updated',
                            resource_type='cookie_consent',
                            resource_id=str(new_consent.id),
                            ip_address=request.META.get('REMOTE_ADDR', ''),
                            user_agent=request.META.get('HTTP_USER_AGENT', ''),
                            details={
                                'new_consent_id': str(new_consent.id),
                                'changes': {
                                    'analytics': new_consent.analytics_cookies,
                                    'marketing': new_consent.marketing_cookies,
                                    'functional': new_consent.functional_cookies
                            },
                            'previous_settings': get_previous_consent_settings(request.user),
                            'consent_version': django_settings.COOKIE_POLICY_VERSION,
                            'expiry_date': str(new_consent.consent_expiry),
                            'consent_method': 'explicit',
                            'user_notification': True
                        }
                    )
                    
                    # Send confirmation email
                    send_consent_confirmation_email(request.user, new_consent)
                    
                    messages.success(request, _('Your cookie preferences have been updated. You can modify these settings at any time.'))
                    return JsonResponse({
                        'status': 'success',
                        'message': _('Cookie preferences updated successfully'),
                        'details': {
                            'consent_id': str(new_consent.id),
                            'expiry_date': str(new_consent.consent_expiry),
                            'settings': {
                                'necessary': True,
                                'analytics': new_consent.analytics_cookies,
                                'marketing': new_consent.marketing_cookies,
                                'functional': new_consent.functional_cookies
                            }
                        }
                    })
            else:
                return JsonResponse({
                    'status': 'error',
                    'errors': form.errors,
                    'message': _('Please review your consent selections')
                }, status=400)
                
        except Exception as e:
            logger.error(f"Cookie consent update error for user {request.user.id}: {str(e)}")
            return JsonResponse({
                'status': 'error',
                'message': _('An error occurred updating your preferences.')
            }, status=500)
    
    return JsonResponse({'status': 'error', 'message': _('Invalid request method.')}, status=405)

def get_previous_consent_settings(user):
    """Get user's previous consent settings for audit trail"""
    previous_consent = CookieConsent.objects.filter(
        user=user
    ).exclude(
        consent_version=django_settings.COOKIE_POLICY_VERSION
    ).order_by('-consent_timestamp').first()
    
    if previous_consent:
        return {
            'analytics': previous_consent.analytics_cookies,
            'marketing': previous_consent.marketing_cookies,
            'functional': previous_consent.functional_cookies,
            'version': previous_consent.consent_version,
            'timestamp': str(previous_consent.consent_timestamp)
        }
    return None

def send_consent_confirmation_email(user, consent):
    """Send confirmation email for consent updates"""
    try:
        subject = _('Your Privacy Settings Have Been Updated')
        message = render_to_string('emails/consent_confirmation.html', {
            'user': user,
            'consent': consent,
            'settings_url': reverse('gdpr_platform:privacy_settings'),
            'timestamp': timezone.now(),
        })
        
        send_mail(
            subject=subject,
            message=strip_tags(message),
            from_email=django_settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            html_message=message
        )
    except Exception as e:
        logger.error(f"Failed to send consent confirmation email to {user.email}: {str(e)}")

@login_required
@role_required('admin', 'compliance_officer', 'user')
def privacy_settings(request):
    """Handle privacy settings"""
    try:
        if request.method == 'POST':
            # Update privacy settings
            privacy_settings = request.user.privacy_settings if hasattr(request.user, 'privacy_settings') else {}
            privacy_settings.update({
                'marketing_emails': request.POST.get('marketing_emails') == 'on',
                'data_sharing': request.POST.get('data_sharing') == 'on',
                'analytics': request.POST.get('analytics') == 'on',
                'last_updated': str(timezone.now())
            })
            request.user.privacy_settings = privacy_settings
            request.user.save()
            
            # Log the update
            AuditLog.objects.create(
                user=request.user,
                action='privacy_settings_updated',
                resource_type='privacy_settings',
                resource_id=str(request.user.id)
            )
            
            messages.success(request, _('Your privacy settings have been updated.'))
            return redirect('gdpr_platform:privacy_settings')
        
        return render(request, 'user_templates/privacy_settings.html', {
            'title': _('Privacy Settings'),
            'privacy_settings': request.user.privacy_settings if hasattr(request.user, 'privacy_settings') else {}
        })
    except Exception as e:
        logger.error(f"Privacy settings error for user {request.user.id}: {str(e)}")
        messages.error(request, _('An error occurred while updating your privacy settings.'))
        return redirect('gdpr_platform:dashboard')

def landing(request):
    """Landing page view"""
    if request.user.is_authenticated:
        return redirect('gdpr_platform:dashboard')
    return render(request, 'landing.html', {
        'title': 'Welcome to GDPR Platform'
    })

def custom_login(request):
    """Custom login view with security features"""
    try:
        next_url = request.GET.get('next', '')
        is_admin = next_url and next_url.startswith('/admin/')
        
        if request.user.is_authenticated:
                # Assign default role if needed
            assign_default_role(request.user)
                    
            if request.user.is_staff:
                    return redirect('gdpr_platform:admin_dashboard')
            return redirect('gdpr_platform:dashboard')
            
        if request.method == 'POST':
            username = request.POST.get('username')
            password = request.POST.get('password')
            user = authenticate(request, username=username, password=password)
            
            if user is not None:
                if user.is_active:
                    # Check if 2FA is required
                    if user.two_factor_enabled:
                        request.session['2fa_user_id'] = user.id
                        request.session['2fa_redirect_url'] = next_url
                        return redirect('gdpr_platform:two_factor_verify')
                    
                    # Log the successful login
                    login(request, user)
                    logger.info(f"Successful login for user: {username}")
                            
                            # Assign default role if needed
                    assign_default_role(user)
                    
                    # Update last login and create session record
                    user.last_login = timezone.now()
                    user.save(update_fields=['last_login'])
                    
                    # Create session record
                    if not request.session.session_key:
                        request.session.save()
                    
                    UserSession.objects.create(
                        user=user,
                        session_key=request.session.session_key,
                        ip_address=get_client_ip(request),
                        user_agent=request.META.get('HTTP_USER_AGENT', '')
                    )
                    
                    # Handle redirection
                    if user.is_staff:
                        return redirect('gdpr_platform:admin_dashboard')
                    return redirect('gdpr_platform:dashboard')
                else:
                    messages.error(request, _('Your account is inactive. Please contact support.'))
            else:
                # Log failed login attempt
                logger.warning(f"Failed login attempt for username: {username}")
                breach_monitor.log_failed_login(username, get_client_ip(request))
                messages.error(request, _('Invalid username or password.'))
        
        return render(request, 'registration/login.html', {
            'title': 'Admin Login' if is_admin else 'Login',
            'form': AuthenticationForm(),
            'show_register': not is_admin,
            'show_password_reset': True,
            'is_admin': is_admin,
            'next': next_url
        })
    except Exception as e:
        logger.error(f"Error in custom_login: {str(e)}")
        messages.error(request, _('An error occurred while logging in. Please try again later.'))
        return redirect('gdpr_platform:landing')

def get_location_from_ip(ip):
    """Get location information from IP address"""
    # This is a placeholder. In production, you would use a geolocation service
    return {
        'country': 'Unknown',
        'city': 'Unknown',
        'region': 'Unknown'
    }

@login_required
def custom_logout(request):
    """Custom logout view that handles cleanup and logging"""
    try:
        # Log the logout action
        AuditLog.objects.create(
            user=request.user,
            action='LOGOUT',
            status='SUCCESS',
            ip_address=get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', '')
        )
        
        # Perform logout
        logout(request)
        return redirect('gdpr_platform:landing')
    except Exception as e:
        logger.error(f"Error during logout for {request.user.id}: {str(e)}")
        logout(request)
        return redirect('gdpr_platform:landing')

def register(request):
    """Handle user registration with GDPR compliance"""
    if request.user.is_authenticated:
        return redirect('gdpr_platform:user_dashboard')

    if request.method == 'POST':
        form = RegistrationForm(request.POST, request.FILES)
        if form.is_valid():
            try:
                with transaction.atomic():
                    user = form.save()
                    
                    # Assign default user role
                    regular_user_role = Role.objects.get(name='user')
                    user.roles.add(regular_user_role)
                    
                    AuditLog.objects.create(
                        user=user,
                        action='user_registration',
                        resource_type='user',
                        resource_id=str(user.id),
                        ip_address=get_client_ip(request),
                        user_agent=request.META.get('HTTP_USER_AGENT', ''),
                        details={
                            'timestamp': str(timezone.now()),
                            'consents': {
                                'privacy_policy': form.cleaned_data.get('privacy_policy_consent'),
                                'data_processing': form.cleaned_data.get('data_processing_consent'),
                                'marketing': form.cleaned_data.get('marketing_consent', False)
                            }
                        }
                    )
                    
                    CookieConsent.objects.create(
                        user=user,
                        necessary_cookies=True,
                        analytics_cookies=False,
                        marketing_cookies=form.cleaned_data.get('marketing_consent', False),
                        functional_cookies=True,
                        ip_address=get_client_ip(request),
                        user_agent=request.META.get('HTTP_USER_AGENT', '')
                    )
                    
                    current_policy = PrivacyPolicy.objects.filter(is_active=True).first()
                    if current_policy:
                        UserPrivacyPolicyConsent.objects.create(
                            user=user,
                            policy=current_policy,
                            ip_address=get_client_ip(request),
                            user_agent=request.META.get('HTTP_USER_AGENT', '')
                        )
                    
                    login(request, user)
                    
                    # Ensure session is created and saved
                    if not request.session.session_key:
                        request.session.save()
                    
                    UserSession.objects.create(
                        user=user,
                        session_key=request.session.session_key,
                        ip_address=get_client_ip(request),
                        user_agent=request.META.get('HTTP_USER_AGENT', '')
                    )
                    
                    try:
                        # Get DPO email from settings or use default
                        dpo_email = getattr(django_settings, 'DPO_EMAIL', 'dpo@gdprplatform.com')
                        
                        # Prepare email context
                        email_context = {
                            'user': user,
                            'site_name': getattr(django_settings, 'SITE_NAME', 'GDPR Platform'),
                            'dpo_email': dpo_email,
                            'request': request,
                        }
                        
                        # Get email settings with defaults
                        from_email = getattr(django_settings, 'DEFAULT_FROM_EMAIL', 'noreply@gdprplatform.com')
                        
                        send_mail(
                            subject=_('Welcome to GDPR Platform'),
                            message=render_to_string('emails/welcome_email.txt', email_context),
                            from_email=from_email,
                            recipient_list=[user.email],
                            html_message=render_to_string('emails/welcome_email.html', email_context)
                        )
                    except Exception as e:
                        logger.error(f"Failed to send welcome email to {user.email}: {str(e)}")
                    
                    messages.success(request, _('Registration successful. Welcome!'))
                    
                    # Redirect directly to user dashboard for new users
                    return redirect('gdpr_platform:user_dashboard')
                    
            except Exception as e:
                logger.error(f"Registration error: {str(e)}")
                messages.error(request, _('An error occurred during registration. Please try again.'))
        else:
            # Log form validation errors
            logger.error(f"Registration form validation errors: {form.errors}")
            for field, errors in form.errors.items():
                for error in errors:
                    messages.error(request, f"{field}: {error}")
    else:
        form = RegistrationForm()
    
    return render(request, 'registration/register.html', {
        'form': form,
        'title': _('Register'),
        'privacy_policy': PrivacyPolicy.objects.filter(is_active=True).first()
    })

@login_required
@role_required('admin', 'compliance_officer', 'dpo', 'user')
def data_rights_dashboard(request):
    """Display user's data rights and GDPR information"""
    try:
        # Get user's data requests, ordered by request date
        user_requests = DataRequest.objects.filter(user=request.user).order_by('-request_date')
        
        # Get latest cookie consent
        cookie_consent = CookieConsent.objects.filter(user=request.user).order_by('-timestamp').first()
        
        # Prepare context with user data
        context = {
            'title': _('Data Rights Dashboard'),
            'user': request.user,  # Use user instead of user_profile
            'user_requests': user_requests,
            'cookie_consent': cookie_consent,
            'two_factor_enabled': request.user.two_factor_enabled,
            'recent_activity': ActivityLog.objects.filter(user=request.user).order_by('-timestamp')[:5],
            'active_sessions': UserSession.objects.filter(user=request.user, is_active=True).order_by('-last_activity'),
            'breach_notifications': BreachNotification.objects.filter(
                recipient=request.user,
                status__in=['pending', 'sent']
            ).order_by('-created_at'),
            'data_processing': DataProcessingActivity.objects.filter(
                processor=request.user,
                is_active=True
            ).order_by('-created_at'),
            'retention_settings': request.user.data_retention_policy,
            'open_tickets': SupportTicket.objects.filter(
                user=request.user,
                status__in=['open', 'in_progress']
            ).order_by('-created_at'),
            'user_rights': {
                'access': True,
                'rectification': True,
                'erasure': True,
                'portability': True,
                'object': True,
                'restrict_processing': True
            }
        }
        
        # Choose template based on user role
        if request.user.has_role('admin'):
            template = 'admin_templates/admin_dashboard.html'
            context.update({
                'total_users': CustomUser.objects.count(),
                'pending_requests': DataRequest.objects.filter(status='pending').count(),
                'compliance_score': calculate_compliance_score(),
                'recent_breaches': DataBreach.objects.filter(
                    resolved=False
                ).order_by('-date_discovered')[:5],
            })
        else:
            template = 'user_templates/dashboard.html'
        
        return render(request, template, context)
        
    except Exception as e:
        logger.error(f"Dashboard error for user {request.user.id}: {str(e)}")
        messages.error(request, _('An error occurred loading the dashboard.'))
        return render(request, 'user_templates/dashboard.html', {
            'error': True,
            'title': 'Dashboard',
            'user': request.user  # Include user in error context
    })

@login_required
def extend_session(request):
    """Extend user session if active"""
    if request.method == 'POST':
        try:
            request.session.modified = True
            return JsonResponse({'status': 'success'})
        except Exception as e:
            logger.error(f"Session extension error for user {request.user.id}: {str(e)}")
            return JsonResponse({'status': 'error'}, status=500)
    return JsonResponse({'status': 'error', 'message': 'Invalid request method'}, status=405)

@login_required
@role_required('admin', 'compliance_officer', 'dpo', 'user')
def export_user_data(request):
    """Handle user data export requests"""
    try:
        if request.method == 'POST':
            # Get selected format and categories
            export_format = request.POST.get('format', 'json')
            categories = request.POST.getlist('categories', [])  # Changed from data_categories to categories
            
            # Get user data
            user_data = get_user_data_categories(request.user)
            
            # Filter data based on selected categories if specific categories were selected
            if categories:
                filtered_data = {}
                for category in categories:
                    if category in user_data:
                        filtered_data[category] = user_data[category]
                user_data = filtered_data
            
            try:
                # Create the export based on the requested format
                if export_format == 'json':
                            export_data = create_json_export(user_data)
                            content_type = 'application/json'
                elif export_format == 'csv':
                            export_data = create_csv_export(user_data)
                            content_type = 'text/csv'
                elif export_format == 'xml':
                            export_data = create_xml_export(user_data)
                            content_type = 'application/xml'
                else:
                    raise ValueError(f"Unsupported export format: {export_format}")
        
                # Create export record
                export_request = DataRequest.objects.create(
                    user=request.user,
                                request_type='export',
                                status='completed',
                                file_format=export_format,
                                data_categories=categories,
                                description=f"Data export in {export_format.upper()} format"
                )
                
                # Send notification email
                send_export_notification_email(request.user, export_request)
            
                        # Return the exported data
                response = HttpResponse(export_data, content_type=content_type)
                response['Content-Disposition'] = f'attachment; filename="user_data_{timezone.now().strftime("%Y%m%d_%H%M%S")}.{export_format}"'
                return response
            
            except Exception as e:
                logger.error(f"Data export error for user {request.user.id}: {str(e)}")
                messages.error(request, _("An error occurred while exporting your data. Please try again."))
                return redirect('gdpr_platform:data_export')
        
        # Get previous exports for GET request
        previous_exports = DataRequest.objects.filter(
                user=request.user,
                request_type='export'
            ).order_by('-request_date')[:5]
        
        return render(request, 'gdpr/data_export.html', {  # Changed from user_templates to gdpr
            'title': _("Export Your Data"),
            'previous_exports': previous_exports,
            'exportable_categories': get_exportable_data_categories()  # Changed from data_categories to exportable_categories
        })
        
    except Exception as e:
        logger.error(f"Data export error for user {request.user.id}: {str(e)}")
        messages.error(request, _("An error occurred while processing your request. Please try again."))
        return redirect('gdpr_platform:dashboard')

def get_current_cookie_preferences(user):
    """Get user's current cookie preferences"""
    consent = CookieConsent.objects.filter(user=user).order_by('-timestamp').first()
    if consent:
        return {
            'necessary': consent.necessary_cookies,
            'analytics': consent.analytics_cookies,
            'marketing': consent.marketing_cookies,
            'functional': consent.functional_cookies,
            'last_updated': str(consent.timestamp)
        }
    return None

def get_privacy_policy_consents(user):
    """Get user's privacy policy consent history"""
    return list(UserPrivacyPolicyConsent.objects.filter(user=user).values(
        'policy__version',
        'consent_date',
        'ip_address',
        'user_agent'
    ))

def get_security_preferences(user):
    """Get user's security preferences"""
    return {
        'two_factor_auth': user.two_factor_enabled,
        'trusted_devices_enabled': hasattr(user, 'trust_settings'),
        'session_timeout': getattr(user, 'session_timeout', django_settings.SESSION_COOKIE_AGE),
        'login_notification': getattr(user, 'login_notification_enabled', False)
    }

def create_json_export(data):
    """Create JSON export of user data"""
    return json.dumps(data, indent=2, default=str)

def create_csv_export(data):
    """Create CSV export of user data"""
    output = StringIO()
    writer = csv.writer(output)
    
    for category, category_data in data.items():
        writer.writerow([f"--- {category.upper()} ---"])
        if isinstance(category_data, dict):
            for key, value in category_data.items():
                if isinstance(value, (list, dict)):
                    writer.writerow([key])
                    if isinstance(value, list):
                        # Handle list of dictionaries
                        if value and isinstance(value[0], dict):
                            headers = value[0].keys()
                            writer.writerow(headers)
                            for item in value:
                                if isinstance(item, dict):
                                    writer.writerow([str(item.get(h, '')) for h in headers])
                                else:
                                    writer.writerow([str(item)])
                        else:
                            # Handle list of non-dictionary items
                            for item in value:
                                writer.writerow([str(item)])
                    else:
                        # Handle nested dictionary
                        for k, v in value.items():
                            writer.writerow([k, str(v)])
                else:
                    writer.writerow([key, str(value)])
        else:
            # Handle non-dictionary category data
            writer.writerow(['Value', str(category_data)])
        writer.writerow([])  # Empty row between categories
    
    return output.getvalue()

def create_xml_export(data):
    """Create XML export of user data"""
    root = ET.Element("user_data")
    
    def dict_to_xml(parent, dictionary):
        for key, value in dictionary.items():
            child = ET.SubElement(parent, key.replace(' ', '_'))
            if isinstance(value, dict):
                dict_to_xml(child, value)
            elif isinstance(value, list):
                for item in value:
                    item_elem = ET.SubElement(child, "item")
                    if isinstance(item, dict):
                        dict_to_xml(item_elem, item)
                    else:
                        item_elem.text = str(item)
            else:
                child.text = str(value)
    
    dict_to_xml(root, data)
    return ET.tostring(root, encoding='unicode', method='xml', pretty_print=True)

def get_exportable_data_categories():
    """Get available data categories for export"""
    return [
        {
            'id': 'personal_info',
            'name': _('Personal Information'),
            'description': _('Your basic account and profile information')
        },
        {
            'id': 'privacy_settings',
            'name': _('Privacy Settings'),
            'description': _('Your privacy preferences and consents')
        },
        {
            'id': 'activity_history',
            'name': _('Activity History'),
            'description': _('Your activity logs and data requests')
        },
        {
            'id': 'data_processing',
            'name': _('Data Processing'),
            'description': _('Information about how your data is processed')
        },
        {
            'id': 'security_settings',
            'name': _('Security Settings'),
            'description': _('Your security preferences and trusted devices')
        }
    ]

def send_export_notification_email(user, export_request):
    """Send export notification email"""
    try:
        subject = _('Your Data Export is Ready')
        message = render_to_string('emails/export_notification.html', {
            'user': user,
            'request_id': export_request.id,
            'export_date': timezone.now(),
            'categories': export_request.data_categories,
            'format': export_request.file_format,
            'download_url': reverse('gdpr_platform:download_export', args=[export_request.id])
        })
        
        send_mail(
            subject=subject,
            message=strip_tags(message),
            from_email=django_settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            html_message=message
        )
    except Exception as e:
        logger.error(f"Failed to send export notification email to {user.email}: {str(e)}")

@login_required
@role_required('admin', 'compliance_officer', 'dpo', 'user')
def rectify_user_data(request):
    """Handle user data rectification requests"""
    try:
        if request.method == 'POST':
                corrections = json.loads(request.POST.get('corrections', '{}'))
                
                with transaction.atomic():
                    # Create rectification request
                    rectification_request = DataRequest.objects.create(
                        user=request.user,
                        request_type='rectification',
                        status='processing',
                        details={'corrections': corrections}
                    )
                    
                    # Apply corrections
                    user = request.user
                    for field, value in corrections.items():
                        if hasattr(user, field):
                            setattr(user, field, value)
        user.save()
        
                # Log the rectification
        AuditLog.objects.create(
            user=user,
                    action='data_rectified',
                    resource_type='user_data',
            resource_id=str(user.id),
                    ip_address=get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
                    details={'fields_updated': list(corrections.keys())}
                )
                
        rectification_request.status = 'completed'
        rectification_request.save()
                
        messages.success(request, _('Your data has been updated successfully.'))
        return JsonResponse({'status': 'success'})
                
    except Exception as e:
        logger.error(f"Data rectification error for user {request.user.id}: {str(e)}")
        return JsonResponse({
            'status': 'error',
            'message': _('An error occurred updating your data.')
        }, status=500)
            
    return JsonResponse({'status': 'error', 'message': 'Invalid request method'}, status=405)

@login_required
@role_required('admin', 'compliance_officer', 'dpo', 'user')
def activity_log(request):
    """
    View for displaying activity logs with filtering and pagination.
    """
    # Get filter parameters
    start_date = request.GET.get('start_date')
    end_date = request.GET.get('end_date')
    action_type = request.GET.get('action_type')
    user_id = request.GET.get('user_id')
    
    # Base queryset
    logs = ActivityLog.objects.all().order_by('-timestamp')
    
    # Apply filters
    if start_date:
        logs = logs.filter(timestamp__gte=start_date)
    if end_date:
        logs = logs.filter(timestamp__lte=end_date)
    if action_type:
        logs = logs.filter(action_type=action_type)
    if user_id:
        logs = logs.filter(user_id=user_id)
        
    # Pagination
    paginator = Paginator(logs, 10)
    page = request.GET.get('page')
    try:
        activity_logs = paginator.page(page)
    except PageNotAnInteger:
        activity_logs = paginator.page(1)
    except EmptyPage:
        activity_logs = paginator.page(paginator.num_pages)
    
    # Process logs for display
    for log in activity_logs:
        log.formatted_timestamp = log.timestamp.strftime('%Y-%m-%d %H:%M:%S')
    
    context = {
        'activity_logs': activity_logs,
        'start_date': start_date,
        'end_date': end_date,
        'action_type': action_type,
        'user_id': user_id,
    }
    
    return render(request, 'compliance_officer_templates/activity_log.html', context)

def export_activity_log(request):
    """
    View for exporting activity logs to CSV.
    """
    # Get filter parameters (same as activity_log view)
    start_date = request.GET.get('start_date')
    end_date = request.GET.get('end_date')
    action_type = request.GET.get('action_type')
    user_id = request.GET.get('user_id')
    
    # Base queryset
    logs = ActivityLog.objects.all().order_by('-timestamp')
    
    # Apply filters (same as activity_log view)
    if start_date:
        logs = logs.filter(timestamp__gte=start_date)
    if end_date:
        logs = logs.filter(timestamp__lte=end_date)
    if action_type:
        logs = logs.filter(action_type=action_type)
    if user_id:
        logs = logs.filter(user_id=user_id)
    
    # Create the HttpResponse object with CSV header
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="activity_log.csv"'

    # Create CSV writer
    writer = csv.writer(response)
    writer.writerow([
        'Timestamp',
        'User',
        'Action',
        'Resource Type',
        'Resource ID',
        'IP Address',
        'User Agent',
        'Status',
        'Details'
    ])

    # Write data
    for log in logs:
        writer.writerow([
            log.formatted_timestamp,
            log.user.email,
            log.get_action_display(),
            log.resource_type,
            log.resource_id,
            log.ip_address,
            log.user_agent,
            log.get_status_display(),
            json.dumps(log.details)
        ])

    return response

@login_required
@role_required('admin', 'compliance_officer', 'dpo', 'user')
def security_dashboard(request):
    """Display security dashboard with enhanced monitoring"""
    try:
        # Get user's security status
        try:
            two_factor_enabled = hasattr(request.user, 'totp_device')
            logger.debug(f"Two-factor status for user {request.user.id}: {two_factor_enabled}")
        except Exception as e:
            logger.error(f"Error checking 2FA status: {str(e)}")
            two_factor_enabled = False

        try:
            active_sessions = UserSession.objects.filter(
                user=request.user,
                is_active=True
            ).order_by('-login_time')
            logger.debug(f"Found {active_sessions.count()} active sessions for user {request.user.id}")
        except Exception as e:
            logger.error(f"Error retrieving active sessions: {str(e)}")
            active_sessions = UserSession.objects.none()
        
        try:
            security_logs = ActivityLog.objects.filter(
                user=request.user,
                action_type__in=['login', 'password', '2fa', 'security']
            ).order_by('-timestamp')[:10]
            logger.debug(f"Found {security_logs.count()} security logs for user {request.user.id}")
        except Exception as e:
            logger.error(f"Error retrieving security logs: {str(e)}")
            security_logs = ActivityLog.objects.none()
        
        try:
            trusted_devices = TrustedDevice.objects.filter(
                user=request.user,
                expires_at__gt=timezone.now()
            ).order_by('-last_used')
            logger.debug(f"Found {trusted_devices.count()} trusted devices for user {request.user.id}")
        except Exception as e:
            logger.error(f"Error retrieving trusted devices: {str(e)}")
            trusted_devices = TrustedDevice.objects.none()

        context = {
            'two_factor_enabled': two_factor_enabled,
            'active_sessions': active_sessions,
            'security_logs': security_logs,
            'trusted_devices': trusted_devices,
        }
        
        return render(request, 'user_templates/security_dashboard.html', context)
        
    except Exception as e:
        logger.error(f"Error in security dashboard: {str(e)}")
        messages.error(request, _('An error occurred while loading the security dashboard.'))
        return redirect('gdpr_platform:dashboard')

@login_required
@role_required('admin', 'compliance_officer', 'dpo', 'user')
def data_processing(request):
    """Handle data processing activities and cross-border transfers."""
    
    # Get processing activities
    activities = DataProcessingActivity.objects.filter(is_active=True).order_by('-created_at')
    processing_activities = [{
        'activity_type': activity.title,
        'description': activity.description,
        'timestamp': activity.created_at
    } for activity in activities]

    # Get transfers
    transfers_qs = DataTransfer.objects.filter(status='active').order_by('-created_at')
    transfers = [{
        'recipient_organization': transfer.destination_system,
        'recipient_country': transfer.destination_system,
        'data_categories': transfer.data_categories,
        'transfer_date': transfer.created_at
    } for transfer in transfers_qs]

    # Get retention settings
    retention_settings = {
        'personal_data': {'retention_period': 24, 'unit': 'months'},
        'sensitive_data': {'retention_period': 12, 'unit': 'months'},
        'financial_data': {'retention_period': 84, 'unit': 'months'},
        'communication_data': {'retention_period': 36, 'unit': 'months'}
    }
        
    context = {
        'title': _('Data Processing Activities'),
        'processing_activities': processing_activities,
        'transfers': transfers,
        'retention_settings': retention_settings
        }
        
    return render(request, 'dpo_templates/data_processing.html', context)

@login_required
@role_required('admin', 'compliance_officer', 'user')
def privacy_policy(request):
    """Display and manage privacy policy"""
    try:
        # Get the latest active policy
        try:
            current_policy = PrivacyPolicy.objects.filter(is_active=True).latest('effective_date')
        except PrivacyPolicy.DoesNotExist:
            # Create a default policy if none exists
            current_policy = PrivacyPolicy.objects.create(
                title=_('Privacy Policy'),
                content=render_to_string('gdpr/default_privacy_policy.html'),
                version='1.0',
                is_active=True,
                effective_date=timezone.now()
            )
        
        # Get user's consent status
        user_consent = UserPrivacyPolicyConsent.objects.filter(
            user=request.user,
            policy=current_policy
        ).first()
        
        context = {
            'title': _('Privacy Policy'),
            'policy': current_policy,
            'has_consented': bool(user_consent),
            'consent_date': user_consent.consented_at if user_consent else None,
            'show_consent_banner': not bool(user_consent)
        }
        
        return render(request, 'gdpr/privacy_policy.html', context)
            
    except Exception as e:
        logger.error(f"Privacy policy view error: {str(e)}")
        messages.error(request, _('An error occurred while loading the privacy policy.'))
        return redirect('gdpr_platform:dashboard')

@login_required
@role_required('admin', 'compliance_officer', 'user')
def update_privacy_policy_consent(request):
    """Handle privacy policy consent updates"""
    if request.method == 'POST':
        try:
            current_policy = PrivacyPolicy.objects.filter(is_active=True).first()
            if not current_policy:
                return JsonResponse({
                    'status': 'error',
                    'message': _('No active privacy policy found.')
                }, status=400)
            
            # Create or update consent
            consent, created = UserPrivacyPolicyConsent.objects.get_or_create(
                user=request.user,
                policy=current_policy,
                defaults={
                    'ip_address': get_client_ip(request),
                    'user_agent': request.META.get('HTTP_USER_AGENT', '')
                }
            )
            
            if not created:
                consent.ip_address = get_client_ip(request)
                consent.user_agent = request.META.get('HTTP_USER_AGENT', '')
                consent.consented_at = timezone.now()
                consent.save()
            
            # Log the consent
            AuditLog.objects.create(
                user=request.user,
                action='privacy_policy_consent_updated',
                resource_type='privacy_policy',
                resource_id=str(current_policy.id),
                ip_address=get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', '')
            )
            
            messages.success(request, _('Your privacy policy consent has been updated.'))
            return JsonResponse({'status': 'success'})
            
        except Exception as e:
            logger.error(f"Privacy policy consent update error for user {request.user.id}: {str(e)}")
            return JsonResponse({
                'status': 'error',
                'message': _('An error occurred updating your consent.')
            }, status=500)
            
    return JsonResponse({'status': 'error', 'message': 'Invalid request method'}, status=405)

@login_required
def setup_2fa(request):
    """Handle 2FA setup"""
    if request.method == 'POST':
        form = TwoFactorSetupForm(request.POST)
        if form.is_valid():
            try:
    # Get or create TOTP device
                device, created = TOTPDevice.objects.get_or_create(
                    user=request.user,
                    defaults={'confirmed': False}
                )
                
                if not device.confirmed:
                    # Verify the token
                    if device.verify_token(form.cleaned_data['verification_code']):
                        device.confirmed = True
                        device.save()
            
                        # Update user's 2FA status
                        request.user.two_factor_enabled = True
                        request.user.save()
                        
                        # Log the setup
                        AuditLog.objects.create(
                                        user=request.user,
                            action='2fa_enabled',
                            resource_type='security',
                                        resource_id=str(request.user.id),
                                        ip_address=get_client_ip(request),
                                        user_agent=request.META.get('HTTP_USER_AGENT', '')
                                    )
                                    
                        messages.success(request, _('Two-factor authentication has been enabled.'))
                        return redirect('gdpr_platform:security_settings')
                    else:
                        messages.error(request, _('Invalid verification code.'))
                else:
                    messages.error(request, _('Two-factor authentication is already set up.'))
            except Exception as e:
                logger.error(f"2FA setup error for user {request.user.id}: {str(e)}")
                messages.error(request, _('An error occurred during 2FA setup.'))
        else:
            form = TwoFactorSetupForm()
            
            # Generate new secret key if needed
            device, created = TOTPDevice.objects.get_or_create(
                user=request.user,
                defaults={'confirmed': False}
            )
            
            if created or not device.confirmed:
        # Generate QR code
                qr = qrcode.QRCode(
                    version=1,
                    error_correction=qrcode.constants.ERROR_CORRECT_L,
                    box_size=10,
                    border=4,
                )
        provisioning_uri = device.config_url
        qr.add_data(provisioning_uri)
        qr.make(fit=True)
        
                # Create SVG QR code
        img = qr.make_image(image_factory=qrcode.image.svg.SvgImage)
        stream = BytesIO()
        img.save(stream)
        qr_code = stream.getvalue().decode()
                
        context = {
            'form': form,
            'qr_code': qr_code,
            'secret_key': device.key,
            'title': 'Setup Two-Factor Authentication'
            }
                
        return render(request, 'security/setup_2fa.html', context)
        
    return redirect('gdpr_platform:security_settings')

@login_required
def disable_2fa(request):
    """Handle 2FA disablement"""
    if request.method == 'POST':
        try:
            # Remove TOTP devices
            TOTPDevice.objects.filter(user=request.user).delete()
            
            
            # Update user's 2FA status
            request.user.two_factor_enabled = False
            request.user.save()
            
            # Log the disablement
            AuditLog.objects.create(
                user=request.user,
                action='2fa_disabled',
                resource_type='security',
                resource_id=str(request.user.id),
                ip_address=get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', '')
            )
            
            # Invalidate all sessions for security
            Session.objects.filter(expire_date__gte=timezone.now()).delete()
            
            messages.success(request, _('Two-factor authentication has been disabled.'))
            return redirect('gdpr_platform:login')
            
        except Exception as e:
            logger.error(f"2FA disable error for user {request.user.id}: {str(e)}")
            messages.error(request, _('An error occurred disabling 2FA.'))
            
    return redirect('gdpr_platform:security_settings')

@login_required
def trusted_devices(request):
    """Handle trusted devices management"""
    try:
        logger.info(f"Loading trusted devices for user {request.user.id}")
        
        # Get user's active sessions
        try:
            active_sessions = UserSession.objects.filter(
                user=request.user,
                logout_time__isnull=True,
                is_active=True
        ).order_by('-login_time')
            logger.debug(f"Found {active_sessions.count()} active sessions for user {request.user.id}")
        except Exception as e:
            logger.error(f"Error retrieving active sessions for user {request.user.id}: {str(e)}")
            active_sessions = UserSession.objects.none()
        
        # Get trusted devices
        try:
            trusted_devices = TrustedDevice.objects.filter(
            user=request.user,
                expires_at__gt=timezone.now()
            ).order_by('-last_used')
            logger.debug(f"Found {trusted_devices.count()} trusted devices for user {request.user.id}")
        except Exception as e:
            logger.error(f"Error retrieving trusted devices for user {request.user.id}: {str(e)}")
            trusted_devices = TrustedDevice.objects.none()
        
        # Get current device info
        current_device = None
        try:
            if request.session.session_key:
                current_session = UserSession.objects.filter(
                    user=request.user,
                    session_key=request.session.session_key,
            is_active=True
                ).first()
                if current_session:
                    current_device = {
                        'user_agent': current_session.user_agent,
                        'ip_address': current_session.ip_address,
                        'last_used': current_session.last_activity
                    }
                    logger.debug(f"Found current device info for user {request.user.id}")
        except Exception as e:
            logger.error(f"Error retrieving current device info for user {request.user.id}: {str(e)}")
        
        context = {
            'active_sessions': active_sessions,
            'trusted_devices': trusted_devices,
            'current_device': current_device,
            'current_session': request.session.session_key,
            'title': 'Trusted Devices'
        }
        
        logger.info(f"Successfully loaded trusted devices page for user {request.user.id}")
        return render(request, 'security/trusted_devices.html', context)
        
    except Exception as e:
        logger.error(f"Unexpected error in trusted devices view for user {request.user.id}: {str(e)}", exc_info=True)
        messages.error(request, _('An error occurred loading your devices.'))
        return redirect('gdpr_platform:dashboard')

# Define action types for audit log
ACTION_TYPES = [
    ('login', _('Login')),
    ('logout', _('Logout')),
    ('data_export', _('Data Export')),
    ('data_deletion', _('Data Deletion')),
    ('data_rectification', _('Data Rectification')),
    ('privacy_settings', _('Privacy Settings Update')),
    ('cookie_consent', _('Cookie Consent Update')),
    ('2fa_enabled', _('2FA Enabled')),
    ('2fa_disabled', _('2FA Disabled')),
    ('password_changed', _('Password Changed')),
    ('security_settings', _('Security Settings Update')),
]

@login_required
@role_required('admin', 'compliance_officer', 'dpo', 'user')
def cross_border_transfers(request):
    """Display and manage cross-border data transfers"""
    try:
        # Get filter parameters
        country = request.GET.get('country')
        mechanism = request.GET.get('mechanism')
        status = request.GET.get('status')
        date_range = request.GET.get('date_range', '30')  # Default to last 30 days

        # Base queryset
        transfers = CrossBorderTransfer.objects.all()

        # Apply filters
        if country:
            transfers = transfers.filter(recipient_country=country)
        if mechanism:
            transfers = transfers.filter(transfer_mechanism=mechanism)
        if status:
            transfers = transfers.filter(status=status)
        if date_range and date_range != 'all':
            days = int(date_range)
            start_date = timezone.now() - timezone.timedelta(days=days)
            transfers = transfers.filter(transfer_date__gte=start_date)

        # Order by most recent
        transfers = transfers.order_by('-transfer_date')

        # Calculate statistics
        active_transfers = transfers.filter(status='active').count()
        pending_transfers = transfers.filter(status='pending').count()
        recipient_countries = transfers.values('recipient_country').distinct().count()
        
        # Calculate risk score (example implementation)
        high_risk_transfers = transfers.filter(risk_level='high').count()
        total_transfers = transfers.count()
        risk_score = int((high_risk_transfers / total_transfers * 100) if total_transfers > 0 else 0)

        # Get unique countries and mechanisms for filters
        countries = transfers.values_list('recipient_country', flat=True).distinct()
        mechanisms = CrossBorderTransfer.TRANSFER_MECHANISM_CHOICES

        # Add status class for badges
        for transfer in transfers:
            transfer.status_class = {
                'active': 'success',
                'pending': 'warning',
                'completed': 'info',
                'suspended': 'danger',
                'expired': 'secondary'
            }.get(transfer.status, 'secondary')

        # Pagination
        paginator = Paginator(transfers, 10)
        page = request.GET.get('page', 1)
        try:
            transfers = paginator.page(page)
        except (PageNotAnInteger, EmptyPage):
            transfers = paginator.page(1)

        # Handle new transfer form
        if request.method == 'POST':
            form = CrossBorderTransferForm(request.POST)
            if form.is_valid():
                transfer = form.save(commit=False)
                transfer.user = request.user
                transfer.save()
                
                # Log the transfer
                AuditLog.objects.create(
                    user=request.user,
                    action='cross_border_transfer_created',
                    resource_type='transfer',
                    resource_id=str(transfer.id),
                    ip_address=get_client_ip(request),
                    user_agent=request.META.get('HTTP_USER_AGENT', ''),
                    details={
                        'recipient_country': transfer.recipient_country,
                        'recipient_organization': transfer.recipient_organization,
                        'transfer_date': str(transfer.transfer_date)
                    }
                )
                
                messages.success(request, _('Cross-border transfer record created successfully.'))
                return redirect('gdpr_platform:cross_border_transfers')
        else:
            form = CrossBorderTransferForm()
        
        context = {
            'transfers': transfers,
            'form': form,
            'title': 'Cross-Border Transfers',
            'active_transfers': active_transfers,
            'pending_transfers': pending_transfers,
            'recipient_countries': recipient_countries,
            'risk_score': risk_score,
            'countries': countries,
            'mechanisms': mechanisms,
            'selected_country': country,
            'selected_mechanism': mechanism,
            'selected_status': status,
            'selected_range': date_range
        }
        
        return render(request, 'dpo_templates/cross_border_transfers.html', context)
        
    except Exception as e:
        logger.error(f"Cross-border transfers view error for user {request.user.id}: {str(e)}")
        messages.error(request, _('An error occurred loading cross-border transfers.'))
        return redirect('gdpr_platform:dashboard')

@login_required
@role_required('admin', 'compliance_officer', 'dpo', 'user')
def data_export(request):
    """Handle user data export requests"""
    try:
        if request.method == 'POST':
            # Get selected format and categories
            export_format = request.POST.get('format', 'json')
            categories = request.POST.getlist('categories', [])  # Changed from data_categories to categories
            
            # Get user data
            user_data = get_user_data_categories(request.user)
            
            # Filter data based on selected categories if specific categories were selected
            if categories:
                filtered_data = {}
                for category in categories:
                    if category in user_data:
                        filtered_data[category] = user_data[category]
                user_data = filtered_data
            
            try:
                # Create the export based on the requested format
                if export_format == 'json':
                    export_data = create_json_export(user_data)
                    content_type = 'application/json'
                elif export_format == 'csv':
                    export_data = create_csv_export(user_data)
                    content_type = 'text/csv'
                elif export_format == 'xml':
                    export_data = create_xml_export(user_data)
                    content_type = 'application/xml'
                else:
                    raise ValueError(f"Unsupported export format: {export_format}")
        
                # Create export record
                export_request = DataRequest.objects.create(
                    user=request.user,
                    request_type='export',
                        status='completed',
                        file_format=export_format,
                        data_categories=categories,
                        description=f"Data export in {export_format.upper()} format"
                )
                
                # Send notification email
                send_export_notification_email(request.user, export_request)
            
                # Return the exported data
                response = HttpResponse(export_data, content_type=content_type)
                response['Content-Disposition'] = f'attachment; filename="user_data_{timezone.now().strftime("%Y%m%d_%H%M%S")}.{export_format}"'
                return response
            
            except Exception as e:
                logger.error(f"Data export error for user {request.user.id}: {str(e)}")
                messages.error(request, _("An error occurred while exporting your data. Please try again."))
                return redirect('gdpr_platform:data_export')
        
        # Get previous exports for GET request
        previous_exports = DataRequest.objects.filter(
            user=request.user,
            request_type='export'
        ).order_by('-request_date')[:5]
        
        return render(request, 'gdpr/data_export.html', {  # Changed from user_templates to gdpr
            'title': _("Export Your Data"),
            'previous_exports': previous_exports,
            'exportable_categories': get_exportable_data_categories()  # Changed from data_categories to exportable_categories
        })
        
    except Exception as e:
        logger.error(f"Data export error for user {request.user.id}: {str(e)}")
        messages.error(request, _("An error occurred while processing your request. Please try again."))
        return redirect('gdpr_platform:dashboard')

def get_current_cookie_preferences(user):
    """Get user's current cookie preferences"""
    consent = CookieConsent.objects.filter(user=user).order_by('-timestamp').first()
    if consent:
        return {
            'necessary': consent.necessary_cookies,
            'analytics': consent.analytics_cookies,
            'marketing': consent.marketing_cookies,
            'functional': consent.functional_cookies,
            'last_updated': str(consent.timestamp)
        }
    return None

def get_privacy_policy_consents(user):
    """Get user's privacy policy consent history"""
    return list(UserPrivacyPolicyConsent.objects.filter(user=user).values(
        'policy__version',
        'consent_date',
        'ip_address',
        'user_agent'
    ))

def get_security_preferences(user):
    """Get user's security preferences"""
    return {
        'two_factor_auth': user.two_factor_enabled,
        'trusted_devices_enabled': hasattr(user, 'trust_settings'),
        'session_timeout': getattr(user, 'session_timeout', django_settings.SESSION_COOKIE_AGE),
        'login_notification': getattr(user, 'login_notification_enabled', False)
    }

def create_json_export(data):
    """Create JSON export of user data"""
    return json.dumps(data, indent=2, default=str)

def create_csv_export(data):
    """Create CSV export of user data"""
    output = StringIO()
    writer = csv.writer(output)
            
    for category, category_data in data.items():
        writer.writerow([f"--- {category.upper()} ---"])
        if isinstance(category_data, dict):
            for key, value in category_data.items():
                if isinstance(value, (list, dict)):
                    writer.writerow([key])
                    if isinstance(value, list):
                        # Handle list of dictionaries
                        if value and isinstance(value[0], dict):
                            headers = value[0].keys()
                            writer.writerow(headers)
                            for item in value:
                                if isinstance(item, dict):
                                    writer.writerow([str(item.get(h, '')) for h in headers])
                                else:
                                    writer.writerow([str(item)])
                        else:
                            # Handle list of non-dictionary items
                            for item in value:
                                writer.writerow([str(item)])
                    else:
                        # Handle nested dictionary
                        for k, v in value.items():
                            writer.writerow([k, str(v)])
                else:
                    writer.writerow([key, str(value)])
        else:
            # Handle non-dictionary category data
            writer.writerow(['Value', str(category_data)])
        writer.writerow([])  # Empty row between categories
    
    return output.getvalue()

def create_xml_export(data):
    """Create XML export of user data"""
    root = ET.Element("user_data")
    
    def dict_to_xml(parent, dictionary):
        for key, value in dictionary.items():
            child = ET.SubElement(parent, key.replace(' ', '_'))
            if isinstance(value, dict):
                dict_to_xml(child, value)
            elif isinstance(value, list):
                for item in value:
                    item_elem = ET.SubElement(child, "item")
                    if isinstance(item, dict):
                        dict_to_xml(item_elem, item)
                    else:
                        item_elem.text = str(item)
            else:
                child.text = str(value)
    
    dict_to_xml(root, data)
    return ET.tostring(root, encoding='unicode', method='xml', pretty_print=True)

def get_exportable_data_categories():
    """Get available data categories for export"""
    return [
        {
            'id': 'personal_info',
            'name': _('Personal Information'),
            'description': _('Your basic account and profile information')
        },
        {
            'id': 'privacy_settings',
            'name': _('Privacy Settings'),
            'description': _('Your privacy preferences and consents')
        },
        {
            'id': 'activity_history',
            'name': _('Activity History'),
            'description': _('Your activity logs and data requests')
        },
        {
            'id': 'data_processing',
            'name': _('Data Processing'),
            'description': _('Information about how your data is processed')
        },
        {
            'id': 'security_settings',
            'name': _('Security Settings'),
            'description': _('Your security preferences and trusted devices')
        }
    ]

def send_export_notification_email(user, export_request):
    """Send export notification email"""
    try:
        subject = _('Your Data Export is Ready')
        message = render_to_string('emails/export_notification.html', {
            'user': user,
            'request_id': export_request.id,
            'export_date': timezone.now(),
            'categories': export_request.data_categories,
            'format': export_request.file_format,
            'download_url': reverse('gdpr_platform:download_export', args=[export_request.id])
        })
        
        send_mail(
            subject=subject,
            message=strip_tags(message),
            from_email=django_settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            html_message=message
        )
    except Exception as e:
        logger.error(f"Failed to send export notification email to {user.email}: {str(e)}")

@login_required
@role_required('admin', 'compliance_officer', 'dpo', 'user')
def rectify_user_data(request):
    """Handle user data rectification requests"""
    try:
        if request.method == 'POST':
                corrections = json.loads(request.POST.get('corrections', '{}'))
                
                with transaction.atomic():
                    # Create rectification request
                    rectification_request = DataRequest.objects.create(
                        user=request.user,
                        request_type='rectification',
                        status='processing',
                        details={'corrections': corrections}
                    )
                    
                    # Apply corrections
                    user = request.user
                    for field, value in corrections.items():
                        if hasattr(user, field):
                            setattr(user, field, value)
        user.save()
        
                # Log the rectification
        AuditLog.objects.create(
            user=user,
                    action='data_rectified',
                    resource_type='user_data',
            resource_id=str(user.id),
                    ip_address=get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
                    details={'fields_updated': list(corrections.keys())}
                )
                
        rectification_request.status = 'completed'
        rectification_request.save()
                
        messages.success(request, _('Your data has been updated successfully.'))
        return JsonResponse({'status': 'success'})
                
    except Exception as e:
        logger.error(f"Data rectification error for user {request.user.id}: {str(e)}")
        return JsonResponse({
            'status': 'error',
            'message': _('An error occurred updating your data.')
        }, status=500)
            
    return JsonResponse({'status': 'error', 'message': 'Invalid request method'}, status=405)

@login_required
@role_required('admin', 'compliance_officer', 'dpo', 'user')
def activity_log(request):
    """
    View for displaying activity logs with filtering and pagination.
    """
    # Get filter parameters
    start_date = request.GET.get('start_date')
    end_date = request.GET.get('end_date')
    action_type = request.GET.get('action_type')
    user_id = request.GET.get('user_id')
    
    # Base queryset
    logs = ActivityLog.objects.all().order_by('-timestamp')
    
    # Apply filters
    if start_date:
        logs = logs.filter(timestamp__gte=start_date)
    if end_date:
        logs = logs.filter(timestamp__lte=end_date)
    if action_type:
        logs = logs.filter(action_type=action_type)
    if user_id:
        logs = logs.filter(user_id=user_id)
        
    # Pagination
    paginator = Paginator(logs, 10)
    page = request.GET.get('page')
    try:
        activity_logs = paginator.page(page)
    except PageNotAnInteger:
        activity_logs = paginator.page(1)
    except EmptyPage:
        activity_logs = paginator.page(paginator.num_pages)
    
    # Process logs for display
    for log in activity_logs:
        log.formatted_timestamp = log.timestamp.strftime('%Y-%m-%d %H:%M:%S')
    
    context = {
        'activity_logs': activity_logs,
        'start_date': start_date,
        'end_date': end_date,
        'action_type': action_type,
        'user_id': user_id,
    }
    
    return render(request, 'compliance_officer_templates/activity_log.html', context)

def export_activity_log(request):
    """
    View for exporting activity logs to CSV.
    """
    # Get filter parameters (same as activity_log view)
    start_date = request.GET.get('start_date')
    end_date = request.GET.get('end_date')
    action_type = request.GET.get('action_type')
    user_id = request.GET.get('user_id')
    
    # Base queryset
    logs = ActivityLog.objects.all().order_by('-timestamp')
    
    # Apply filters (same as activity_log view)
    if start_date:
        logs = logs.filter(timestamp__gte=start_date)
    if end_date:
        logs = logs.filter(timestamp__lte=end_date)
    if action_type:
        logs = logs.filter(action_type=action_type)
    if user_id:
        logs = logs.filter(user_id=user_id)
    
    # Create the HttpResponse object with CSV header
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="activity_log.csv"'

    # Create CSV writer
    writer = csv.writer(response)
    writer.writerow([
        'Timestamp',
        'User',
        'Action',
        'Resource Type',
        'Resource ID',
        'IP Address',
        'User Agent',
        'Status',
        'Details'
    ])
            
            # Write data
    for log in logs:
        writer.writerow([
            log.formatted_timestamp,
            log.user.email,
            log.get_action_display(),
            log.resource_type,
            log.resource_id,
            log.ip_address,
            log.user_agent,
            log.get_status_display(),
            json.dumps(log.details)
        ])

    return response
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login, logout, get_user_model, authenticate
from django.contrib.auth.decorators import login_required, permission_required
from django.contrib.auth.views import LoginView
from django.contrib.auth.forms import SetPasswordForm, AuthenticationForm
from django.contrib import messages
from django.http import JsonResponse, HttpResponse, FileResponse
from django.urls import reverse_lazy
from django.utils import timezone
from django.views.decorators.http import require_POST
from django.core.paginator import Paginator, PageNotAnInteger, EmptyPage
from django.db.models import Q, Sum, Avg, F, DurationField, ExpressionWrapper
from django.views.generic import FormView
from django.contrib.auth.forms import PasswordResetForm
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.views.generic.base import TemplateView
from django.utils.translation import gettext_lazy as _
from django.utils.decorators import method_decorator
from django.core.exceptions import ValidationError
from django.contrib.sessions.models import Session
from django.conf import settings
from django.core.cache import cache
from django.db import transaction
import logging
import json
import csv
from io import StringIO, BytesIO
from datetime import datetime, timedelta
import os
import hashlib
import base64
import pyotp
import qrcode
import qrcode.image.svg
from functools import wraps
from .models import (
    Role, AuditLog, DataRequest, DataCategory,
    DataBreach, BreachTimeline, CrossBorderTransfer,
    CookieConsent, DataTransfer, ProcessingActivity,
    DataProcessingActivity, ProcessingRequirement,
    UserSession, PrivacyPolicy, UserPrivacyPolicyConsent,
    DataExport, TwoFactorAuth, TrustedDevice, TrustSettings,
    ActivityLog, DeletionTask, BreachNotification,
    ConsentRecord, Task, Report, ReportSchedule, SystemSettings
)
from .forms import (
    RegistrationForm, DataRequestForm, CookiePreferencesForm,
    CrossBorderTransferForm, TwoFactorSetupForm
)
from .monitoring import breach_monitor
from django_otp.plugins.otp_totp.models import TOTPDevice
from django_otp.util import random_hex
from .decorators import (
    role_required, permission_required, dpo_required,
    admin_required, compliance_officer_required, any_staff_role_required
)
from .services.compliance_checker import ComplianceCheckerService
import pytz
from celery import shared_task
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table
from reportlab.lib.styles import getSampleStyleSheet
from .utils import get_client_ip
from django.template import TemplateDoesNotExist
from django.conf import settings as django_settings
import xml.etree.ElementTree as ET
import io
from django.contrib.auth.models import Group
from django.contrib.auth.models import Permission

User = get_user_model()
logger = logging.getLogger(__name__)

def rate_limit(key_prefix, limit=5, period=300):
    """
    Rate limiting decorator
    :param key_prefix: Prefix for the cache key
    :param limit: Number of allowed requests
    :param period: Time period in seconds
    """
    def decorator(func):
        @wraps(func)
        def wrapper(request, *args, **kwargs):
            client_ip = request.META.get('REMOTE_ADDR', '')
            cache_key = f"{key_prefix}:{client_ip}"
            
            # Get current request count
            requests = cache.get(cache_key, 0)
            
            if requests >= limit:
                messages.error(request, _('Too many attempts. Please try again later.'))
                return redirect('gdpr_platform:login')
            
            # Increment request count
            cache.set(cache_key, requests + 1, period)
            
            return func(request, *args, **kwargs)
        return wrapper
    return decorator

class CustomPasswordResetView(FormView):
    template_name = 'registration/password_reset_form.html'
    form_class = PasswordResetForm
    success_url = reverse_lazy('gdpr_platform:custom_password_reset_done')
    email_template_name = 'emails/password_reset_email.html'
    subject_template_name = 'emails/password_reset_subject.txt'
    
    @method_decorator(rate_limit('password_reset', limit=3, period=3600))
    def post(self, request, *args, **kwargs):
        return super().post(request, *args, **kwargs)
    
    def form_valid(self, form):
        """Add AI security checks and rate limiting before processing the reset request"""
        email = form.cleaned_data['email']
        user_ip = self.request.META.get('REMOTE_ADDR', '')
        
        # Hash the IP for security logging
        hashed_ip = hashlib.sha256(user_ip.encode()).hexdigest()
        
        # Log the reset attempt for AI monitoring
        AuditLog.objects.create(
            user=None,
            action='password_reset_requested',
            resource_type='user',
            resource_id=email,
            ip_address=hashed_ip,  # Store hashed IP
            user_agent=self.request.META.get('HTTP_USER_AGENT', ''),
            details={
                'email': email,
                'timestamp': str(timezone.now()),
                'request_origin': hashed_ip
            }
        )
        
        # Process the password reset
        opts = {
            'use_https': self.request.is_secure(),
            'token_generator': default_token_generator,
            'email_template_name': self.email_template_name,
            'subject_template_name': self.subject_template_name,
            'request': self.request,
            'extra_email_context': {
                'user_ip': hashed_ip,
                'timestamp': timezone.now().strftime('%Y-%m-%d %H:%M:%S UTC'),
                'security_level': 'Enhanced',
                'ai_verified': True
            }
        }
        
        try:
            form.save(**opts)
        except Exception as e:
            logger.error(f"Password reset error for {email}: {str(e)}")
            # Don't reveal if the email exists
            pass
        
        return super().form_valid(form)

class PasswordResetConfirmView(FormView):
    template_name = 'registration/password_reset_confirm.html'
    form_class = SetPasswordForm
    success_url = reverse_lazy('gdpr_platform:custom_password_reset_complete')
    token_generator = default_token_generator

    def get_user(self, uidb64):
        try:
            uid = urlsafe_base64_decode(uidb64).decode()
            user = User.objects.get(pk=uid)
            if not user.is_active:
                return None
            return user
        except (TypeError, ValueError, OverflowError, User.DoesNotExist, ValidationError):
            return None

    def get_form(self, form_class=None):
        user = self.get_user(self.kwargs.get('uidb64'))
        token = self.kwargs.get('token')
        
        if user is not None and self.token_generator.check_token(user, token):
            return self.form_class(user, **self.get_form_kwargs())
        return None

    @method_decorator(rate_limit('password_reset_confirm', limit=3, period=3600))
    def post(self, request, *args, **kwargs):
        return super().post(request, *args, **kwargs)

    def form_valid(self, form):
        user = form.user
        new_password = form.cleaned_data['new_password1']
        
        try:
        # Set the new password
            form.save()
            
            # Invalidate all existing sessions for security
            Session.objects.filter(expire_date__gte=timezone.now()).delete()
        
        # Log the successful password reset
            AuditLog.objects.create(
                user=user,
                action='password_reset_completed',
                resource_type='user',
                resource_id=str(user.id),
                    ip_address=hashlib.sha256(self.request.META.get('REMOTE_ADDR', '').encode()).hexdigest(),
                user_agent=self.request.META.get('HTTP_USER_AGENT', ''),
                details={
                    'timestamp': str(timezone.now()),
                        'security_measures': ['password_changed', 'sessions_terminated', 'security_logs_updated']
                    }
                )
                
            messages.success(self.request, _('Your password has been successfully reset.'))
            return super().form_valid(form)
            
        except Exception as e:
            logger.error(f"Password reset confirmation error for user {user.id}: {str(e)}")
            messages.error(self.request, _('An error occurred. Please try again.'))
            return self.form_invalid(form)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        user = self.get_user(self.kwargs.get('uidb64'))
        token = self.kwargs.get('token')
        
        if user is not None and self.token_generator.check_token(user, token):
            context['validlink'] = True
        else:
            context['validlink'] = False
            
        return context

@login_required
@role_required('admin', 'compliance_officer', 'dpo', 'user')
def handle_data_deletion(request):
    """Handle user data deletion requests with comprehensive tracking and transparency"""
    if request.method == 'POST':
        try:
            with transaction.atomic():
                user = request.user
                
                # Get selected categories
                categories = request.POST.getlist('data_categories', [])
                if not categories:
                    messages.error(request, _('Please select at least one data category to delete.'))
                    return redirect('gdpr_platform:data_deletion')
                
                # Create data deletion request with detailed tracking
            deletion_request = DataRequest.objects.create(
                    user=user,
                request_type='deletion',
                status='pending',
                    data_categories=categories,
                    description=request.POST.get('deletion_reason', ''),
                    notes=f"IP: {request.META.get('REMOTE_ADDR', '')}, UA: {request.META.get('HTTP_USER_AGENT', '')}"
                )
                
                # Log the deletion request with comprehensive audit trail
            AuditLog.objects.create(
                    user=user,
                action='data_deletion_requested',
                    resource_type='user',
                    resource_id=str(user.id),
                    ip_address=request.META.get('REMOTE_ADDR', ''),
                    user_agent=request.META.get('HTTP_USER_AGENT', ''),
                    details={
                    'request_id': str(deletion_request.id),
                        'timestamp': str(timezone.now()),
                        'deletion_scope': categories,
                        'immediate_deletion': request.POST.get('immediate_deletion', False),
                        'retention_policy_applied': True,
                        'backup_deletion_scheduled': True
                    }
                )
                
                # Calculate deletion schedule based on retention policies
            retention_period = 30  # Default retention period
            try:
                if isinstance(user.data_retention_policy, dict):
                    personal_info = user.data_retention_policy.get('personal_info', {})
                    if isinstance(personal_info, dict):
                        retention_period = int(personal_info.get('retention_period', 30))
            except (AttributeError, TypeError, ValueError):
                pass  # Use default retention period
                
            deletion_date = timezone.now() + timedelta(days=retention_period)
            
                # Handle immediate deletion requests if allowed
            if request.POST.get('immediate_deletion') and user.has_permission('immediate_deletion'):
                deletion_date = timezone.now()
            
            # Update user status
            user.account_status = 'pending_deletion'
            user.deletion_scheduled_date = deletion_date
            user.save()
                
            # Schedule data deletion tasks
            schedule_data_deletion_tasks(user, deletion_date, deletion_request.id)
            
            # Revoke all sessions
            Session.objects.filter(expire_date__gte=timezone.now()).delete()
            
            # Send confirmation email
            send_deletion_confirmation_email(user, deletion_request, deletion_date)
                
            messages.success(request, _(
                'Your data deletion request has been received and will be processed. '
                'You will receive a confirmation email with further details.'
            ))
            return redirect('gdpr_platform:logout')
                    
        except Exception as e:
            logger.error(f"Data deletion error for user {request.user.id}: {str(e)}")
            messages.error(request, _('An error occurred processing your request. Please try again.'))
            return redirect('gdpr_platform:dashboard')
            
    # Get available data categories for deletion
    data_categories = get_exportable_data_categories()
    
    # Get retention policies with proper type checking
    retention_policies = {}
    try:
        if hasattr(django_settings, 'GDPR_RETENTION_PERIODS'):
            retention_periods = getattr(django_settings, 'GDPR_RETENTION_PERIODS', {})
            if isinstance(retention_periods, dict):
                retention_policies = {str(k): v for k, v in retention_periods.items()}
    except Exception as e:
        logger.error(f"Error getting retention policies: {str(e)}")
    
    return render(request, 'user_templates/data_deletion.html', {
        'title': _('Request Data Deletion'),
        'data_categories': data_categories,
        'retention_policies': retention_policies,
        'can_request_immediate': request.user.has_permission('immediate_deletion')
    })

def schedule_data_deletion_tasks(user, deletion_date, request_id):
    """Schedule comprehensive data deletion tasks"""
    tasks = [
        ('user_account', 'Delete user account and profile'),
        ('personal_data', 'Delete personal information'),
        ('activity_logs', 'Anonymize activity logs'),
        ('analytics_data', 'Delete analytics data'),
        ('backup_data', 'Remove from backups'),
        ('third_party', 'Notify third-party processors'),
        ('audit_trail', 'Create deletion audit trail')
    ]
    
    for task_type, description in tasks:
        DeletionTask.objects.create(
            user=user,
            request_id=request_id,
            task_type=task_type,
            description=description,
            scheduled_date=deletion_date,
            status='scheduled'
        )

def get_user_data_categories(user):
    """Get user data organized by categories"""
    return {
        'personal_info': {
            'username': user.username,
            'email': user.email,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'date_joined': str(user.date_joined),
            'last_login': str(user.last_login),
            'phone_number': user.phone_number,
            'address': user.address,
            'city': user.city,
            'country': user.country,
            'postal_code': user.postal_code,
            'language_preference': user.preferred_language
        },
        'privacy_settings': {
            'marketing_preferences': user.marketing_preferences,
            'privacy_settings': user.privacy_settings,
            'data_retention_policy': user.data_retention_policy,
            'cookie_preferences': get_current_cookie_preferences(user),
            'privacy_policy_consents': get_privacy_policy_consents(user)
        },
        'security_settings': {
            'two_factor_enabled': user.two_factor_enabled,
            'last_login_ip': user.last_login_ip,
            'account_status': user.account_status,
            'security_preferences': get_security_preferences(user)
        },
        'activity_history': {
            'login_history': list(UserSession.objects.filter(user=user).values(
                'login_time', 'last_activity', 'ip_address', 'user_agent', 'is_active'
            )),
            'data_requests': list(DataRequest.objects.filter(user=user).values(
                'request_type', 'status', 'request_date', 'completion_date', 'description'
            )),
            'consent_history': list(ConsentRecord.objects.filter(user=user).values(
                'consent_type', 'status', 'granted_at', 'withdrawn_at', 'purpose'
            ))
        }
    }

def send_deletion_confirmation_email(user, deletion_request, deletion_date):
    """Send detailed deletion confirmation email"""
    try:
        subject = _('Your Data Deletion Request Confirmation')
        message = render_to_string('emails/deletion_confirmation.html', {
            'user': user,
            'request_id': deletion_request.tracking_id,
            'deletion_date': deletion_date,
            'data_categories': deletion_request.data_categories,
            'retention_period': django_settings.GDPR_RETENTION_PERIODS['personal_info'],
            'contact_email': django_settings.SUPPORT_EMAIL
        })
        
        send_mail(
            subject=subject,
            message=strip_tags(message),
            from_email=django_settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            html_message=message
        )
    except Exception as e:
        logger.error(f"Failed to send deletion confirmation email to {user.email}: {str(e)}")

@login_required
@role_required('admin', 'compliance_officer', 'dpo', 'user')
def data_deletion(request):
    """Redirect to handle_data_deletion for backward compatibility"""
    return handle_data_deletion(request)

@login_required
@role_required('admin', 'compliance_officer', 'user')
def update_cookie_consent(request):
    """Handle cookie consent updates with full transparency and granular control"""
    if request.method == 'POST':
        try:
            form = CookiePreferencesForm(request.POST)
            if form.is_valid():
                    with transaction.atomic():
                    # Create new consent record with detailed tracking
                        new_consent = CookieConsent.objects.create(
                            user=request.user,
                            necessary_cookies=True,  # Always required
                            analytics_cookies=form.cleaned_data.get('analytics_cookies', False),
                            marketing_cookies=form.cleaned_data.get('marketing_cookies', False),
                            functional_cookies=form.cleaned_data.get('functional_cookies', False),
                            ip_address=request.META.get('REMOTE_ADDR', ''),
                        user_agent=request.META.get('HTTP_USER_AGENT', ''),
                        consent_version=django_settings.COOKIE_POLICY_VERSION,
                        consent_method='explicit',
                        consent_timestamp=timezone.now(),
                        consent_expiry=timezone.now() + timedelta(days=django_settings.COOKIE_CONSENT_EXPIRY),
                        consent_details={
                            'form_submitted': True,
                            'source': 'web_form',
                            'explicit_action': True,
                            'policy_version': django_settings.COOKIE_POLICY_VERSION,
                            'browser_info': request.META.get('HTTP_USER_AGENT', ''),
                            'screen_resolution': request.POST.get('screen_resolution', ''),
                            'consent_language': request.LANGUAGE_CODE,
                            'geo_location': get_location_from_ip(request.META.get('REMOTE_ADDR', '')),
                        }
                    )
                    
                    # Log consent update with detailed audit trail
                        AuditLog.objects.create(
                            user=request.user,
                            action='cookie_preferences_updated',
                            resource_type='cookie_consent',
                            resource_id=str(new_consent.id),
                            ip_address=request.META.get('REMOTE_ADDR', ''),
                            user_agent=request.META.get('HTTP_USER_AGENT', ''),
                            details={
                                'new_consent_id': str(new_consent.id),
                                'changes': {
                                    'analytics': new_consent.analytics_cookies,
                                    'marketing': new_consent.marketing_cookies,
                                    'functional': new_consent.functional_cookies
                            },
                            'previous_settings': get_previous_consent_settings(request.user),
                            'consent_version': django_settings.COOKIE_POLICY_VERSION,
                            'expiry_date': str(new_consent.consent_expiry),
                            'consent_method': 'explicit',
                            'user_notification': True
                        }
                    )
                    
                    # Send confirmation email
                    send_consent_confirmation_email(request.user, new_consent)
                    
                    messages.success(request, _('Your cookie preferences have been updated. You can modify these settings at any time.'))
                    return JsonResponse({
                        'status': 'success',
                        'message': _('Cookie preferences updated successfully'),
                        'details': {
                            'consent_id': str(new_consent.id),
                            'expiry_date': str(new_consent.consent_expiry),
                            'settings': {
                                'necessary': True,
                                'analytics': new_consent.analytics_cookies,
                                'marketing': new_consent.marketing_cookies,
                                'functional': new_consent.functional_cookies
                            }
                        }
                    })
            else:
                return JsonResponse({
                    'status': 'error',
                    'errors': form.errors,
                    'message': _('Please review your consent selections')
                }, status=400)
                
        except Exception as e:
            logger.error(f"Cookie consent update error for user {request.user.id}: {str(e)}")
            return JsonResponse({
                'status': 'error',
                'message': _('An error occurred updating your preferences.')
            }, status=500)
    
    return JsonResponse({'status': 'error', 'message': _('Invalid request method.')}, status=405)

def get_previous_consent_settings(user):
    """Get user's previous consent settings for audit trail"""
    previous_consent = CookieConsent.objects.filter(
        user=user
    ).exclude(
        consent_version=django_settings.COOKIE_POLICY_VERSION
    ).order_by('-consent_timestamp').first()
    
    if previous_consent:
        return {
            'analytics': previous_consent.analytics_cookies,
            'marketing': previous_consent.marketing_cookies,
            'functional': previous_consent.functional_cookies,
            'version': previous_consent.consent_version,
            'timestamp': str(previous_consent.consent_timestamp)
        }
    return None

def send_consent_confirmation_email(user, consent):
    """Send confirmation email for consent updates"""
    try:
        subject = _('Your Privacy Settings Have Been Updated')
        message = render_to_string('emails/consent_confirmation.html', {
            'user': user,
            'consent': consent,
            'settings_url': reverse('gdpr_platform:privacy_settings'),
            'timestamp': timezone.now(),
        })
        
        send_mail(
            subject=subject,
            message=strip_tags(message),
            from_email=django_settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            html_message=message
        )
    except Exception as e:
        logger.error(f"Failed to send consent confirmation email to {user.email}: {str(e)}")

@login_required
@role_required('admin', 'compliance_officer', 'user')
def privacy_settings(request):
    """Handle privacy settings"""
    try:
        if request.method == 'POST':
            # Update privacy settings
            privacy_settings = request.user.privacy_settings if hasattr(request.user, 'privacy_settings') else {}
            privacy_settings.update({
                'marketing_emails': request.POST.get('marketing_emails') == 'on',
                'data_sharing': request.POST.get('data_sharing') == 'on',
                'analytics': request.POST.get('analytics') == 'on',
                'last_updated': str(timezone.now())
            })
            request.user.privacy_settings = privacy_settings
            request.user.save()
            
            # Log the update
            AuditLog.objects.create(
                user=request.user,
                action='privacy_settings_updated',
                resource_type='privacy_settings',
                resource_id=str(request.user.id)
            )
            
            messages.success(request, _('Your privacy settings have been updated.'))
            return redirect('gdpr_platform:privacy_settings')
        
        return render(request, 'user_templates/privacy_settings.html', {
            'title': _('Privacy Settings'),
            'privacy_settings': request.user.privacy_settings if hasattr(request.user, 'privacy_settings') else {}
        })
    except Exception as e:
        logger.error(f"Privacy settings error for user {request.user.id}: {str(e)}")
        messages.error(request, _('An error occurred while updating your privacy settings.'))
        return redirect('gdpr_platform:dashboard')

def landing(request):
    """Landing page view"""
    if request.user.is_authenticated:
        return redirect('gdpr_platform:dashboard')
    return render(request, 'landing.html', {
        'title': 'Welcome to GDPR Platform'
    })

def custom_login(request):
    """Custom login view with security features"""
    try:
        next_url = request.GET.get('next', '')
        is_admin = next_url and next_url.startswith('/admin/')
        
        if request.user.is_authenticated:
                # Assign default role if needed
            assign_default_role(request.user)
                    
            if request.user.is_staff:
                    return redirect('gdpr_platform:admin_dashboard')
            return redirect('gdpr_platform:dashboard')
            
        if request.method == 'POST':
            username = request.POST.get('username')
            password = request.POST.get('password')
            user = authenticate(request, username=username, password=password)
            
            if user is not None:
                if user.is_active:
                    # Check if 2FA is required
                    if user.two_factor_enabled:
                        request.session['2fa_user_id'] = user.id
                        request.session['2fa_redirect_url'] = next_url
                        return redirect('gdpr_platform:two_factor_verify')
                    
                    # Log the successful login
                    login(request, user)
                    logger.info(f"Successful login for user: {username}")
                            
                            # Assign default role if needed
                    assign_default_role(user)
                    
                    # Update last login and create session record
                    user.last_login = timezone.now()
                    user.save(update_fields=['last_login'])
                    
                    # Create session record
                    if not request.session.session_key:
                        request.session.save()
                    
                    UserSession.objects.create(
                        user=user,
                        session_key=request.session.session_key,
                        ip_address=get_client_ip(request),
                        user_agent=request.META.get('HTTP_USER_AGENT', '')
                    )
                    
                    # Handle redirection
                    if user.is_staff:
                        return redirect('gdpr_platform:admin_dashboard')
                    return redirect('gdpr_platform:dashboard')
                else:
                    messages.error(request, _('Your account is inactive. Please contact support.'))
            else:
                # Log failed login attempt
                logger.warning(f"Failed login attempt for username: {username}")
                breach_monitor.log_failed_login(username, get_client_ip(request))
                messages.error(request, _('Invalid username or password.'))
        
        return render(request, 'registration/login.html', {
            'title': 'Admin Login' if is_admin else 'Login',
            'form': AuthenticationForm(),
            'show_register': not is_admin,
            'show_password_reset': True,
            'is_admin': is_admin,
            'next': next_url
        })
    except Exception as e:
        logger.error(f"Error in custom_login: {str(e)}")
        messages.error(request, _('An error occurred while logging in. Please try again later.'))
        return redirect('gdpr_platform:landing')

def get_location_from_ip(ip):
    """Get location information from IP address"""
    # This is a placeholder. In production, you would use a geolocation service
    return {
        'country': 'Unknown',
        'city': 'Unknown',
        'region': 'Unknown'
    }

@login_required
def custom_logout(request):
    """Custom logout view that handles cleanup and logging"""
    try:
        # Log the logout action
        AuditLog.objects.create(
            user=request.user,
            action='LOGOUT',
            status='SUCCESS',
            ip_address=get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', '')
        )
        
        # Perform logout
        logout(request)
        return redirect('gdpr_platform:landing')
    except Exception as e:
        logger.error(f"Error during logout for {request.user.id}: {str(e)}")
        logout(request)
        return redirect('gdpr_platform:landing')

def register(request):
    """Handle user registration with GDPR compliance"""
    if request.user.is_authenticated:
        return redirect('gdpr_platform:user_dashboard')

    if request.method == 'POST':
        form = RegistrationForm(request.POST, request.FILES)
        if form.is_valid():
            try:
                with transaction.atomic():
                    user = form.save()
                    
                    # Assign default user role
                    regular_user_role = Role.objects.get(name='user')
                    user.roles.add(regular_user_role)
                    
                    AuditLog.objects.create(
                        user=user,
                        action='user_registration',
                        resource_type='user',
                        resource_id=str(user.id),
                        ip_address=get_client_ip(request),
                        user_agent=request.META.get('HTTP_USER_AGENT', ''),
                        details={
                            'timestamp': str(timezone.now()),
                            'consents': {
                                'privacy_policy': form.cleaned_data.get('privacy_policy_consent'),
                                'data_processing': form.cleaned_data.get('data_processing_consent'),
                                'marketing': form.cleaned_data.get('marketing_consent', False)
                            }
                        }
                    )
                    
                    CookieConsent.objects.create(
                        user=user,
                        necessary_cookies=True,
                        analytics_cookies=False,
                        marketing_cookies=form.cleaned_data.get('marketing_consent', False),
                        functional_cookies=True,
                        ip_address=get_client_ip(request),
                        user_agent=request.META.get('HTTP_USER_AGENT', '')
                    )
                    
                    current_policy = PrivacyPolicy.objects.filter(is_active=True).first()
                    if current_policy:
                        UserPrivacyPolicyConsent.objects.create(
                            user=user,
                            policy=current_policy,
                            ip_address=get_client_ip(request),
                            user_agent=request.META.get('HTTP_USER_AGENT', '')
                        )
                    
                    login(request, user)
                    
                    # Ensure session is created and saved
                    if not request.session.session_key:
                        request.session.save()
                    
                    UserSession.objects.create(
                        user=user,
                        session_key=request.session.session_key,
                        ip_address=get_client_ip(request),
                        user_agent=request.META.get('HTTP_USER_AGENT', '')
                    )
                    
                    try:
                        # Get DPO email from settings or use default
                        dpo_email = getattr(django_settings, 'DPO_EMAIL', 'dpo@gdprplatform.com')
                        
                        # Prepare email context
                        email_context = {
                            'user': user,
                            'site_name': getattr(django_settings, 'SITE_NAME', 'GDPR Platform'),
                            'dpo_email': dpo_email,
                            'request': request,
                        }
                        
                        # Get email settings with defaults
                        from_email = getattr(django_settings, 'DEFAULT_FROM_EMAIL', 'noreply@gdprplatform.com')
                        
                        send_mail(
                            subject=_('Welcome to GDPR Platform'),
                            message=render_to_string('emails/welcome_email.txt', email_context),
                            from_email=from_email,
                            recipient_list=[user.email],
                            html_message=render_to_string('emails/welcome_email.html', email_context)
                        )
                    except Exception as e:
                        logger.error(f"Failed to send welcome email to {user.email}: {str(e)}")
                    
                    messages.success(request, _('Registration successful. Welcome!'))
                    
                    # Redirect directly to user dashboard for new users
                    return redirect('gdpr_platform:user_dashboard')
                    
            except Exception as e:
                logger.error(f"Registration error: {str(e)}")
                messages.error(request, _('An error occurred during registration. Please try again.'))
        else:
            # Log form validation errors
            logger.error(f"Registration form validation errors: {form.errors}")
            for field, errors in form.errors.items():
                for error in errors:
                    messages.error(request, f"{field}: {error}")
    else:
        form = RegistrationForm()
    
    return render(request, 'registration/register.html', {
        'form': form,
        'title': _('Register'),
        'privacy_policy': PrivacyPolicy.objects.filter(is_active=True).first()
    })

@login_required
@role_required('admin', 'compliance_officer', 'dpo', 'user')
def data_rights_dashboard(request):
    """Display user's data rights and GDPR information"""
    try:
        # Get user's data requests, ordered by request date
        user_requests = DataRequest.objects.filter(user=request.user).order_by('-request_date')
        
        # Get latest cookie consent
        cookie_consent = CookieConsent.objects.filter(user=request.user).order_by('-timestamp').first()
        
        # Prepare context with user data
        context = {
            'title': _('Data Rights Dashboard'),
            'user': request.user,  # Use user instead of user_profile
            'user_requests': user_requests,
            'cookie_consent': cookie_consent,
            'two_factor_enabled': request.user.two_factor_enabled,
            'recent_activity': ActivityLog.objects.filter(user=request.user).order_by('-timestamp')[:5],
            'active_sessions': UserSession.objects.filter(user=request.user, is_active=True).order_by('-last_activity'),
            'breach_notifications': BreachNotification.objects.filter(
                recipient=request.user,
                status__in=['pending', 'sent']
            ).order_by('-created_at'),
            'data_processing': DataProcessingActivity.objects.filter(
                processor=request.user,
                is_active=True
            ).order_by('-created_at'),
            'retention_settings': request.user.data_retention_policy,
            'open_tickets': SupportTicket.objects.filter(
                user=request.user,
                status__in=['open', 'in_progress']
            ).order_by('-created_at'),
            'user_rights': {
                'access': True,
                'rectification': True,
                'erasure': True,
                'portability': True,
                'object': True,
                'restrict_processing': True
            }
        }
        
        # Choose template based on user role
        if request.user.has_role('admin'):
            template = 'admin_templates/admin_dashboard.html'
            context.update({
                'total_users': CustomUser.objects.count(),
                'pending_requests': DataRequest.objects.filter(status='pending').count(),
                'compliance_score': calculate_compliance_score(),
                'recent_breaches': DataBreach.objects.filter(
                    resolved=False
                ).order_by('-date_discovered')[:5],
            })
        else:
            template = 'user_templates/dashboard.html'
        
        return render(request, template, context)
        
    except Exception as e:
        logger.error(f"Dashboard error for user {request.user.id}: {str(e)}")
        messages.error(request, _('An error occurred loading the dashboard.'))
        return render(request, 'user_templates/dashboard.html', {
            'error': True,
            'title': 'Dashboard',
            'user': request.user  # Include user in error context
    })

@login_required
def extend_session(request):
    """Extend user session if active"""
    if request.method == 'POST':
        try:
            request.session.modified = True
            return JsonResponse({'status': 'success'})
        except Exception as e:
            logger.error(f"Session extension error for user {request.user.id}: {str(e)}")
            return JsonResponse({'status': 'error'}, status=500)
    return JsonResponse({'status': 'error', 'message': 'Invalid request method'}, status=405)

@login_required
@role_required('admin', 'compliance_officer', 'dpo', 'user')
def export_user_data(request):
    """Handle user data export requests"""
    try:
        if request.method == 'POST':
            # Get selected format and categories
            export_format = request.POST.get('format', 'json')
            categories = request.POST.getlist('categories', [])  # Changed from data_categories to categories
            
            # Get user data
            user_data = get_user_data_categories(request.user)
            
            # Filter data based on selected categories if specific categories were selected
            if categories:
                filtered_data = {}
                for category in categories:
                    if category in user_data:
                        filtered_data[category] = user_data[category]
                user_data = filtered_data
            
            try:
                # Create the export based on the requested format
                if export_format == 'json':
                            export_data = create_json_export(user_data)
                            content_type = 'application/json'
                elif export_format == 'csv':
                            export_data = create_csv_export(user_data)
                            content_type = 'text/csv'
                elif export_format == 'xml':
                            export_data = create_xml_export(user_data)
                            content_type = 'application/xml'
                else:
                    raise ValueError(f"Unsupported export format: {export_format}")
        
                # Create export record
                export_request = DataRequest.objects.create(
                    user=request.user,
                                request_type='export',
                                status='completed',
                                file_format=export_format,
                                data_categories=categories,
                                description=f"Data export in {export_format.upper()} format"
                )
                
                # Send notification email
                send_export_notification_email(request.user, export_request)
            
                        # Return the exported data
                response = HttpResponse(export_data, content_type=content_type)
                response['Content-Disposition'] = f'attachment; filename="user_data_{timezone.now().strftime("%Y%m%d_%H%M%S")}.{export_format}"'
                return response
            
            except Exception as e:
                logger.error(f"Data export error for user {request.user.id}: {str(e)}")
                messages.error(request, _("An error occurred while exporting your data. Please try again."))
                return redirect('gdpr_platform:data_export')
        
        # Get previous exports for GET request
        previous_exports = DataRequest.objects.filter(
                user=request.user,
                request_type='export'
            ).order_by('-request_date')[:5]
        
        return render(request, 'gdpr/data_export.html', {  # Changed from user_templates to gdpr
            'title': _("Export Your Data"),
            'previous_exports': previous_exports,
            'exportable_categories': get_exportable_data_categories()  # Changed from data_categories to exportable_categories
        })
        
    except Exception as e:
        logger.error(f"Data export error for user {request.user.id}: {str(e)}")
        messages.error(request, _("An error occurred while processing your request. Please try again."))
        return redirect('gdpr_platform:dashboard')

def get_current_cookie_preferences(user):
    """Get user's current cookie preferences"""
    consent = CookieConsent.objects.filter(user=user).order_by('-timestamp').first()
    if consent:
        return {
            'necessary': consent.necessary_cookies,
            'analytics': consent.analytics_cookies,
            'marketing': consent.marketing_cookies,
            'functional': consent.functional_cookies,
            'last_updated': str(consent.timestamp)
        }
    return None

def get_privacy_policy_consents(user):
    """Get user's privacy policy consent history"""
    return list(UserPrivacyPolicyConsent.objects.filter(user=user).values(
        'policy__version',
        'consent_date',
        'ip_address',
        'user_agent'
    ))

def get_security_preferences(user):
    """Get user's security preferences"""
    return {
        'two_factor_auth': user.two_factor_enabled,
        'trusted_devices_enabled': hasattr(user, 'trust_settings'),
        'session_timeout': getattr(user, 'session_timeout', django_settings.SESSION_COOKIE_AGE),
        'login_notification': getattr(user, 'login_notification_enabled', False)
    }

def create_json_export(data):
    """Create JSON export of user data"""
    return json.dumps(data, indent=2, default=str)

def create_csv_export(data):
    """Create CSV export of user data"""
    output = StringIO()
    writer = csv.writer(output)
    
    for category, category_data in data.items():
        writer.writerow([f"--- {category.upper()} ---"])
        if isinstance(category_data, dict):
            for key, value in category_data.items():
                if isinstance(value, (list, dict)):
                    writer.writerow([key])
                    if isinstance(value, list):
                        # Handle list of dictionaries
                        if value and isinstance(value[0], dict):
                            headers = value[0].keys()
                            writer.writerow(headers)
                            for item in value:
                                if isinstance(item, dict):
                                    writer.writerow([str(item.get(h, '')) for h in headers])
                                else:
                                    writer.writerow([str(item)])
                        else:
                            # Handle list of non-dictionary items
                            for item in value:
                                writer.writerow([str(item)])
                    else:
                        # Handle nested dictionary
                        for k, v in value.items():
                            writer.writerow([k, str(v)])
                else:
                    writer.writerow([key, str(value)])
        else:
            # Handle non-dictionary category data
            writer.writerow(['Value', str(category_data)])
        writer.writerow([])  # Empty row between categories
    
    return output.getvalue()

def create_xml_export(data):
    """Create XML export of user data"""
    root = ET.Element("user_data")
    
    def dict_to_xml(parent, dictionary):
        for key, value in dictionary.items():
            child = ET.SubElement(parent, key.replace(' ', '_'))
            if isinstance(value, dict):
                dict_to_xml(child, value)
            elif isinstance(value, list):
                for item in value:
                    item_elem = ET.SubElement(child, "item")
                    if isinstance(item, dict):
                        dict_to_xml(item_elem, item)
                    else:
                        item_elem.text = str(item)
            else:
                child.text = str(value)
    
    dict_to_xml(root, data)
    return ET.tostring(root, encoding='unicode', method='xml', pretty_print=True)

def get_exportable_data_categories():
    """Get available data categories for export"""
    return [
        {
            'id': 'personal_info',
            'name': _('Personal Information'),
            'description': _('Your basic account and profile information')
        },
        {
            'id': 'privacy_settings',
            'name': _('Privacy Settings'),
            'description': _('Your privacy preferences and consents')
        },
        {
            'id': 'activity_history',
            'name': _('Activity History'),
            'description': _('Your activity logs and data requests')
        },
        {
            'id': 'data_processing',
            'name': _('Data Processing'),
            'description': _('Information about how your data is processed')
        },
        {
            'id': 'security_settings',
            'name': _('Security Settings'),
            'description': _('Your security preferences and trusted devices')
        }
    ]

def send_export_notification_email(user, export_request):
    """Send export notification email"""
    try:
        subject = _('Your Data Export is Ready')
        message = render_to_string('emails/export_notification.html', {
            'user': user,
            'request_id': export_request.id,
            'export_date': timezone.now(),
            'categories': export_request.data_categories,
            'format': export_request.file_format,
            'download_url': reverse('gdpr_platform:download_export', args=[export_request.id])
        })
        
        send_mail(
            subject=subject,
            message=strip_tags(message),
            from_email=django_settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            html_message=message
        )
    except Exception as e:
        logger.error(f"Failed to send export notification email to {user.email}: {str(e)}")

@login_required
@role_required('admin', 'compliance_officer', 'dpo', 'user')
def rectify_user_data(request):
    """Handle user data rectification requests"""
    try:
        if request.method == 'POST':
                corrections = json.loads(request.POST.get('corrections', '{}'))
                
                with transaction.atomic():
                    # Create rectification request
                    rectification_request = DataRequest.objects.create(
                        user=request.user,
                        request_type='rectification',
                        status='processing',
                        details={'corrections': corrections}
                    )
                    
                    # Apply corrections
                    user = request.user
                    for field, value in corrections.items():
                        if hasattr(user, field):
                            setattr(user, field, value)
        user.save()
        
                # Log the rectification
        AuditLog.objects.create(
            user=user,
                    action='data_rectified',
                    resource_type='user_data',
            resource_id=str(user.id),
                    ip_address=get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
                    details={'fields_updated': list(corrections.keys())}
                )
                
        rectification_request.status = 'completed'
        rectification_request.save()
                
        messages.success(request, _('Your data has been updated successfully.'))
        return JsonResponse({'status': 'success'})
                
    except Exception as e:
        logger.error(f"Data rectification error for user {request.user.id}: {str(e)}")
        return JsonResponse({
            'status': 'error',
            'message': _('An error occurred updating your data.')
        }, status=500)
            
    return JsonResponse({'status': 'error', 'message': 'Invalid request method'}, status=405)

@login_required
@role_required('admin', 'compliance_officer', 'dpo', 'user')
def activity_log(request):
    """
    View for displaying activity logs with filtering and pagination.
    """
    # Get filter parameters
    start_date = request.GET.get('start_date')
    end_date = request.GET.get('end_date')
    action_type = request.GET.get('action_type')
    user_id = request.GET.get('user_id')
    
    # Base queryset
    logs = ActivityLog.objects.all().order_by('-timestamp')
    
    # Apply filters
    if start_date:
        logs = logs.filter(timestamp__gte=start_date)
    if end_date:
        logs = logs.filter(timestamp__lte=end_date)
    if action_type:
        logs = logs.filter(action_type=action_type)
    if user_id:
        logs = logs.filter(user_id=user_id)
        
    # Pagination
    paginator = Paginator(logs, 10)
    page = request.GET.get('page')
    try:
        activity_logs = paginator.page(page)
    except PageNotAnInteger:
        activity_logs = paginator.page(1)
    except EmptyPage:
        activity_logs = paginator.page(paginator.num_pages)
    
    # Process logs for display
    for log in activity_logs:
        log.formatted_timestamp = log.timestamp.strftime('%Y-%m-%d %H:%M:%S')
    
    context = {
        'activity_logs': activity_logs,
        'start_date': start_date,
        'end_date': end_date,
        'action_type': action_type,
        'user_id': user_id,
    }
    
    return render(request, 'compliance_officer_templates/activity_log.html', context)

def export_activity_log(request):
    """
    View for exporting activity logs to CSV.
    """
    # Get filter parameters (same as activity_log view)
    start_date = request.GET.get('start_date')
    end_date = request.GET.get('end_date')
    action_type = request.GET.get('action_type')
    user_id = request.GET.get('user_id')
    
    # Base queryset
    logs = ActivityLog.objects.all().order_by('-timestamp')
    
    # Apply filters (same as activity_log view)
    if start_date:
        logs = logs.filter(timestamp__gte=start_date)
    if end_date:
        logs = logs.filter(timestamp__lte=end_date)
    if action_type:
        logs = logs.filter(action_type=action_type)
    if user_id:
        logs = logs.filter(user_id=user_id)
    
    # Create the HttpResponse object with CSV header
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="activity_log.csv"'

    # Create CSV writer
    writer = csv.writer(response)
    writer.writerow([
        'Timestamp',
        'User',
        'Action',
        'Resource Type',
        'Resource ID',
        'IP Address',
        'User Agent',
        'Status',
        'Details'
    ])

    # Write data
    for log in logs:
        writer.writerow([
            log.formatted_timestamp,
            log.user.email,
            log.get_action_display(),
            log.resource_type,
            log.resource_id,
            log.ip_address,
            log.user_agent,
            log.get_status_display(),
            json.dumps(log.details)
        ])

    return response

@login_required
@role_required('admin', 'compliance_officer', 'dpo', 'user')
def security_dashboard(request):
    """Display security dashboard with enhanced monitoring"""
    try:
        # Get user's security status
        try:
            two_factor_enabled = hasattr(request.user, 'totp_device')
            logger.debug(f"Two-factor status for user {request.user.id}: {two_factor_enabled}")
        except Exception as e:
            logger.error(f"Error checking 2FA status: {str(e)}")
            two_factor_enabled = False

        try:
            active_sessions = UserSession.objects.filter(
            user=request.user,
            is_active=True
        ).order_by('-login_time')
            logger.debug(f"Found {active_sessions.count()} active sessions for user {request.user.id}")
        except Exception as e:
            logger.error(f"Error retrieving active sessions: {str(e)}")
            active_sessions = UserSession.objects.none()
        
        try:
            security_logs = ActivityLog.objects.filter(
            user=request.user,
                action_type__in=['login', 'password', '2fa', 'security']
        ).order_by('-timestamp')[:10]
            logger.debug(f"Found {security_logs.count()} security logs for user {request.user.id}")
        except Exception as e:
            logger.error(f"Error retrieving security logs: {str(e)}")
            security_logs = ActivityLog.objects.none()
        
        try:
            trusted_devices = TrustedDevice.objects.filter(
            user=request.user,
                expires_at__gt=timezone.now()
        ).order_by('-last_used')
            logger.debug(f"Found {trusted_devices.count()} trusted devices for user {request.user.id}")
        except Exception as e:
            logger.error(f"Error retrieving trusted devices: {str(e)}")
            trusted_devices = TrustedDevice.objects.none()

        try:
            login_history = ActivityLog.objects.filter(
                user=request.user,
                action_type='login'
            ).order_by('-timestamp')[:10]
            logger.debug(f"Found {login_history.count()} login history entries for user {request.user.id}")
        except Exception as e:
            logger.error(f"Error retrieving login history: {str(e)}")
            login_history = ActivityLog.objects.none()

        # Calculate security score based on available factors
        security_score = 0
        try:
            if two_factor_enabled:
                security_score += 40
            if trusted_devices.exists():
                security_score += 20
            if request.user.last_password_change:
                days_since_password_change = (timezone.now() - request.user.last_password_change).days
                if days_since_password_change <= 90:
                    security_score += 20
            if active_sessions.count() <= 3:  # Not too many active sessions
                security_score += 20
            logger.debug(f"Calculated security score for user {request.user.id}: {security_score}")
        except Exception as e:
            logger.error(f"Error calculating security score: {str(e)}")
            security_score = 0
        
        context = {
            'title': _('Security Dashboard'),
            'two_factor_enabled': two_factor_enabled,
            'active_sessions': active_sessions,
            'security_logs': security_logs,
            'trusted_devices': trusted_devices,
            'trusted_devices_count': trusted_devices.count(),
            'security_score': security_score,
            'login_history': login_history,
            'user': request.user
        }
        
        return render(request, 'security/security_dashboard.html', context)
        
    except Exception as e:
        logger.error(f"Security dashboard error for user {request.user.id}: {str(e)}", exc_info=True)
        messages.error(request, _('An error occurred loading the security dashboard.'))
        return redirect('gdpr_platform:dashboard')

@login_required
@role_required('admin', 'compliance_officer', 'dpo', 'user')
def data_processing(request):
    """Handle data processing activities and cross-border transfers."""
    
    # Get processing activities
    activities = DataProcessingActivity.objects.filter(is_active=True).order_by('-created_at')
    processing_activities = [{
        'activity_type': activity.title,
        'description': activity.description,
        'timestamp': activity.created_at
    } for activity in activities]

    # Get transfers
    transfers_qs = DataTransfer.objects.filter(status='active').order_by('-created_at')
    transfers = [{
        'recipient_organization': transfer.destination_system,
        'recipient_country': transfer.destination_system,
        'data_categories': transfer.data_categories,
        'transfer_date': transfer.created_at
    } for transfer in transfers_qs]

    # Get retention settings
    retention_settings = {
        'personal_data': {'retention_period': 24, 'unit': 'months'},
        'sensitive_data': {'retention_period': 12, 'unit': 'months'},
        'financial_data': {'retention_period': 84, 'unit': 'months'},
        'communication_data': {'retention_period': 36, 'unit': 'months'}
    }
        
    context = {
        'title': _('Data Processing Activities'),
        'processing_activities': processing_activities,
        'transfers': transfers,
        'retention_settings': retention_settings
        }
        
    return render(request, 'dpo_templates/data_processing.html', context)

@login_required
@role_required('admin', 'compliance_officer', 'user')
def privacy_policy(request):
    """Display and manage privacy policy"""
    try:
        # Get the latest active policy
        try:
            current_policy = PrivacyPolicy.objects.filter(is_active=True).latest('effective_date')
        except PrivacyPolicy.DoesNotExist:
            # Create a default policy if none exists
            current_policy = PrivacyPolicy.objects.create(
                title=_('Privacy Policy'),
                content=render_to_string('gdpr/default_privacy_policy.html'),
                version='1.0',
                is_active=True,
                effective_date=timezone.now()
            )
        
        # Get user's consent status
        user_consent = UserPrivacyPolicyConsent.objects.filter(
            user=request.user,
            policy=current_policy
        ).first()
        
        context = {
            'title': _('Privacy Policy'),
            'policy': current_policy,
            'has_consented': bool(user_consent),
            'consent_date': user_consent.consented_at if user_consent else None,
            'show_consent_banner': not bool(user_consent)
        }
        
        return render(request, 'gdpr/privacy_policy.html', context)
            
    except Exception as e:
        logger.error(f"Privacy policy view error: {str(e)}")
        messages.error(request, _('An error occurred while loading the privacy policy.'))
        return redirect('gdpr_platform:dashboard')

@login_required
@role_required('admin', 'compliance_officer', 'user')
def update_privacy_policy_consent(request):
    """Handle privacy policy consent updates"""
    if request.method == 'POST':
        try:
            current_policy = PrivacyPolicy.objects.filter(is_active=True).first()
            if not current_policy:
                return JsonResponse({
                    'status': 'error',
                    'message': _('No active privacy policy found.')
                }, status=400)
            
            # Create or update consent
            consent, created = UserPrivacyPolicyConsent.objects.get_or_create(
                user=request.user,
                policy=current_policy,
                defaults={
                    'ip_address': get_client_ip(request),
                    'user_agent': request.META.get('HTTP_USER_AGENT', '')
                }
            )
            
            if not created:
                consent.ip_address = get_client_ip(request)
                consent.user_agent = request.META.get('HTTP_USER_AGENT', '')
                consent.consented_at = timezone.now()
                consent.save()
            
            # Log the consent
            AuditLog.objects.create(
                user=request.user,
                action='privacy_policy_consent_updated',
                resource_type='privacy_policy',
                resource_id=str(current_policy.id),
                ip_address=get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', '')
            )
            
            messages.success(request, _('Your privacy policy consent has been updated.'))
            return JsonResponse({'status': 'success'})
            
        except Exception as e:
            logger.error(f"Privacy policy consent update error for user {request.user.id}: {str(e)}")
            return JsonResponse({
                'status': 'error',
                'message': _('An error occurred updating your consent.')
            }, status=500)
            
    return JsonResponse({'status': 'error', 'message': 'Invalid request method'}, status=405)

@login_required
def setup_2fa(request):
    """Handle 2FA setup"""
    if request.method == 'POST':
        form = TwoFactorSetupForm(request.POST)
        if form.is_valid():
            try:
    # Get or create TOTP device
                device, created = TOTPDevice.objects.get_or_create(
                    user=request.user,
                    defaults={'confirmed': False}
                )
                
                if not device.confirmed:
                    # Verify the token
                    if device.verify_token(form.cleaned_data['verification_code']):
                        device.confirmed = True
                        device.save()
            
                        # Update user's 2FA status
                        request.user.two_factor_enabled = True
                        request.user.save()
                        
                        # Log the setup
                        AuditLog.objects.create(
                                        user=request.user,
                            action='2fa_enabled',
                            resource_type='security',
                                        resource_id=str(request.user.id),
                                        ip_address=get_client_ip(request),
                                        user_agent=request.META.get('HTTP_USER_AGENT', '')
                                    )
                                    
                        messages.success(request, _('Two-factor authentication has been enabled.'))
                        return redirect('gdpr_platform:security_settings')
                    else:
                        messages.error(request, _('Invalid verification code.'))
                else:
                    messages.error(request, _('Two-factor authentication is already set up.'))
            except Exception as e:
                logger.error(f"2FA setup error for user {request.user.id}: {str(e)}")
                messages.error(request, _('An error occurred during 2FA setup.'))
        else:
            form = TwoFactorSetupForm()
            
            # Generate new secret key if needed
            device, created = TOTPDevice.objects.get_or_create(
                user=request.user,
                defaults={'confirmed': False}
            )
            
            if created or not device.confirmed:
        # Generate QR code
                qr = qrcode.QRCode(
                    version=1,
                    error_correction=qrcode.constants.ERROR_CORRECT_L,
                    box_size=10,
                    border=4,
                )
        provisioning_uri = device.config_url
        qr.add_data(provisioning_uri)
        qr.make(fit=True)
        
                # Create SVG QR code
        img = qr.make_image(image_factory=qrcode.image.svg.SvgImage)
        stream = BytesIO()
        img.save(stream)
        qr_code = stream.getvalue().decode()
                
        context = {
            'form': form,
            'qr_code': qr_code,
            'secret_key': device.key,
            'title': 'Setup Two-Factor Authentication'
            }
                
        return render(request, 'security/setup_2fa.html', context)
        
    return redirect('gdpr_platform:security_settings')

@login_required
def disable_2fa(request):
    """Handle 2FA disablement"""
    if request.method == 'POST':
        try:
            # Remove TOTP devices
            TOTPDevice.objects.filter(user=request.user).delete()
            
            
            # Update user's 2FA status
            request.user.two_factor_enabled = False
            request.user.save()
            
            # Log the disablement
            AuditLog.objects.create(
                user=request.user,
                action='2fa_disabled',
                resource_type='security',
                resource_id=str(request.user.id),
                ip_address=get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', '')
            )
            
            # Invalidate all sessions for security
            Session.objects.filter(expire_date__gte=timezone.now()).delete()
            
            messages.success(request, _('Two-factor authentication has been disabled.'))
            return redirect('gdpr_platform:login')
            
        except Exception as e:
            logger.error(f"2FA disable error for user {request.user.id}: {str(e)}")
            messages.error(request, _('An error occurred disabling 2FA.'))
            
    return redirect('gdpr_platform:security_settings')

@login_required
def trusted_devices(request):
    """Handle trusted devices management"""
    try:
        logger.info(f"Loading trusted devices for user {request.user.id}")
        
        # Get user's active sessions
        try:
            active_sessions = UserSession.objects.filter(
            user=request.user,
            logout_time__isnull=True,
            is_active=True
        ).order_by('-login_time')
            logger.debug(f"Found {active_sessions.count()} active sessions for user {request.user.id}")
        except Exception as e:
            logger.error(f"Error retrieving active sessions for user {request.user.id}: {str(e)}")
            active_sessions = UserSession.objects.none()
        
        # Get trusted devices
        try:
            trusted_devices = TrustedDevice.objects.filter(
            user=request.user,
                expires_at__gt=timezone.now()
            ).order_by('-last_used')
            logger.debug(f"Found {trusted_devices.count()} trusted devices for user {request.user.id}")
        except Exception as e:
            logger.error(f"Error retrieving trusted devices for user {request.user.id}: {str(e)}")
            trusted_devices = TrustedDevice.objects.none()
        
        # Get current device info
        current_device = None
        try:
            if request.session.session_key:
                current_session = UserSession.objects.filter(
                    user=request.user,
                    session_key=request.session.session_key,
            is_active=True
                ).first()
                if current_session:
                    current_device = {
                        'user_agent': current_session.user_agent,
                        'ip_address': current_session.ip_address,
                        'last_used': current_session.last_activity
                    }
                    logger.debug(f"Found current device info for user {request.user.id}")
        except Exception as e:
            logger.error(f"Error retrieving current device info for user {request.user.id}: {str(e)}")
        
        context = {
            'active_sessions': active_sessions,
            'trusted_devices': trusted_devices,
            'current_device': current_device,
            'current_session': request.session.session_key,
            'title': 'Trusted Devices'
        }
        
        logger.info(f"Successfully loaded trusted devices page for user {request.user.id}")
        return render(request, 'security/trusted_devices.html', context)
        
    except Exception as e:
        logger.error(f"Unexpected error in trusted devices view for user {request.user.id}: {str(e)}", exc_info=True)
        messages.error(request, _('An error occurred loading your devices.'))
        return redirect('gdpr_platform:dashboard')

# Define action types for audit log
ACTION_TYPES = [
    ('login', _('Login')),
    ('logout', _('Logout')),
    ('data_export', _('Data Export')),
    ('data_deletion', _('Data Deletion')),
    ('data_rectification', _('Data Rectification')),
    ('privacy_settings', _('Privacy Settings Update')),
    ('cookie_consent', _('Cookie Consent Update')),
    ('2fa_enabled', _('2FA Enabled')),
    ('2fa_disabled', _('2FA Disabled')),
    ('password_changed', _('Password Changed')),
    ('security_settings', _('Security Settings Update')),
]

@login_required
@role_required('admin', 'compliance_officer', 'dpo', 'user')
def cross_border_transfers(request):
    """Display and manage cross-border data transfers"""
    try:
        # Get filter parameters
        country = request.GET.get('country')
        mechanism = request.GET.get('mechanism')
        status = request.GET.get('status')
        date_range = request.GET.get('date_range', '30')  # Default to last 30 days

        # Base queryset
        transfers = CrossBorderTransfer.objects.all()

        # Apply filters
        if country:
            transfers = transfers.filter(recipient_country=country)
        if mechanism:
            transfers = transfers.filter(transfer_mechanism=mechanism)
        if status:
            transfers = transfers.filter(status=status)
        if date_range and date_range != 'all':
            days = int(date_range)
            start_date = timezone.now() - timezone.timedelta(days=days)
            transfers = transfers.filter(transfer_date__gte=start_date)

        # Order by most recent
        transfers = transfers.order_by('-transfer_date')

        # Calculate statistics
        active_transfers = transfers.filter(status='active').count()
        pending_transfers = transfers.filter(status='pending').count()
        recipient_countries = transfers.values('recipient_country').distinct().count()
        
        # Calculate risk score (example implementation)
        high_risk_transfers = transfers.filter(risk_level='high').count()
        total_transfers = transfers.count()
        risk_score = int((high_risk_transfers / total_transfers * 100) if total_transfers > 0 else 0)

        # Get unique countries and mechanisms for filters
        countries = transfers.values_list('recipient_country', flat=True).distinct()
        mechanisms = CrossBorderTransfer.TRANSFER_MECHANISM_CHOICES

        # Add status class for badges
        for transfer in transfers:
            transfer.status_class = {
                'active': 'success',
                'pending': 'warning',
                'completed': 'info',
                'suspended': 'danger',
                'expired': 'secondary'
            }.get(transfer.status, 'secondary')

        # Pagination
        paginator = Paginator(transfers, 10)
        page = request.GET.get('page', 1)
        try:
            transfers = paginator.page(page)
        except (PageNotAnInteger, EmptyPage):
            transfers = paginator.page(1)

        # Handle new transfer form
        if request.method == 'POST':
            form = CrossBorderTransferForm(request.POST)
            if form.is_valid():
                transfer = form.save(commit=False)
                transfer.user = request.user
                transfer.save()
                
                # Log the transfer
                AuditLog.objects.create(
                    user=request.user,
                    action='cross_border_transfer_created',
                    resource_type='transfer',
                    resource_id=str(transfer.id),
                    ip_address=get_client_ip(request),
                    user_agent=request.META.get('HTTP_USER_AGENT', ''),
                    details={
                        'recipient_country': transfer.recipient_country,
                        'recipient_organization': transfer.recipient_organization,
                        'transfer_date': str(transfer.transfer_date)
                    }
                )
                
                messages.success(request, _('Cross-border transfer record created successfully.'))
                return redirect('gdpr_platform:cross_border_transfers')
        else:
            form = CrossBorderTransferForm()
        
        context = {
            'transfers': transfers,
            'form': form,
            'title': 'Cross-Border Transfers',
            'active_transfers': active_transfers,
            'pending_transfers': pending_transfers,
            'recipient_countries': recipient_countries,
            'risk_score': risk_score,
            'countries': countries,
            'mechanisms': mechanisms,
            'selected_country': country,
            'selected_mechanism': mechanism,
            'selected_status': status,
            'selected_range': date_range
        }
        
        return render(request, 'dpo_templates/cross_border_transfers.html', context)
        
    except Exception as e:
        logger.error(f"Cross-border transfers view error for user {request.user.id}: {str(e)}")
        messages.error(request, _('An error occurred loading cross-border transfers.'))
        return redirect('gdpr_platform:dashboard')

@login_required
@role_required('admin', 'compliance_officer', 'dpo', 'user')
def data_export(request):
    """Handle user data export requests"""
    try:
        if request.method == 'POST':
            # Get selected format and categories
            export_format = request.POST.get('format', 'json')
            categories = request.POST.getlist('categories', [])  # Changed from data_categories to categories
            
            # Get user data
            user_data = get_user_data_categories(request.user)
            
            # Filter data based on selected categories if specific categories were selected
            if categories:
                filtered_data = {}
                for category in categories:
                    if category in user_data:
                        filtered_data[category] = user_data[category]
                user_data = filtered_data
            
            try:
                # Create the export based on the requested format
                if export_format == 'json':
                    export_data = create_json_export(user_data)
                    content_type = 'application/json'
                elif export_format == 'csv':
                    export_data = create_csv_export(user_data)
                    content_type = 'text/csv'
                elif export_format == 'xml':
                    export_data = create_xml_export(user_data)
                    content_type = 'application/xml'
                else:
                    raise ValueError(f"Unsupported export format: {export_format}")
        
                # Create export record
                export_request = DataRequest.objects.create(
                    user=request.user,
                    request_type='export',
                        status='completed',
                        file_format=export_format,
                        data_categories=categories,
                        description=f"Data export in {export_format.upper()} format"
                )
                
                # Send notification email
                send_export_notification_email(request.user, export_request)
            
                # Return the exported data
                response = HttpResponse(export_data, content_type=content_type)
                response['Content-Disposition'] = f'attachment; filename="user_data_{timezone.now().strftime("%Y%m%d_%H%M%S")}.{export_format}"'
                return response
            
            except Exception as e:
                logger.error(f"Data export error for user {request.user.id}: {str(e)}")
                messages.error(request, _("An error occurred while exporting your data. Please try again."))
                return redirect('gdpr_platform:data_export')
        
        # Get previous exports for GET request
        previous_exports = DataRequest.objects.filter(
            user=request.user,
            request_type='export'
        ).order_by('-request_date')[:5]
        
        return render(request, 'gdpr/data_export.html', {  # Changed from user_templates to gdpr
            'title': _("Export Your Data"),
            'previous_exports': previous_exports,
            'exportable_categories': get_exportable_data_categories()  # Changed from data_categories to exportable_categories
        })
        
    except Exception as e:
        logger.error(f"Data export error for user {request.user.id}: {str(e)}")
        messages.error(request, _("An error occurred while processing your request. Please try again."))
        return redirect('gdpr_platform:dashboard')

def get_current_cookie_preferences(user):
    """Get user's current cookie preferences"""
    consent = CookieConsent.objects.filter(user=user).order_by('-timestamp').first()
    if consent:
        return {
            'necessary': consent.necessary_cookies,
            'analytics': consent.analytics_cookies,
            'marketing': consent.marketing_cookies,
            'functional': consent.functional_cookies,
            'last_updated': str(consent.timestamp)
        }
    return None

def get_privacy_policy_consents(user):
    """Get user's privacy policy consent history"""
    return list(UserPrivacyPolicyConsent.objects.filter(user=user).values(
        'policy__version',
        'consent_date',
        'ip_address',
        'user_agent'
    ))

def get_security_preferences(user):
    """Get user's security preferences"""
    return {
        'two_factor_auth': user.two_factor_enabled,
        'trusted_devices_enabled': hasattr(user, 'trust_settings'),
        'session_timeout': getattr(user, 'session_timeout', django_settings.SESSION_COOKIE_AGE),
        'login_notification': getattr(user, 'login_notification_enabled', False)
    }

def create_json_export(data):
    """Create JSON export of user data"""
    return json.dumps(data, indent=2, default=str)

def create_csv_export(data):
    """Create CSV export of user data"""
    output = StringIO()
    writer = csv.writer(output)
            
    for category, category_data in data.items():
        writer.writerow([f"--- {category.upper()} ---"])
        if isinstance(category_data, dict):
            for key, value in category_data.items():
                if isinstance(value, (list, dict)):
                    writer.writerow([key])
                    if isinstance(value, list):
                        # Handle list of dictionaries
                        if value and isinstance(value[0], dict):
                            headers = value[0].keys()
                            writer.writerow(headers)
                            for item in value:
                                if isinstance(item, dict):
                                    writer.writerow([str(item.get(h, '')) for h in headers])
                                else:
                                    writer.writerow([str(item)])
                        else:
                            # Handle list of non-dictionary items
                            for item in value:
                                writer.writerow([str(item)])
                    else:
                        # Handle nested dictionary
                        for k, v in value.items():
                            writer.writerow([k, str(v)])
                else:
                    writer.writerow([key, str(value)])
        else:
            # Handle non-dictionary category data
            writer.writerow(['Value', str(category_data)])
        writer.writerow([])  # Empty row between categories
    
    return output.getvalue()

def create_xml_export(data):
    """Create XML export of user data"""
    root = ET.Element("user_data")
    
    def dict_to_xml(parent, dictionary):
        for key, value in dictionary.items():
            child = ET.SubElement(parent, key.replace(' ', '_'))
            if isinstance(value, dict):
                dict_to_xml(child, value)
            elif isinstance(value, list):
                for item in value:
                    item_elem = ET.SubElement(child, "item")
                    if isinstance(item, dict):
                        dict_to_xml(item_elem, item)
                    else:
                        item_elem.text = str(item)
            else:
                child.text = str(value)
    
    dict_to_xml(root, data)
    return ET.tostring(root, encoding='unicode', method='xml', pretty_print=True)

def get_exportable_data_categories():
    """Get available data categories for export"""
    return [
        {
            'id': 'personal_info',
            'name': _('Personal Information'),
            'description': _('Your basic account and profile information')
        },
        {
            'id': 'privacy_settings',
            'name': _('Privacy Settings'),
            'description': _('Your privacy preferences and consents')
        },
        {
            'id': 'activity_history',
            'name': _('Activity History'),
            'description': _('Your activity logs and data requests')
        },
        {
            'id': 'data_processing',
            'name': _('Data Processing'),
            'description': _('Information about how your data is processed')
        },
        {
            'id': 'security_settings',
            'name': _('Security Settings'),
            'description': _('Your security preferences and trusted devices')
        }
    ]

def send_export_notification_email(user, export_request):
    """Send export notification email"""
    try:
        subject = _('Your Data Export is Ready')
        message = render_to_string('emails/export_notification.html', {
            'user': user,
            'request_id': export_request.id,
            'export_date': timezone.now(),
            'categories': export_request.data_categories,
            'format': export_request.file_format,
            'download_url': reverse('gdpr_platform:download_export', args=[export_request.id])
        })
        
        send_mail(
            subject=subject,
            message=strip_tags(message),
            from_email=django_settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            html_message=message
        )
    except Exception as e:
        logger.error(f"Failed to send export notification email to {user.email}: {str(e)}")

@login_required
@role_required('admin', 'compliance_officer', 'dpo', 'user')
def rectify_user_data(request):
    """Handle user data rectification requests"""
    try:
        if request.method == 'POST':
                corrections = json.loads(request.POST.get('corrections', '{}'))
                
                with transaction.atomic():
                    # Create rectification request
                    rectification_request = DataRequest.objects.create(
                        user=request.user,
                        request_type='rectification',
                        status='processing',
                        details={'corrections': corrections}
                    )
                    
                    # Apply corrections
                    user = request.user
                    for field, value in corrections.items():
                        if hasattr(user, field):
                            setattr(user, field, value)
        user.save()
        
                # Log the rectification
        AuditLog.objects.create(
            user=user,
                    action='data_rectified',
                    resource_type='user_data',
            resource_id=str(user.id),
                    ip_address=get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
                    details={'fields_updated': list(corrections.keys())}
                )
                
        rectification_request.status = 'completed'
        rectification_request.save()
                
        messages.success(request, _('Your data has been updated successfully.'))
        return JsonResponse({'status': 'success'})
                
    except Exception as e:
        logger.error(f"Data rectification error for user {request.user.id}: {str(e)}")
        return JsonResponse({
            'status': 'error',
            'message': _('An error occurred updating your data.')
        }, status=500)
            
    return JsonResponse({'status': 'error', 'message': 'Invalid request method'}, status=405)

@login_required
@role_required('admin', 'compliance_officer', 'dpo', 'user')
def activity_log(request):
    """
    View for displaying activity logs with filtering and pagination.
    """
    # Get filter parameters
    start_date = request.GET.get('start_date')
    end_date = request.GET.get('end_date')
    action_type = request.GET.get('action_type')
    user_id = request.GET.get('user_id')
    
    # Base queryset
    logs = ActivityLog.objects.all().order_by('-timestamp')
    
    # Apply filters
    if start_date:
        logs = logs.filter(timestamp__gte=start_date)
    if end_date:
        logs = logs.filter(timestamp__lte=end_date)
    if action_type:
        logs = logs.filter(action_type=action_type)
    if user_id:
        logs = logs.filter(user_id=user_id)
        
    # Pagination
    paginator = Paginator(logs, 10)
    page = request.GET.get('page')
    try:
        activity_logs = paginator.page(page)
    except PageNotAnInteger:
        activity_logs = paginator.page(1)
    except EmptyPage:
        activity_logs = paginator.page(paginator.num_pages)
    
    # Process logs for display
    for log in activity_logs:
        log.formatted_timestamp = log.timestamp.strftime('%Y-%m-%d %H:%M:%S')
    
    context = {
        'activity_logs': activity_logs,
        'start_date': start_date,
        'end_date': end_date,
        'action_type': action_type,
        'user_id': user_id,
    }
    
    return render(request, 'compliance_officer_templates/activity_log.html', context)

def export_activity_log(request):
    """
    View for exporting activity logs to CSV.
    """
    # Get filter parameters (same as activity_log view)
    start_date = request.GET.get('start_date')
    end_date = request.GET.get('end_date')
    action_type = request.GET.get('action_type')
    user_id = request.GET.get('user_id')
    
    # Base queryset
    logs = ActivityLog.objects.all().order_by('-timestamp')
    
    # Apply filters (same as activity_log view)
    if start_date:
        logs = logs.filter(timestamp__gte=start_date)
    if end_date:
        logs = logs.filter(timestamp__lte=end_date)
    if action_type:
        logs = logs.filter(action_type=action_type)
    if user_id:
        logs = logs.filter(user_id=user_id)
    
    # Create the HttpResponse object with CSV header
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="activity_log.csv"'

    # Create CSV writer
    writer = csv.writer(response)
    writer.writerow([
        'Timestamp',
        'User',
        'Action',
        'Resource Type',
        'Resource ID',
        'IP Address',
        'User Agent',
        'Status',
        'Details'
    ])
            
            # Write data
    for log in logs:
        writer.writerow([
            log.formatted_timestamp,
            log.user.email,
            log.get_action_display(),
            log.resource_type,
            log.resource_id,
            log.ip_address,
            log.user_agent,
            log.get_status_display(),
            json.dumps(log.details)
        ])

    return response

@login_required
@role_required('admin', 'compliance_officer', 'dpo', 'user')
def security_dashboard(request):
    """Display security dashboard with enhanced monitoring"""
    try:
        # Get user's security status
        try:
            two_factor_enabled = hasattr(request.user, 'totp_device')
            logger.debug(f"Two-factor status for user {request.user.id}: {two_factor_enabled}")
        except Exception as e:
            logger.error(f"Error checking 2FA status: {str(e)}")
            two_factor_enabled = False

        try:
            active_sessions = UserSession.objects.filter(
                user=request.user,
                is_active=True
            ).order_by('-login_time')
            logger.debug(f"Found {active_sessions.count()} active sessions for user {request.user.id}")
        except Exception as e:
            logger.error(f"Error retrieving active sessions: {str(e)}")
            active_sessions = UserSession.objects.none()

        try:
            security_logs = ActivityLog.objects.filter(
                user=request.user,
                action_type__in=['login', 'password', '2fa', 'security']
            ).order_by('-timestamp')[:10]
            logger.debug(f"Found {security_logs.count()} security logs for user {request.user.id}")
        except Exception as e:
            logger.error(f"Error retrieving security logs: {str(e)}")
            security_logs = ActivityLog.objects.none()

        try:
            trusted_devices = TrustedDevice.objects.filter(
                user=request.user,
                expires_at__gt=timezone.now()
            ).order_by('-last_used')
            logger.debug(f"Found {trusted_devices.count()} trusted devices for user {request.user.id}")
        except Exception as e:
            logger.error(f"Error retrieving trusted devices: {str(e)}")
            trusted_devices = TrustedDevice.objects.none()

        try:
            login_history = ActivityLog.objects.filter(
                user=request.user,
                action_type='login'
            ).order_by('-timestamp')[:10]
            logger.debug(f"Found {login_history.count()} login history entries for user {request.user.id}")
        except Exception as e:
            logger.error(f"Error retrieving login history: {str(e)}")
            login_history = ActivityLog.objects.none()

        # Calculate security score based on available factors
        security_score = 0
        try:
            if two_factor_enabled:
                security_score += 40
            if trusted_devices.exists():
                security_score += 20
            if request.user.last_password_change:
                days_since_password_change = (timezone.now() - request.user.last_password_change).days
                if days_since_password_change <= 90:
                    security_score += 20
            if active_sessions.count() <= 3:  # Not too many active sessions
                security_score += 20
            logger.debug(f"Calculated security score for user {request.user.id}: {security_score}")
        except Exception as e:
            logger.error(f"Error calculating security score: {str(e)}")
            security_score = 0

        context = {
            'title': _('Security Dashboard'),
            'two_factor_enabled': two_factor_enabled,
            'active_sessions': active_sessions,
            'security_logs': security_logs,
            'trusted_devices': trusted_devices,
            'trusted_devices_count': trusted_devices.count(),
            'security_score': security_score,
            'login_history': login_history,
            'user': request.user
        }
        
        return render(request, 'security/security_dashboard.html', context)
        
    except Exception as e:
        logger.error(f"Security dashboard error for user {request.user.id}: {str(e)}", exc_info=True)
        messages.error(request, _('An error occurred loading the security dashboard.'))
        return redirect('gdpr_platform:dashboard')

@login_required
@role_required('admin', 'compliance_officer', 'dpo', 'user')
def data_processing(request):
    """Handle data processing activities and cross-border transfers."""
    
    # Get processing activities
    activities = DataProcessingActivity.objects.filter(is_active=True).order_by('-created_at')
    processing_activities = [{
        'activity_type': activity.title,
        'description': activity.description,
        'timestamp': activity.created_at
    } for activity in activities]

    # Get transfers
    transfers_qs = DataTransfer.objects.filter(status='active').order_by('-created_at')
    transfers = [{
        'recipient_organization': transfer.destination_system,
        'recipient_country': transfer.destination_system,
        'data_categories': transfer.data_categories,
        'transfer_date': transfer.created_at
    } for transfer in transfers_qs]

    # Get retention settings
    retention_settings = {
        'personal_data': {'retention_period': 24, 'unit': 'months'},
        'sensitive_data': {'retention_period': 12, 'unit': 'months'},
        'financial_data': {'retention_period': 84, 'unit': 'months'},
        'communication_data': {'retention_period': 36, 'unit': 'months'}
    }
        
    context = {
        'title': _('Data Processing Activities'),
        'processing_activities': processing_activities,
        'transfers': transfers,
        'retention_settings': retention_settings
        }
        
    return render(request, 'dpo_templates/data_processing.html', context)

@login_required
@role_required('admin', 'compliance_officer', 'user')
def privacy_policy(request):
    """Display and manage privacy policy"""
    try:
        # Get the latest active policy
        try:
            current_policy = PrivacyPolicy.objects.filter(is_active=True).latest('effective_date')
        except PrivacyPolicy.DoesNotExist:
            # Create a default policy if none exists
            current_policy = PrivacyPolicy.objects.create(
                title=_('Privacy Policy'),
                content=render_to_string('gdpr/default_privacy_policy.html'),
                version='1.0',
                is_active=True,
                effective_date=timezone.now()
            )
        
        # Get user's consent status
        user_consent = UserPrivacyPolicyConsent.objects.filter(
            user=request.user,
            policy=current_policy
        ).first()
        
        context = {
            'title': _('Privacy Policy'),
            'policy': current_policy,
            'has_consented': bool(user_consent),
            'consent_date': user_consent.consented_at if user_consent else None,
            'show_consent_banner': not bool(user_consent)
        }
        
        return render(request, 'gdpr/privacy_policy.html', context)
            
    except Exception as e:
        logger.error(f"Privacy policy view error: {str(e)}")
        messages.error(request, _('An error occurred while loading the privacy policy.'))
        return redirect('gdpr_platform:dashboard')

@login_required
@role_required('admin', 'compliance_officer', 'user')
def update_privacy_policy_consent(request):
    """Handle privacy policy consent updates"""
    if request.method == 'POST':
        try:
            current_policy = PrivacyPolicy.objects.filter(is_active=True).first()
            if not current_policy:
                return JsonResponse({
                    'status': 'error',
                    'message': _('No active privacy policy found.')
                }, status=400)
            
            # Create or update consent
            consent, created = UserPrivacyPolicyConsent.objects.get_or_create(
                user=request.user,
                policy=current_policy,
                defaults={
                    'ip_address': get_client_ip(request),
                    'user_agent': request.META.get('HTTP_USER_AGENT', '')
                }
            )
            
            if not created:
                consent.ip_address = get_client_ip(request)
                consent.user_agent = request.META.get('HTTP_USER_AGENT', '')
                consent.consented_at = timezone.now()
                consent.save()
            
            # Log the consent
            AuditLog.objects.create(
                user=request.user,
                action='privacy_policy_consent_updated',
                resource_type='privacy_policy',
                resource_id=str(current_policy.id),
                ip_address=get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', '')
            )
            
            messages.success(request, _('Your privacy policy consent has been updated.'))
            return JsonResponse({'status': 'success'})
            
        except Exception as e:
            logger.error(f"Privacy policy consent update error for user {request.user.id}: {str(e)}")
            return JsonResponse({
                'status': 'error',
                'message': _('An error occurred updating your consent.')
            }, status=500)
            
    return JsonResponse({'status': 'error', 'message': 'Invalid request method'}, status=405)

@login_required
def setup_2fa(request):
    """Handle 2FA setup"""
    if request.method == 'POST':
        form = TwoFactorSetupForm(request.POST)
        if form.is_valid():
            try:
                # Get or create TOTP device
                device, created = TOTPDevice.objects.get_or_create(
                    user=request.user,
                    defaults={'confirmed': False}
                )
                
                if not device.confirmed:
                    # Verify the token
                    if device.verify_token(form.cleaned_data['verification_code']):
                        device.confirmed = True
                        device.save()
            
                        # Update user's 2FA status
                        request.user.two_factor_enabled = True
                        request.user.save()
                        
                        # Log the setup
                        AuditLog.objects.create(
                            user=request.user,
                            action='2fa_enabled',
                            resource_type='security',
                resource_id=str(request.user.id),
                            ip_address=get_client_ip(request),
                            user_agent=request.META.get('HTTP_USER_AGENT', '')
                        )
                                    
                        messages.success(request, _('Two-factor authentication has been enabled.'))
                        return redirect('gdpr_platform:security_settings')
                    else:
                        messages.error(request, _('Invalid verification code.'))
                else:
                    messages.error(request, _('Two-factor authentication is already set up.'))
            except Exception as e:
                logger.error(f"2FA setup error for user {request.user.id}: {str(e)}")
                messages.error(request, _('An error occurred during 2FA setup.'))
        else:
            form = TwoFactorSetupForm()
            
            # Generate new secret key if needed
            device, created = TOTPDevice.objects.get_or_create(
                user=request.user,
                defaults={'confirmed': False}
            )
            
            if created or not device.confirmed:
        # Generate QR code
                qr = qrcode.QRCode(
                    version=1,
                    error_correction=qrcode.constants.ERROR_CORRECT_L,
                    box_size=10,
                    border=4,
                )
        provisioning_uri = device.config_url
        qr.add_data(provisioning_uri)
        qr.make(fit=True)
        
                # Create SVG QR code
        img = qr.make_image(image_factory=qrcode.image.svg.SvgImage)
        stream = BytesIO()
        img.save(stream)
        qr_code = stream.getvalue().decode()
                
        context = {
            'form': form,
            'qr_code': qr_code,
            'secret_key': device.key,
            'title': 'Setup Two-Factor Authentication'
            }
                
        return render(request, 'security/setup_2fa.html', context)
        
    return redirect('gdpr_platform:security_settings')

@login_required
def disable_2fa(request):
    """Handle 2FA disablement"""
    if request.method == 'POST':
        try:
            # Remove TOTP devices
            TOTPDevice.objects.filter(user=request.user).delete()
            
            
            # Update user's 2FA status
            request.user.two_factor_enabled = False
            request.user.save()
            
            # Log the disablement
            AuditLog.objects.create(
                user=request.user,
                action='2fa_disabled',
                resource_type='security',
                resource_id=str(request.user.id),
                ip_address=get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', '')
            )
            
            # Invalidate all sessions for security
            Session.objects.filter(expire_date__gte=timezone.now()).delete()
            
            messages.success(request, _('Two-factor authentication has been disabled.'))
            return redirect('gdpr_platform:login')
        
        except Exception as e:
            logger.error(f"2FA disable error for user {request.user.id}: {str(e)}")
            messages.error(request, _('An error occurred disabling 2FA.'))
            
    return redirect('gdpr_platform:security_settings')

@login_required
def trusted_devices(request):
    """Handle trusted devices management"""
    try:
        logger.info(f"Loading trusted devices for user {request.user.id}")
        
        # Get user's active sessions
        try:
            active_sessions = UserSession.objects.filter(
                user=request.user,
                logout_time__isnull=True,
                is_active=True
            ).order_by('-login_time')
            logger.debug(f"Found {active_sessions.count()} active sessions for user {request.user.id}")
        except Exception as e:
            logger.error(f"Error retrieving active sessions for user {request.user.id}: {str(e)}")
            active_sessions = UserSession.objects.none()
        
        # Get trusted devices
        try:
            trusted_devices = TrustedDevice.objects.filter(
                user=request.user,
                expires_at__gt=timezone.now()
            ).order_by('-last_used')
            logger.debug(f"Found {trusted_devices.count()} trusted devices for user {request.user.id}")
        except Exception as e:
            logger.error(f"Error retrieving trusted devices for user {request.user.id}: {str(e)}")
            trusted_devices = TrustedDevice.objects.none()
        
        # Get current device info
        current_device = None
        try:
            if request.session.session_key:
                current_session = UserSession.objects.filter(
                    user=request.user,
                    session_key=request.session.session_key,
                    is_active=True
                ).first()
                if current_session:
                    current_device = {
                        'user_agent': current_session.user_agent,
                        'ip_address': current_session.ip_address,
                        'last_used': current_session.last_activity
                    }
                    logger.debug(f"Found current device info for user {request.user.id}")
        except Exception as e:
            logger.error(f"Error retrieving current device info for user {request.user.id}: {str(e)}")
        
        context = {
            'active_sessions': active_sessions,
            'trusted_devices': trusted_devices,
            'current_device': current_device,
            'current_session': request.session.session_key,
            'title': 'Trusted Devices'
        }
        
        logger.info(f"Successfully loaded trusted devices page for user {request.user.id}")
        return render(request, 'security/trusted_devices.html', context)
        
    except Exception as e:
        logger.error(f"Unexpected error in trusted devices view for user {request.user.id}: {str(e)}", exc_info=True)
        messages.error(request, _('An error occurred loading your devices.'))
        return redirect('gdpr_platform:dashboard')

# Define action types for audit log
ACTION_TYPES = [
    ('login', _('Login')),
    ('logout', _('Logout')),
    ('data_export', _('Data Export')),
    ('data_deletion', _('Data Deletion')),
    ('data_rectification', _('Data Rectification')),
    ('privacy_settings', _('Privacy Settings Update')),
    ('cookie_consent', _('Cookie Consent Update')),
    ('2fa_enabled', _('2FA Enabled')),
    ('2fa_disabled', _('2FA Disabled')),
    ('password_changed', _('Password Changed')),
    ('security_settings', _('Security Settings Update')),
]

@login_required
@role_required('admin', 'compliance_officer', 'dpo', 'user')
def cross_border_transfers(request):
    """Display and manage cross-border data transfers"""
    try:
        # Get filter parameters
        country = request.GET.get('country')
        mechanism = request.GET.get('mechanism')
        status = request.GET.get('status')
        date_range = request.GET.get('date_range', '30')  # Default to last 30 days

        # Base queryset
        transfers = CrossBorderTransfer.objects.all()

        # Apply filters
        if country:
            transfers = transfers.filter(recipient_country=country)
        if mechanism:
            transfers = transfers.filter(transfer_mechanism=mechanism)
        if status:
            transfers = transfers.filter(status=status)
        if date_range and date_range != 'all':
            days = int(date_range)
            start_date = timezone.now() - timezone.timedelta(days=days)
            transfers = transfers.filter(transfer_date__gte=start_date)

        # Order by most recent
        transfers = transfers.order_by('-transfer_date')

        # Calculate statistics
        active_transfers = transfers.filter(status='active').count()
        pending_transfers = transfers.filter(status='pending').count()
        recipient_countries = transfers.values('recipient_country').distinct().count()
        
        # Calculate risk score (example implementation)
        high_risk_transfers = transfers.filter(risk_level='high').count()
        total_transfers = transfers.count()
        risk_score = int((high_risk_transfers / total_transfers * 100) if total_transfers > 0 else 0)

        # Get unique countries and mechanisms for filters
        countries = transfers.values_list('recipient_country', flat=True).distinct()
        mechanisms = CrossBorderTransfer.TRANSFER_MECHANISM_CHOICES

        # Add status class for badges
        for transfer in transfers:
            transfer.status_class = {
                'active': 'success',
                'pending': 'warning',
                'completed': 'info',
                'suspended': 'danger',
                'expired': 'secondary'
            }.get(transfer.status, 'secondary')

        # Pagination
        paginator = Paginator(transfers, 10)
        page = request.GET.get('page', 1)
        try:
            transfers = paginator.page(page)
        except (PageNotAnInteger, EmptyPage):
            transfers = paginator.page(1)

        # Handle new transfer form
        if request.method == 'POST':
            form = CrossBorderTransferForm(request.POST)
            if form.is_valid():
                transfer = form.save(commit=False)
                transfer.user = request.user
                transfer.save()
                
                # Log the transfer
                AuditLog.objects.create(
                    user=request.user,
                    action='cross_border_transfer_created',
                    resource_type='transfer',
                    resource_id=str(transfer.id),
                    ip_address=get_client_ip(request),
                    user_agent=request.META.get('HTTP_USER_AGENT', ''),
                    details={
                        'recipient_country': transfer.recipient_country,
                        'recipient_organization': transfer.recipient_organization,
                        'transfer_date': str(transfer.transfer_date)
                    }
                )
                
                messages.success(request, _('Cross-border transfer record created successfully.'))
                return redirect('gdpr_platform:cross_border_transfers')
        else:
            form = CrossBorderTransferForm()
        
        context = {
            'transfers': transfers,
            'form': form,
            'title': 'Cross-Border Transfers',
            'active_transfers': active_transfers,
            'pending_transfers': pending_transfers,
            'recipient_countries': recipient_countries,
            'risk_score': risk_score,
            'countries': countries,
            'mechanisms': mechanisms,
            'selected_country': country,
            'selected_mechanism': mechanism,
            'selected_status': status,
            'selected_range': date_range
        }
        
        return render(request, 'dpo_templates/cross_border_transfers.html', context)
        
    except Exception as e:
        logger.error(f"Cross-border transfers view error for user {request.user.id}: {str(e)}")
        messages.error(request, _('An error occurred loading cross-border transfers.'))
        return redirect('gdpr_platform:dashboard')

@login_required
@role_required('admin', 'compliance_officer', 'dpo', 'user')
def data_rectification(request):
    """Handle user data rectification requests"""
    try:
        if request.method == 'POST':
            form = DataRequestForm(request.POST)
            if form.is_valid():
                # Create rectification request
                rectification_request = DataRequest.objects.create(
                user=request.user,
                    request_type='rectification',
                    status='pending',
                    notes=form.cleaned_data['notes']
                )
                
                # Log the request
                AuditLog.objects.create(
                    user=request.user,
                    action='data_rectification_requested',
                    resource_type='user_data',
                    resource_id=str(request.user.id),
                    details={'request_id': str(rectification_request.id)}
                )
                
                messages.success(request, _('Your data rectification request has been submitted.'))
                return redirect('gdpr_platform:dashboard')
        else:
            form = DataRequestForm()
        
        return render(request, 'user_templates/data_rectification.html', {
            'title': _('Update Your Data'),
            'form': form
        })
        
    except Exception as e:
        logger.error(f"Data rectification error for user {request.user.id}: {str(e)}")
        messages.error(request, _('An error occurred while processing your request.'))
        return redirect('gdpr_platform:dashboard')

@login_required
def settings(request):
    """User settings view"""
    try:
        if request.method == 'POST':
                # Update user settings
            user = request.user
            user.first_name = request.POST.get('first_name', user.first_name)
            user.last_name = request.POST.get('last_name', user.last_name)
            user.email = request.POST.get('email', user.email)
            user.phone_number = request.POST.get('phone_number', user.phone_number)
            user.date_of_birth = request.POST.get('date_of_birth', user.date_of_birth)
            user.address = request.POST.get('address', user.address)
            user.city = request.POST.get('city', user.city)
            user.country = request.POST.get('country', user.country)
            user.postal_code = request.POST.get('postal_code', user.postal_code)
            user.nationality = request.POST.get('nationality', user.nationality)
            user.occupation = request.POST.get('occupation', user.occupation)
            user.company = request.POST.get('company', user.company)
            user.preferred_language = request.POST.get('preferred_language', user.preferred_language)
            user.save()
                
                # Log the update
            AuditLog.objects.create(
                user=user,
                action='settings_updated',
                resource_type='user_settings',
                resource_id=str(user.id)
            )
                
            messages.success(request, _('Your settings have been updated.'))
            return redirect('gdpr_platform:settings')
        
        return render(request, 'user_templates/settings.html', {
            'title': _('Settings'),
            'user': request.user
        })
    except Exception as e:
        logger.error(f"Settings view error for user {request.user.id}: {str(e)}")
        messages.error(request, _('An error occurred while updating your settings.'))
        return redirect('gdpr_platform:dashboard')

@login_required
@role_required('admin')
def revoke_session(request):
    """Revoke a specific session"""
    try:
        session_key = request.POST.get('session_key')
        if session_key:
            # Don't allow revoking current session
            if session_key != request.session.session_key:
                UserSession.objects.filter(
                    user=request.user,
                    session_key=session_key
                ).update(
                    is_active=False,
                    logout_time=timezone.now(),
                    end_reason='revoked'
                )
                
                # Delete the session
                Session.objects.filter(session_key=session_key).delete()
                
                # Log the action
                AuditLog.objects.create(
                    user=request.user,
                    action='session_revoked',
                    resource_type='session',
                    resource_id=session_key,
                    ip_address=get_client_ip(request),
                    user_agent=request.META.get('HTTP_USER_AGENT', '')
                )
                
                messages.success(request, _('Session has been revoked.'))
        else:
                messages.error(request, _('Cannot revoke current session.'))
    except Exception as e:
        logger.error(f"Session revocation error for user {request.user.id}: {str(e)}")
        messages.error(request, _('An error occurred while revoking the session.'))
    
    return redirect('gdpr_platform:trusted_devices')

@login_required
@role_required('admin')
def revoke_all_sessions(request):
    """Revoke all sessions except current"""
    try:
        current_session_key = request.session.session_key
        
        # Update UserSession records
        UserSession.objects.filter(
            user=request.user
        ).exclude(
            session_key=current_session_key
        ).update(
            is_active=False,
            logout_time=timezone.now(),
            end_reason='revoked_all'
        )
        
        # Delete session records
        Session.objects.filter(
            expire_date__gte=timezone.now()
        ).exclude(
            session_key=current_session_key
        ).delete()
        
        # Log the action
        AuditLog.objects.create(
                user=request.user,
            action='all_sessions_revoked',
            resource_type='session',
            resource_id='all',
                ip_address=get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', '')
        )
        
        messages.success(request, _('All other sessions have been revoked.'))
    except Exception as e:
        logger.error(f"All sessions revocation error for user {request.user.id}: {str(e)}")
        messages.error(request, _('An error occurred while revoking sessions.'))
    
    return redirect('gdpr_platform:trusted_devices')

@login_required
@admin_required
def admin_dashboard(request):
    """
    Admin dashboard view showing system overview and key metrics.
    """
    # Get user statistics
    total_users = User.objects.count()
    active_users = User.objects.filter(is_active=True).count()
    
    # Get pending data requests
    pending_requests = DataRequest.objects.filter(status='pending').count()
    
    # Get active data breaches
    active_breaches = DataBreach.objects.filter(status='active').count()
    
    # Calculate system health
    db_health = check_database_health()
    cache_health = check_cache_health()
    storage_health = check_storage_health()
    system_health = (db_health + cache_health + storage_health) // 3
    
    # Get recent activity
    recent_activity = AuditLog.objects.all().order_by('-timestamp')[:10]
    
    # Get pending data requests for display
    pending_data_requests = DataRequest.objects.filter(
        status='pending'
    ).select_related('user').order_by('-request_date')[:5]
    
    context = {
        'total_users': total_users,
        'active_users': active_users,
        'pending_requests': pending_requests,
        'active_breaches': active_breaches,
        'system_health': system_health,
        'db_health': db_health,
        'cache_health': cache_health,
        'storage_health': storage_health,
        'recent_activity': recent_activity,
        'pending_data_requests': pending_data_requests,
        'db_status_message': _('Database is functioning normally'),
        'cache_status_message': _('Cache system is responsive'),
        'storage_status_message': _('Storage system is available'),
    }
    
    return render(request, 'admin_templates/admin_dashboard.html', context)

@login_required
@admin_required
def user_management(request):
    """
    User management view for administrators.
    """
    # Handle POST requests (add, edit, delete users)
    if request.method == 'POST':
        action = request.POST.get('action')
        
        if action == 'edit':
            return handle_user_edit(request)
        elif action == 'delete':
            return handle_user_delete(request)
        else:
            return handle_user_add(request)
    
    # Get query parameters
    search = request.GET.get('search', '')
    role = request.GET.get('role', '')
    status = request.GET.get('status', '')
    sort = request.GET.get('sort', 'date_joined')
    page = request.GET.get('page', 1)
    
    # Build query
    users = User.objects.all()
    
    if search:
        users = users.filter(
            Q(email__icontains=search) |
            Q(first_name__icontains=search) |
            Q(last_name__icontains=search)
        )
    
    if role:
        users = users.filter(roles__name=role)
    
    if status:
        users = users.filter(account_status=status)
    
    # Apply sorting
    if sort == 'email':
        users = users.order_by('email')
    elif sort == 'last_login':
        users = users.order_by('-last_login')
    else:  # date_joined
        users = users.order_by('-date_joined')
    
    # Paginate results
    paginator = Paginator(users, 20)
    users_page = paginator.get_page(page)
    
    context = {
        'users': users_page,
        'available_roles': Role.objects.all(),
        'search': search,
        'role': role,
        'status': status,
        'sort': sort,
    }
    
    return render(request, 'admin_templates/user_management.html', context)

@login_required
@admin_required
def system_settings(request):
    """
    System settings view for administrators.
    """
    if request.method == 'POST':
        return handle_settings_update(request)
    
    # Get current settings
    current_settings = SystemSettings.get_settings()
    
    context = {
        'settings': settings,
        'available_languages': django_settings.LANGUAGES,
        'available_timezones': pytz.common_timezones,
    }
    
    return render(request, 'admin_templates/system_settings.html', context)

# Helper functions for user management
def handle_user_add(request):
    """Handle adding a new user."""
    try:
        email = request.POST.get('email')
        first_name = request.POST.get('first_name')
        last_name = request.POST.get('last_name')
        roles = request.POST.getlist('roles')
        
        # Create user
        user = User.objects.create_user(
            email=email,
            first_name=first_name,
            last_name=last_name
        )
        
        # Assign roles
        for role_id in roles:
            role = Role.objects.get(id=role_id)
            user.roles.add(role)
        
        # Log action
        AuditLog.objects.create(
            user=request.user,
            action=f"Created user: {email}",
            category="user_management"
        )
        
        messages.success(request, _('User created successfully'))
        return JsonResponse({'success': True})
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)})

def handle_user_edit(request):
    """Handle editing an existing user."""
    try:
        user_id = request.POST.get('user_id')
        user = get_object_or_404(User, id=user_id)
        
        # Update user fields
        user.email = request.POST.get('email')
        user.first_name = request.POST.get('first_name')
        user.last_name = request.POST.get('last_name')
        user.account_status = request.POST.get('status')
        
        # Update roles
        new_roles = request.POST.getlist('roles')
        user.roles.clear()
        for role_id in new_roles:
            role = Role.objects.get(id=role_id)
            user.roles.add(role)
        
        user.save()
        
        # Log action
        AuditLog.objects.create(
            user=request.user,
            action=f"Updated user: {user.email}",
            category="user_management"
        )
        
        messages.success(request, _('User updated successfully'))
        return JsonResponse({'success': True})
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)})

def handle_user_delete(request):
    """Handle deleting a user."""
    try:
        user_id = request.POST.get('user_id')
        user = get_object_or_404(User, id=user_id)
        
        # Log action before deletion
        email = user.email
        AuditLog.objects.create(
            user=request.user,
            action=f"Deleted user: {email}",
            category="user_management"
        )
        
        user.delete()
        messages.success(request, _('User deleted successfully'))
        return JsonResponse({'success': True})
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)})

# Helper functions for system settings
@admin_required
def system_settings(request):
    """
    System settings view for administrators.
    """
    if request.method == 'POST':
        try:
            current_settings = SystemSettings.get_settings()
            
            # Update general settings
            current_settings.platform_name = request.POST.get('platform_name')
            current_settings.support_email = request.POST.get('support_email')
            current_settings.default_language = request.POST.get('default_language')
            current_settings.timezone = request.POST.get('timezone')
            
            # Update security settings
            current_settings.enforce_2fa = request.POST.get('enforce_2fa') == 'true'
            current_settings.session_timeout = int(request.POST.get('session_timeout'))
            current_settings.password_policy = {
                'require_uppercase': request.POST.get('require_uppercase') == 'true',
                'require_numbers': request.POST.get('require_numbers') == 'true',
                'require_special_chars': request.POST.get('require_special_chars') == 'true',
                'min_length': int(request.POST.get('min_password_length'))
            }
            
            # Update data retention settings
            current_settings.data_retention = {
                'audit_log_days': int(request.POST.get('audit_log_retention')),
                'backup_days': int(request.POST.get('backup_retention')),
                'inactive_user_days': int(request.POST.get('inactive_user_deletion')),
                'auto_anonymize': request.POST.get('auto_anonymize') == 'true'
            }
            
            # Update email settings
            current_settings.email = {
                'smtp_host': request.POST.get('smtp_host'),
                'smtp_port': int(request.POST.get('smtp_port')),
                'smtp_user': request.POST.get('smtp_user'),
                'smtp_password': request.POST.get('smtp_password'),
                'use_tls': request.POST.get('use_tls') == 'true'
            }
            
            current_settings.save()
            
            # Log action
            AuditLog.objects.create(
                user=request.user,
                action="Updated system settings",
                category="system_settings"
            )
            
            return JsonResponse({'success': True})
        except Exception as e:
            return JsonResponse({'success': False, 'error': str(e)})
    
    # Get current settings
    current_settings = SystemSettings.get_settings()
    
    context = {
        'settings': current_settings,
        'available_languages': django_settings.LANGUAGES,
        'available_timezones': pytz.common_timezones,
    }
    
    return render(request, 'admin_templates/system_settings.html', context)
# System health check functions
def check_database_health():
    """Check database health and return a percentage score."""
    try:
        # Perform basic database operations
        User.objects.first()
        return 100
    except:
        return 0

def check_cache_health():
    """Check cache system health and return a percentage score."""
    try:
        from django.core.cache import cache
        cache.set('health_check', 'ok', 10)
        result = cache.get('health_check') == 'ok'
        return 100 if result else 0
    except:
        return 0

def check_storage_health():
    """Check storage system health and return a percentage score."""
    try:
        import os
        storage_path = django_settings.MEDIA_ROOT
        # Check if storage is writable
        test_file = os.path.join(storage_path, '.storage_test')
        with open(test_file, 'w') as f:
            f.write('test')
        os.remove(test_file)
        return 100
    except:
        return 0

@login_required
@role_required('admin', 'compliance_officer', 'dpo', 'user')
def compliance_dashboard(request):
    """
    Display the compliance dashboard with metrics, status, and recent activities.
    """
    # Calculate compliance metrics
    compliance_score = calculate_compliance_score()
    pending_requests = DataRequest.objects.filter(status='pending').count()
    policy_updates = AuditLog.objects.filter(
        action='policy_updated',
        timestamp__gte=timezone.now() - timedelta(days=30)
    ).count()
    risk_level = calculate_risk_level()

    # Calculate compliance status scores
    data_protection_score = calculate_data_protection_score()
    user_rights_score = calculate_user_rights_score()
    documentation_score = calculate_documentation_score()
    breach_management_score = calculate_breach_management_score()
    third_party_score = calculate_third_party_score()
    staff_training_score = calculate_staff_training_score()

    # Get recent activities
    recent_activities = AuditLog.objects.filter(
        action__in=['data_request', 'policy_updated', 'breach_reported', 'compliance_check']
    ).order_by('-timestamp')[:10]

    # Get pending tasks
    pending_tasks = Task.objects.filter(
        status='pending',
        due_date__gte=timezone.now()
    ).order_by('due_date')[:10]

    context = {
        'compliance_score': compliance_score,
        'pending_requests': pending_requests,
        'policy_updates': policy_updates,
        'risk_level': risk_level,
        'data_protection_score': data_protection_score,
        'user_rights_score': user_rights_score,
        'documentation_score': documentation_score,
        'breach_management_score': breach_management_score,
        'third_party_score': third_party_score,
        'staff_training_score': staff_training_score,
        'recent_activities': [
            {
                'timestamp': activity.timestamp,
                'description': activity.get_action_display(),
                'status': activity.get_status_display(),
                'status_class': get_status_class(activity.status)
            }
            for activity in recent_activities
        ],
        'pending_tasks': [
            {
                'description': task.description,
                'due_date': task.due_date,
                'priority': task.get_priority_display(),
                'priority_class': get_priority_class(task.priority)
            }
            for task in pending_tasks
        ]
    }

    return render(request, 'compliance_officer_templates/compliance_dashboard.html', context)

def calculate_compliance_score():
    """Calculate overall compliance score based on various metrics."""
    scores = [
        calculate_data_protection_score(),
        calculate_user_rights_score(),
        calculate_documentation_score(),
        calculate_breach_management_score(),
        calculate_third_party_score(),
        calculate_staff_training_score()
    ]
    return round(sum(scores) / len(scores))

def calculate_data_protection_score():
    """Calculate data protection compliance score."""
    try:
        weights = {
            'processing_activities': 0.3,
            'security_measures': 0.3,
            'data_breaches': 0.2,
            'cross_border': 0.2
        }
        
        # Processing activities score
        total_processing = DataProcessingActivity.objects.count()
        if total_processing > 0:
            compliant_processing = DataProcessingActivity.objects.filter(
                Q(legal_basis__isnull=False) & 
                Q(purpose__isnull=False) & 
                Q(security_measures__isnull=False)
            ).count()
            processing_score = (compliant_processing / total_processing * 100)
        else:
            processing_score = 100
            
        # Security measures score
        security_score = calculate_security_score()
            
        # Data breaches score
        total_breaches = DataBreach.objects.count()
        if total_breaches > 0:
            handled_breaches = DataBreach.objects.filter(
                Q(containment_measures__isnull=False) & 
                Q(remediation_steps__isnull=False)
            ).count()
            breach_score = (handled_breaches / total_breaches * 100)
        else:
            breach_score = 100
            
        # Cross-border transfers score
        total_transfers = CrossBorderTransfer.objects.count()
        if total_transfers > 0:
            compliant_transfers = CrossBorderTransfer.objects.filter(
                Q(transfer_mechanism__in=['scc', 'bcr', 'adequacy']) | 
                Q(adequacy_assessment__isnull=False)
            ).count()
            transfer_score = (compliant_transfers / total_transfers * 100)
        else:
            transfer_score = 100
            
        # Calculate weighted score
        total_score = (
            processing_score * weights['processing_activities'] +
            security_score * weights['security_measures'] +
            breach_score * weights['data_breaches'] +
            transfer_score * weights['cross_border']
        )
        
        return round(total_score)
    except Exception as e:
        logger.error(f"Error calculating data protection score: {str(e)}")
        return 0

def calculate_user_rights_score():
    """Calculate user rights compliance score."""
    try:
        total_score = 0
        weights = {
            'request_handling': 0.4,
            'consent_management': 0.3,
            'privacy_notices': 0.3
        }
        
        # Check data request handling
        total_requests = DataRequest.objects.count()
        if total_requests > 0:
            timely_responses = DataRequest.objects.filter(
                completion_date__lte=F('request_date') + timedelta(days=30)
            ).count()
            request_score = (timely_responses / total_requests * 100)
        else:
            request_score = 100
            
        # Check consent management
        total_users = CustomUser.objects.count()
        users_with_consent = CookieConsent.objects.values('user').distinct().count()
        consent_score = (users_with_consent / total_users * 100) if total_users > 0 else 100
        
        # Check privacy notices
        latest_policy = PrivacyPolicy.objects.filter(is_active=True).first()
        if latest_policy:
            users_accepted = UserPrivacyPolicyConsent.objects.filter(
                policy=latest_policy
            ).values('user').distinct().count()
            privacy_score = (users_accepted / total_users * 100) if total_users > 0 else 100
        else:
            privacy_score = 0
            
        # Calculate weighted score
        total_score = (
            request_score * weights['request_handling'] +
            consent_score * weights['consent_management'] +
            privacy_score * weights['privacy_notices']
        )
        
        return round(total_score)
    except Exception as e:
        logger.error(f"Error calculating user rights score: {str(e)}")
        return 0

def calculate_documentation_score():
    """Calculate documentation compliance score."""
    try:
        total_score = 0
        weights = {
            'processing_records': 0.4,
            'breach_documentation': 0.3,
            'consent_records': 0.3
        }
        
        # Check processing activity documentation
        activities = DataProcessingActivity.objects.all()
        if activities.exists():
            well_documented = activities.exclude(
                Q(description='') | 
                Q(purpose='') | 
                Q(security_measures={}) |
                Q(data_subjects={}) |
                Q(recipients={})
            ).count()
            processing_score = (well_documented / activities.count() * 100)
        else:
            processing_score = 100
            
        # Check breach documentation
        breaches = DataBreach.objects.all()
        if breaches.exists():
            documented_breaches = breaches.exclude(
                Q(description='') |
                Q(remediation_steps='') |
                Q(data_protection_impact='') |
                Q(breach_root_cause='')
            ).count()
            breach_score = (documented_breaches / breaches.count() * 100)
        else:
            breach_score = 100
            
        # Check consent records
        consents = ConsentRecord.objects.all()
        if consents.exists():
            valid_consents = consents.exclude(
                Q(purpose='') |
                Q(notes='')
            ).count()
            consent_score = (valid_consents / consents.count() * 100)
        else:
            consent_score = 100
            
        # Calculate weighted score
        total_score = (
            processing_score * weights['processing_records'] +
            breach_score * weights['breach_documentation'] +
            consent_score * weights['consent_records']
        )
        
        return round(total_score)
    except Exception as e:
        logger.error(f"Error calculating documentation score: {str(e)}")
        return 0

def calculate_breach_management_score():
    """Calculate breach management compliance score."""
    try:
        total_score = 0
        weights = {
            'response_time': 0.3,
            'notification_compliance': 0.3,
            'resolution_rate': 0.2,
            'documentation_quality': 0.2
        }
        
        breaches = DataBreach.objects.all()
        if breaches.exists():
            # Check response time (should be within 72 hours)
            timely_responses = 0
            for breach in breaches:
                if breach.date_reported and breach.date_discovered:
                    response_time = (breach.date_reported - breach.date_discovered).total_seconds() / 3600
                    if response_time <= 72:  # 72 hours GDPR requirement
                        timely_responses += 1
            response_score = (timely_responses / breaches.count() * 100)
            
            # Check notification compliance
            notification_required = breaches.filter(severity__in=['high', 'critical'])
            if notification_required.exists():
                properly_notified = notification_required.filter(
                    authority_notified=True,
                    users_notified=True
                ).count()
                notification_score = (properly_notified / notification_required.count() * 100)
            else:
                notification_score = 100
                
            # Check resolution rate
            resolved = breaches.filter(resolved=True).count()
            resolution_score = (resolved / breaches.count() * 100)
            
            # Check documentation quality
            well_documented = breaches.exclude(
                Q(remediation_steps='') |
                Q(impact_assessment='') |
                Q(containment_measures=[])
            ).count()
            documentation_score = (well_documented / breaches.count() * 100)
            
            # Calculate weighted score
            total_score = (
                response_score * weights['response_time'] +
                notification_score * weights['notification_compliance'] +
                resolution_score * weights['resolution_rate'] +
                documentation_score * weights['documentation_quality']
            )
        else:
            total_score = 100  # No breaches is good
            
        return round(total_score)
    except Exception as e:
        logger.error(f"Error calculating breach management score: {str(e)}")
        return 0

def calculate_third_party_score():
    """Calculate third party compliance score."""
    try:
        total_score = 0
        weights = {
            'transfer_compliance': 0.5,
            'documentation': 0.5
        }
        
        transfers = CrossBorderTransfer.objects.all()
        if transfers.exists():
            # Check transfer mechanism compliance
            compliant_transfers = transfers.filter(
                Q(transfer_mechanism__in=['scc', 'bcr', 'adequacy']) |
                Q(adequacy_assessment__isnull=False)
            ).count()
            transfer_score = (compliant_transfers / transfers.count() * 100)
            
            # Check documentation completeness
            documented_transfers = transfers.exclude(
                Q(safeguards='') |
                Q(transfer_impact_assessment='') |
                Q(supplementary_measures='')
            ).count()
            documentation_score = (documented_transfers / transfers.count() * 100)
            
            # Calculate weighted score
            total_score = (
                transfer_score * weights['transfer_compliance'] +
                documentation_score * weights['documentation']
            )
        else:
            total_score = 100  # No transfers is compliant by default
            
        return round(total_score)
    except Exception as e:
        logger.error(f"Error calculating third party score: {str(e)}")
        return 0

def calculate_staff_training_score():
    """Calculate staff training compliance score."""
    try:
        # This is a placeholder since we don't have a training model yet
        # In a real implementation, you would:
        # 1. Track staff training completion
        # 2. Monitor training effectiveness
        # 3. Check regular updates and refresher courses
        # 4. Verify role-specific training compliance
        
        # For now, return a default score
        # TODO: Implement actual staff training tracking
        return 85
    except Exception as e:
        logger.error(f"Error calculating staff training score: {str(e)}")
        return 0

def calculate_risk_level():
    """Calculate the overall risk level based on various factors"""
    try:
        # Get recent data breaches
        recent_breaches = DataBreach.objects.filter(
            date_reported__gte=timezone.now() - timedelta(days=90)
        )
        
        # Calculate risk factors
        high_severity_breaches = recent_breaches.filter(severity__in=['high', 'critical']).count()
        unnotified_breaches = recent_breaches.filter(
            authority_notified=False,
            date_reported__lte=timezone.now() - timedelta(hours=72)
        ).count()
        unresolved_breaches = recent_breaches.filter(resolved=False).count()
        
        # Calculate risk score
        risk_score = 0
        if high_severity_breaches > 0:
            risk_score += 40
        if unnotified_breaches > 0:
            risk_score += 30
        if unresolved_breaches > 0:
            risk_score += 30
            
        # Determine risk level
        if risk_score >= 70:
            return 'high'
        elif risk_score >= 40:
            return 'medium'
        else:
            return 'low'
            
    except Exception as e:
        logger.error(f"Error calculating risk level: {str(e)}")
        return 'unknown'

def get_status_class(status):
    """Get Bootstrap class for status badge."""
    return {
        'completed': 'success',
        'pending': 'warning',
        'failed': 'danger'
    }.get(status, 'secondary')

def get_priority_class(priority):
    """Get Bootstrap class for priority badge."""
    return {
        'high': 'danger',
        'medium': 'warning',
        'low': 'info'
    }.get(priority, 'secondary')

@login_required
@role_required('admin', 'compliance_officer', 'dpo', 'user')
def dpo_dashboard(request):
    """
    Display the Data Protection Officer dashboard with breach monitoring and data processing activities.
    """
    # Get active breaches and transfers
    active_breaches = DataBreach.objects.filter(status='active').count()
    pending_transfers = DataTransfer.objects.filter(status='pending').count()
    processing_activities = DataProcessingActivity.objects.filter(is_active=True).count()
    risk_level = calculate_risk_level()

    # Get recent breaches with formatted data
    recent_breaches = [
            {
                'id': breach.id,
            'reported_date': breach.date_reported,
            'type': breach.get_breach_type_display(),
            'affected_users': breach.affected_users,
                'status': breach.get_status_display(),
                'status_class': get_breach_status_class(breach.status)
            }
        for breach in DataBreach.objects.all().order_by('-date_reported')[:10]
    ]

    # Get processing activities with formatted data
    processing_activities_list = [
            {
                'name': activity.name,
                'purpose': activity.purpose,
            'data_categories': activity.data_categories,
            'status': 'Active' if activity.is_active else 'Inactive',
            'status_class': 'success' if activity.is_active else 'secondary'
        }
        for activity in DataProcessingActivity.objects.filter(is_active=True).order_by('-created_at')[:5]
    ]

    # Get pending transfers with formatted data
    pending_transfers_list = [
        {
            'destination': transfer.destination_system,
            'data_type': transfer.data_categories,
            'transfer_date': transfer.created_at,
            'status': transfer.status,
                'status_class': get_transfer_status_class(transfer.status)
            }
        for transfer in DataTransfer.objects.filter(status='pending').order_by('created_at')[:5]
    ]

    context = {
        'active_breaches': active_breaches,
        'pending_transfers': pending_transfers,
        'processing_activities': processing_activities,
        'risk_level': risk_level,
        'recent_breaches': recent_breaches,
        'processing_activities_list': processing_activities_list,
        'pending_transfers_list': pending_transfers_list,
    }

    return render(request, 'dpo_templates/dpo_dashboard.html', context)

def get_breach_status_class(status):
    """Get Bootstrap class for breach status badge."""
    return {
        'active': 'danger',
        'investigating': 'warning',
        'resolved': 'success',
        'reported': 'info'
    }.get(status, 'secondary')

def get_activity_status_class(status):
    """Get Bootstrap class for processing activity status badge."""
    return {
        'active': 'success',
        'pending': 'warning',
        'suspended': 'danger',
        'archived': 'secondary'
    }.get(status, 'secondary')

def get_transfer_status_class(status):
    """Get Bootstrap class for transfer status badge."""
    return {
        'pending': 'warning',
        'approved': 'success',
        'rejected': 'danger',
        'completed': 'info'
    }.get(status, 'secondary')

@login_required
@role_required('admin', 'compliance_officer', 'dpo', 'user')
def audit_logs(request):
    """
    Display and filter audit logs with export capability.
    """
    # Get filter parameters
    action = request.GET.get('action')
    user_query = request.GET.get('user')
    date_from = request.GET.get('date_from')
    date_to = request.GET.get('date_to')
    resource_type = request.GET.get('resource_type')
    status = request.GET.get('status')
    ip_address = request.GET.get('ip_address')

    # Base queryset
    logs = AuditLog.objects.all().order_by('-timestamp')

    # Apply filters
    if action:
        logs = logs.filter(action=action)
    if user_query:
        logs = logs.filter(Q(user__email__icontains=user_query) | Q(user__username__icontains=user_query))
    if date_from:
        logs = logs.filter(timestamp__gte=date_from)
    if date_to:
        logs = logs.filter(timestamp__lte=date_to)
    if resource_type:
        logs = logs.filter(resource_type=resource_type)
    if status:
        logs = logs.filter(status=status)
    if ip_address:
        logs = logs.filter(ip_address__icontains=ip_address)

    # Pagination
    paginator = Paginator(logs, 20)  # Show 20 logs per page
    page = request.GET.get('page')
    try:
        audit_logs = paginator.page(page)
    except PageNotAnInteger:
        audit_logs = paginator.page(1)
    except EmptyPage:
        audit_logs = paginator.page(paginator.num_pages)

    # Prepare logs for display
    for log in audit_logs:
        log.status_class = get_log_status_class(log.status)

    context = {
        'audit_logs': audit_logs,
        'available_actions': AuditLog.ACTION_CHOICES,
        'available_resource_types': AuditLog.RESOURCE_TYPE_CHOICES,
        'available_statuses': AuditLog.STATUS_CHOICES
    }

    return render(request, 'compliance_officer_templates/audit_logs.html', context)

@login_required
@role_required('admin', 'compliance_officer', 'dpo', 'user')
def export_audit_logs(request):
    """
    Export filtered audit logs as CSV.
    """
    # Get filter parameters (same as audit_logs view)
    action = request.GET.get('action')
    user_query = request.GET.get('user')
    date_from = request.GET.get('date_from')
    date_to = request.GET.get('date_to')
    resource_type = request.GET.get('resource_type')
    status = request.GET.get('status')
    ip_address = request.GET.get('ip_address')

    # Base queryset
    logs = AuditLog.objects.all().order_by('-timestamp')

    # Apply filters (same as audit_logs view)
    if action:
        logs = logs.filter(action=action)
    if user_query:
        logs = logs.filter(Q(user__email__icontains=user_query) | Q(user__username__icontains=user_query))
    if date_from:
        logs = logs.filter(timestamp__gte=date_from)
    if date_to:
        logs = logs.filter(timestamp__lte=date_to)
    if resource_type:
        logs = logs.filter(resource_type=resource_type)
    if status:
        logs = logs.filter(status=status)
    if ip_address:
        logs = logs.filter(ip_address__icontains=ip_address)

    # Create the HttpResponse object with CSV header
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="audit_logs.csv"'

    # Create CSV writer
    writer = csv.writer(response)
    writer.writerow([
        'Timestamp',
        'User',
        'Action',
        'Resource Type',
        'Resource ID',
        'IP Address',
        'User Agent',
        'Status',
        'Details'
    ])

    # Write data
    for log in logs:
        writer.writerow([
            log.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            log.user.email,
            log.get_action_display(),
            log.resource_type,
            log.resource_id,
            log.ip_address,
            log.user_agent,
            log.get_status_display(),
            json.dumps(log.details)
        ])

    return response

def get_log_status_class(status):
    """Get Bootstrap class for log status badge."""
    return {
        'success': 'success',
        'error': 'danger',
        'warning': 'warning',
        'info': 'info'
    }.get(status, 'secondary')

@login_required
@role_required('admin', 'compliance_officer', 'dpo', 'user')
def manage_breaches(request):
    """View for managing data breaches."""
    try:
        breaches = DataBreach.objects.all().order_by('-date_reported')
        can_change = request.user.has_perm('gdpr_platform.change_databreach')

        context = {
            'breaches': breaches,
            'page_title': _('Manage Data Breaches'),
            'active_section': 'breaches',
            'can_change': can_change
        }

        return render(request, 'dpo_templates/manage_breaches.html', context)
    except Exception as e:
        logger.error(f"Error in manage breaches view: {str(e)}")
        messages.error(request, _('An error occurred while loading the breaches.'))
        return redirect('gdpr_platform:dashboard')

@login_required
@role_required('admin', 'compliance_officer', 'dpo', 'user')
def breach_details(request, breach_id):
    """Get detailed information about a specific breach."""
    try:
        breach = DataBreach.objects.get(id=breach_id)
        timeline = breach.timeline.all().order_by('-created_at')

        data = {
            'id': breach.id,
            'type_display': breach.get_type_display(),
            'severity_display': breach.get_severity_display(),
            'severity_class': get_severity_class(breach.severity),
            'description': breach.description,
            'affected_data_display': breach.get_affected_data_display(),
            'affected_users_count': breach.affected_users_count,
            'detection_date': breach.detection_date.isoformat(),
            'reported_date': breach.reported_date.isoformat(),
            'status_display': breach.get_status_display(),
            'status_class': get_breach_status_class(breach.status),
            'requires_notification': breach.requires_notification,
            'timeline': [
                {
                    'timestamp': event.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                    'description': event.description,
                    'user': event.created_by.get_full_name() or event.created_by.email
                }
                for event in timeline
            ]
        }

        if breach.resolution_date:
            response_time = (breach.resolution_date - breach.reported_date).total_seconds() / 3600
            data['response_time'] = round(response_time, 1)
        else:
            data['response_time'] = '-'

        return JsonResponse(data)

    except DataBreach.DoesNotExist:
        return JsonResponse({'error': 'Breach not found'}, status=404)
    except Exception as e:
        logger.error(f"Error fetching breach details: {str(e)}")
        return JsonResponse({'error': 'Internal server error'}, status=500)

@shared_task
def notify_breach_affected_users(breach_id, status):
    """Send notifications to users affected by a data breach."""
    try:
        breach = DataBreach.objects.get(id=breach_id)
        affected_users = User.objects.filter(id__in=breach.affected_users)

        for user in affected_users:
            send_breach_notification_email.delay(
                user.id,
                breach.id,
                status
            )

        logger.info(f"Sent breach notifications to {affected_users.count()} users for breach {breach_id}")

    except DataBreach.DoesNotExist:
        logger.error(f"Breach {breach_id} not found when sending notifications")
    except Exception as e:
        logger.error(f"Error sending breach notifications: {str(e)}")

@shared_task
def send_breach_notification_email(user_id, breach_id, status):
    """Send email notification about a data breach to a specific user."""
    try:
        user = User.objects.get(id=user_id)
        breach = DataBreach.objects.get(id=breach_id)

        context = {
            'user': user,
            'breach': breach,
            'status': status,
            'platform_name': get_platform_name()
        }

        send_email_template(
            subject=_("Important: Data Breach Notification"),
            template='emails/data_breach_notification.html',
            context=context,
            to_email=user.email
        )

        logger.info(f"Sent breach notification email to user {user_id} for breach {breach_id}")

    except (User.DoesNotExist, DataBreach.DoesNotExist):
        logger.error(f"User {user_id} or breach {breach_id} not found when sending email")
    except Exception as e:
        logger.error(f"Error sending breach notification email: {str(e)}")

@login_required
@role_required('admin', 'compliance_officer', 'dpo')
def processing_overview(request):
    """
    View for displaying an overview of data processing activities.
    """
    # Get processing statistics
    active_processes = DataProcessingActivity.objects.filter(status='active').count()
    high_risk_activities = DataProcessingActivity.objects.filter(risk_level='high').count()
    data_categories = DataCategory.objects.count()
    
    # Calculate compliance score based on completed requirements
    total_requirements = ProcessingRequirement.objects.count()
    completed_requirements = ProcessingRequirement.objects.filter(status='completed').count()
    compliance_score = int((completed_requirements / total_requirements * 100) if total_requirements > 0 else 0)
    
    # Get recent activities with pagination
    recent_activities = DataProcessingActivity.objects.all().order_by('-start_date')[:10]
    
    # Prepare chart data
    category_data = []
    category_labels = []
    for category in DataCategory.objects.all():
        count = DataProcessingActivity.objects.filter(data_categories=category).count()
        if count > 0:
            category_data.append(count)
            category_labels.append(str(category.name))
    
    legal_basis_data = []
    legal_basis_labels = []
    for basis, label in DataProcessingActivity.LEGAL_BASIS_CHOICES:
        count = DataProcessingActivity.objects.filter(legal_basis=basis).count()
        if count > 0:
            legal_basis_data.append(count)
            legal_basis_labels.append(str(label))
    
    context = {
        'active_processes': active_processes,
        'high_risk_activities': high_risk_activities,
        'data_categories': data_categories,
        'compliance_score': compliance_score,
        'recent_activities': recent_activities,
        'category_data': json.dumps(category_data),
        'category_labels': json.dumps(category_labels),
        'legal_basis_data': json.dumps(legal_basis_data),
        'legal_basis_labels': json.dumps(legal_basis_labels),
    }
    
    return render(request, 'compliance_officer_templates/processing_overview.html', context)

@login_required
@role_required('admin', 'compliance_officer', 'dpo')
def processing_activities(request):
    """
    View for managing data processing activities.
    """
    # Get filter parameters
    category = request.GET.get('category')
    legal_basis = request.GET.get('legal_basis')
    risk_level = request.GET.get('risk_level')
    status = request.GET.get('status')
    
    # Base queryset
    activities = DataProcessingActivity.objects.all()
    
    # Apply filters
    if category:
        activities = activities.filter(category_id=category)
    if legal_basis:
        activities = activities.filter(legal_basis=legal_basis)
    if risk_level:
        activities = activities.filter(risk_level=risk_level)
    if status:
        activities = activities.filter(status=status)
    
    # Order by latest first
    activities = activities.order_by('-start_date')
    
    # Pagination
    paginator = Paginator(activities, 10)
    page = request.GET.get('page')
    activities = paginator.get_page(page)
    
    # Get categories and legal bases for filters
    categories = DataCategory.objects.all()
    legal_bases = DataProcessingActivity.LEGAL_BASIS_CHOICES
    
    context = {
        'activities': activities,
        'categories': categories,
        'legal_bases': legal_bases,
        'selected_category': category,
        'selected_basis': legal_basis,
        'selected_risk': risk_level,
        'selected_status': status,
        'data_categories': DataCategory.objects.all(),
    }
    
    return render(request, 'compliance_officer_templates/processing_activities.html', context)

@login_required
@role_required('admin', 'compliance_officer', 'dpo', 'user')
def data_requests_overview(request):
    """View for displaying and managing data requests"""
    # Get all data requests
    data_requests = DataRequest.objects.all()
    
    # Calculate statistics
    total_requests = data_requests.count()
    pending_requests = data_requests.filter(status='pending').count()
    completed_requests = data_requests.filter(status='completed').count()
    
    # Calculate average response time using ExpressionWrapper
    avg_response_time = data_requests.filter(
        completion_date__isnull=False
    ).annotate(
        response_time=ExpressionWrapper(
            F('completion_date') - F('request_date'),
            output_field=DurationField()
        )
    ).aggregate(
        avg_time=Avg('response_time')
    )['avg_time']
    
    # Get unique values for filters
    status_choices = DataRequest.STATUS_CHOICES
    request_type_choices = DataRequest.REQUEST_TYPES
    
    context = {
        'requests': data_requests,
        'stats': {
            'total': total_requests,
            'pending': pending_requests,
            'completed': completed_requests,
            'avg_response_days': avg_response_time.days if avg_response_time else 0
        },
        'filters': {
            'status_choices': status_choices,
            'request_type_choices': request_type_choices
        }
    }
    
    return render(request, 'compliance_officer_templates/data_requests_overview.html', context)

@login_required
@role_required('admin', 'compliance_officer', 'dpo', 'user')
def manage_privacy_policy(request):
    """View for managing privacy policy versions and updates"""
    if request.method == 'POST':
        action = request.POST.get('action')
        
        if action == 'create':
            try:
                version = request.POST.get('version')
                content = request.POST.get('content')
                effective_date = request.POST.get('effective_date')
                
                # Create new privacy policy version
                policy = PrivacyPolicy.objects.create(
                    version=version,
                    content=content,
                    effective_date=timezone.make_aware(datetime.strptime(effective_date, '%Y-%m-%d')),
                    created_by=request.user
                )
                
                # Log the action
                ActivityLog.objects.create(
                    user=request.user,
                    action='privacy_policy_created',
                    resource_type='privacy_policy',
                    resource_id=str(policy.id),
                    details={'version': version}
                )
                
                messages.success(request, 'New privacy policy version created successfully.')
                
            except Exception as e:
                messages.error(request, f'Error creating privacy policy: {str(e)}')
        
        elif action == 'activate':
            try:
                policy_id = request.POST.get('policy_id')
                policy = get_object_or_404(PrivacyPolicy, id=policy_id)
                
                # Deactivate all other versions
                PrivacyPolicy.objects.all().update(is_active=False)
                
                # Activate selected version
                policy.is_active = True
                policy.save()
                
                # Log the action
                ActivityLog.objects.create(
                    user=request.user,
                    action='privacy_policy_activated',
                    resource_type='privacy_policy',
                    resource_id=str(policy.id),
                    details={'version': policy.version}
                )
                
                messages.success(request, f'Privacy policy version {policy.version} activated.')
                
            except Exception as e:
                messages.error(request, f'Error activating privacy policy: {str(e)}')
    
    # Get all privacy policy versions
    policies = PrivacyPolicy.objects.all().order_by('-effective_date')
    active_policy = PrivacyPolicy.objects.filter(is_active=True).first()
    
    context = {
        'policies': policies,
        'active_policy': active_policy,
        'page_title': 'Manage Privacy Policy',
        'section': 'privacy'
    }
    
    return render(request, 'gdpr/manage_privacy_policy.html', context)

@login_required
@role_required('admin', 'compliance_officer', 'dpo', 'user')
def data_breach_notifications(request):
    """Handle data breach notifications view"""
    try:
        # Get notifications for the user
        notifications = BreachNotification.objects.filter(
            recipient=request.user
        ).select_related('breach').order_by('-created_at')

        # Get unacknowledged notifications count
        unacknowledged_count = notifications.filter(status='pending').count()
    
        context = {
                    'notifications': notifications,
                    'unacknowledged_count': unacknowledged_count,
                    'title': _('Data Breach Notifications')
        }
        
        return render(request, 'dpo_templates/breach_notifications.html', context)

    except Exception as e:
        logger.error(f"Error in data breach notifications view: {str(e)}")
        messages.error(request, _('An error occurred loading notifications.'))
        return redirect('gdpr_platform:dashboard')

@login_required
@role_required('admin', 'compliance_officer', 'dpo', 'user')
def compliance_reports(request):
    """View for generating and managing compliance reports"""
    
    # Get report filters from request
    report_type = request.GET.get('type', 'all')
    start_date = request.GET.get('start_date')
    end_date = request.GET.get('end_date')
    
    # Initialize base reports queryset
    reports = {
        'data_breaches': DataBreach.objects.all(),
        'data_requests': DataRequest.objects.all(),
        'processing_activities': DataProcessingActivity.objects.all(),
        'cross_border_transfers': CrossBorderTransfer.objects.all(),
        'consent_records': ConsentRecord.objects.all()
    }
    
    # Apply date filters if provided
    if start_date and end_date:
        try:
            start = timezone.make_aware(datetime.strptime(start_date, '%Y-%m-%d'))
            end = timezone.make_aware(datetime.strptime(end_date, '%Y-%m-%d'))
            
            reports['data_breaches'] = reports['data_breaches'].filter(date_reported__range=[start, end])
            reports['data_requests'] = reports['data_requests'].filter(request_date__range=[start, end])
            reports['processing_activities'] = reports['processing_activities'].filter(created_at__range=[start, end])
            reports['cross_border_transfers'] = reports['cross_border_transfers'].filter(transfer_date__range=[start, end])
            reports['consent_records'] = reports['consent_records'].filter(granted_at__range=[start, end])
        except ValueError:
            messages.error(request, 'Invalid date format. Please use YYYY-MM-DD.')
    
    # Calculate statistics
    stats = {
        'data_breaches': {
            'total': reports['data_breaches'].count(),
            'critical': reports['data_breaches'].filter(severity='critical').count(),
            'high': reports['data_breaches'].filter(severity='high').count(),
            'resolved': reports['data_breaches'].filter(status='resolved').count()
        },
        'data_requests': {
            'total': reports['data_requests'].count(),
            'pending': reports['data_requests'].filter(status='pending').count(),
            'completed': reports['data_requests'].filter(status='completed').count(),
            'overdue': len([r for r in reports['data_requests'].all() if r.is_overdue()])
        },
        'processing_activities': {
            'total': reports['processing_activities'].count(),
            'high_risk': reports['processing_activities'].filter(risk_level='high').count(),
            'dpia_required': reports['processing_activities'].filter(dpia_required=True).count()
        },
        'transfers': {
            'total': reports['cross_border_transfers'].count(),
            'active': reports['cross_border_transfers'].filter(status='active').count(),
            'expired': reports['cross_border_transfers'].filter(status='expired').count()
        },
        'consent': {
            'total': reports['consent_records'].count(),
            'active': reports['consent_records'].filter(status='active').count(),
            'withdrawn': reports['consent_records'].filter(status='withdrawn').count()
        }
    }
    
    # Calculate compliance scores
    compliance_scores = {
        'overall': calculate_compliance_score(),
        'data_protection': calculate_data_protection_score(),
        'user_rights': calculate_user_rights_score(),
        'documentation': calculate_documentation_score(),
        'breach_management': calculate_breach_management_score(),
        'third_party': calculate_third_party_score(),
        'staff_training': calculate_staff_training_score()
    }
    
    context = {
        'reports': reports,
        'stats': stats,
        'compliance_scores': compliance_scores,
        'report_type': report_type,
        'start_date': start_date,
        'end_date': end_date
    }
    
    # Handle export request
    if request.GET.get('export'):
        format = request.GET.get('format', 'pdf')
        return export_compliance_report(context, format)
    
    return render(request, 'gdpr/compliance_reports.html', context)

@login_required
@role_required('admin', 'dpo', 'compliance_officer', 'user')
def user_dashboard(request):
    """Display user's dashboard with GDPR information"""
    try:
        # Get user's data requests, ordered by request date
        user_requests = DataRequest.objects.filter(user=request.user).order_by('-request_date')
        
        # Get latest cookie consent
        cookie_consent = CookieConsent.objects.filter(user=request.user).order_by('-timestamp').first()
        
        # Get breach notifications for the user
        breach_notifications = BreachNotification.objects.filter(
            recipient=request.user,
            status__in=['pending', 'sent']
        ).order_by('-created_at')
        
        # Prepare context with user data
        context = {
            'title': _('Dashboard'),
            'user': request.user,
            'user_requests': user_requests,
            'cookie_consent': cookie_consent,
            'two_factor_enabled': request.user.two_factor_enabled,
            'recent_activity': ActivityLog.objects.filter(user=request.user).order_by('-timestamp')[:5],
            'active_sessions': UserSession.objects.filter(user=request.user, is_active=True).order_by('-last_activity'),
            'breach_notifications': breach_notifications,
            'data_processing': DataProcessingActivity.objects.filter(
                processor=request.user,
                is_active=True
            ).order_by('-created_at'),
            'retention_settings': request.user.data_retention_policy,
            'open_tickets': SupportTicket.objects.filter(
                user=request.user,
                status__in=['open', 'in_progress']
            ).order_by('-created_at'),
            'user_rights': {
                'access': True,
                'rectification': True,
                'erasure': True,
                'portability': True,
                'object': True,
                'restrict_processing': True
            }
        }
        
        return render(request, 'user_templates/dashboard.html', context)
            
    except Exception as e:
        logger.error(f"Dashboard error for user {request.user.id}: {str(e)}")
        messages.error(request, _('An error occurred loading your dashboard. Please try again later.'))
        return render(request, 'user_templates/dashboard.html', {
            'error': True,
            'title': 'Dashboard',
            'user': request.user
        })

@login_required
def update_marketing_preferences(request):
    """Update user's marketing preferences."""
    if request.method == 'POST':
        try:
            # Get the preferences from the form
            preferences = {
                'email_marketing': request.POST.get('email_marketing') == 'on',
                'product_updates': request.POST.get('product_updates') == 'on',
                'third_party_marketing': request.POST.get('third_party_marketing') == 'on',
                'communication_frequency': request.POST.get('communication_frequency', 'monthly')
            }
            
            # Update the user's marketing preferences
            request.user.marketing_preferences = preferences
            request.user.save()
            
            # Create an audit log entry
            AuditLog.objects.create(
                user=request.user,
                action='update_marketing_preferences',
                resource_type='marketing_preferences',
                resource_id=str(request.user.id),
                ip_address=request.META.get('REMOTE_ADDR'),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                details=json.dumps(preferences)
            )
            
            messages.success(request, _('Marketing preferences updated successfully.'))
            return JsonResponse({'status': 'success'})
            
        except Exception as e:
            logger.error(f"Error updating marketing preferences: {str(e)}")
            messages.error(request, _('An error occurred while updating your marketing preferences.'))
            return JsonResponse({'status': 'error'}, status=400)
            
    return JsonResponse({'status': 'error', 'message': 'Method not allowed'}, status=405)

@login_required
@role_required('admin', 'compliance_officer', 'dpo', 'user')
def acknowledge_breach(request, notification_id):
    """Handle breach notification acknowledgment."""
    try:
        notification = BreachNotification.objects.get(
            id=notification_id,
            recipient=request.user,
            status__in=['pending', 'sent']
        )
        
        # Update notification status
        notification.status = 'acknowledged'
        notification.acknowledged_at = timezone.now()
        notification.save()
        
        # Create audit log entry
        AuditLog.objects.create(
            user=request.user,
            action='acknowledge_breach',
            resource_type='breach_notification',
            resource_id=str(notification_id),
            ip_address=request.META.get('REMOTE_ADDR'),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            details=json.dumps({
                'breach_id': str(notification.breach.id),
                'acknowledged_at': notification.acknowledged_at.isoformat()
            })
        )
        
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return JsonResponse({'status': 'success'})
        
        messages.success(request, _('Breach notification has been acknowledged.'))
        return redirect('gdpr_platform:dashboard')
        
    except BreachNotification.DoesNotExist:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return JsonResponse({'status': 'error', 'message': 'Notification not found'}, status=404)
        
        messages.error(request, _('Breach notification not found.'))
        return redirect('gdpr_platform:dashboard')
    
    except Exception as e:
        logger.error(f"Error acknowledging breach notification: {str(e)}")
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return JsonResponse({'status': 'error', 'message': 'An error occurred'}, status=500)
        
        messages.error(request, _('An error occurred while acknowledging the breach notification.'))
        return redirect('gdpr_platform:dashboard')

@login_required
def terminate_session(request):
    """Terminate a specific user session"""
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            session_id = data.get('session_id')
            
            # Get the session and verify it belongs to the user
            session = UserSession.objects.get(id=session_id, user=request.user)
            
            # Don't allow terminating current session through this endpoint
            if not session.is_current:
                session.end_session()
                
                # Log the action
                ActivityLog.objects.create(
                    user=request.user,
                    action_type='security',
                    action='terminate_session',
                    ip_address=request.META.get('REMOTE_ADDR'),
                    user_agent=request.META.get('HTTP_USER_AGENT'),
                    status='success',
                    details={'session_id': session_id}
                )
                
                return JsonResponse({'success': True})
            else:
                return JsonResponse({
                    'success': False,
                    'error': _('Cannot terminate current session')
                }, status=400)
                
        except UserSession.DoesNotExist:
            return JsonResponse({
                'success': False,
                'error': _('Session not found')
            }, status=404)
        except Exception as e:
            logger.error(f"Error terminating session: {str(e)}")
            return JsonResponse({
                'success': False,
                'error': _('An error occurred while terminating the session')
            }, status=500)
    
    return JsonResponse({
        'success': False,
        'error': _('Invalid request method')
    }, status=405)

def ensure_groups_exist():
    """Ensure all required groups exist in the database"""
    required_groups = ['admin', 'dpo', 'compliance_officer', 'user']
    for group_name in required_groups:
        Group.objects.get_or_create(name=group_name)

def ensure_dpo_permissions():
    """Ensure all DPO users have the required permissions"""
    try:
        dpo_role = Role.objects.get(name='dpo')
        required_permissions = [
            'view_processing',
            'view_databreach',
            'add_databreach',
            'change_databreach',
            'view_crossbordertransfer',
            'add_crossbordertransfer',
            'change_crossbordertransfer'
        ]
        
        # Get all required permissions
        permissions = Permission.objects.filter(codename__in=required_permissions)
        
        # Add permissions to DPO role
        dpo_role.permissions.add(*permissions)
        
        # Update all users with DPO role
        users_with_dpo = CustomUser.objects.filter(roles=dpo_role)
        for user in users_with_dpo:
            user.user_permissions.add(*permissions)
            
    except Exception as e:
        logger.error(f"Error ensuring DPO permissions: {str(e)}")

@login_required
def dashboard(request):
    """Main dashboard view that redirects to role-specific dashboards"""
    try:
        # Get user roles
        user_roles = request.user.roles.all().values_list('name', flat=True)
        
        # Check roles in order of priority
        if request.user.is_staff or request.user.is_superuser:
            return redirect('gdpr_platform:admin_dashboard')
        
        # Check roles in priority order
        if 'admin' in user_roles:
            return redirect('gdpr_platform:admin_dashboard')
        elif 'dpo' in user_roles:
            return redirect('gdpr_platform:dpo_dashboard')
        elif 'compliance_officer' in user_roles:
            return redirect('gdpr_platform:compliance_dashboard')
        elif 'user' in user_roles:
            return redirect('gdpr_platform:user_dashboard')
        else:
            # If no roles are assigned, assign default user role and redirect
            assign_default_role(request.user)
            return redirect('gdpr_platform:user_dashboard')
            
    except Exception as e:
        logger.error(f"Dashboard redirect error for user {request.user.id}: {str(e)}")
        messages.error(request, _('An error occurred. Please try again later.'))
        return redirect('gdpr_platform:landing')

@login_required
@role_required('admin', 'compliance_officer', 'dpo', 'user')
def request_details(request, request_id):
    """View for displaying details of a specific data request"""
    try:
        # Get the data request
        data_request = get_object_or_404(DataRequest, id=request_id)
        
        # Ensure users can only view their own requests unless they're admin/dpo/compliance_officer
        if not any(role in request.user.groups.values_list('name', flat=True) 
                  for role in ['admin', 'dpo', 'compliance_officer']) \
           and data_request.user != request.user:
            messages.error(request, _('You do not have permission to view this request.'))
            return redirect('gdpr_platform:user_dashboard')
        
        # Get related data
        context = {
            'data_request': data_request,
            'status_history': data_request.status_history.all().order_by('-created_at') if hasattr(data_request, 'status_history') else None,
            'documents': data_request.documents.all().order_by('-uploaded_at') if hasattr(data_request, 'documents') else None,
        }
        
        return render(request, 'user_templates/request_details.html', context)
        
    except DataRequest.DoesNotExist:
        messages.error(request, _('Request not found.'))
        return redirect('gdpr_platform:user_dashboard')
    except Exception as e:
        logger.error(f"Error viewing request details for {request_id}: {str(e)}")
        messages.error(request, _('An error occurred while loading the request details.'))
        return redirect('gdpr_platform:user_dashboard')

def assign_default_role(user):
    """Assign default role to user if they don't have any roles"""
    try:
        # If user is staff/superuser, assign admin role
        if user.is_staff or user.is_superuser:
            admin_role, _ = Role.objects.get_or_create(name='admin')
            user.roles.add(admin_role)
            logger.info(f"Assigned 'admin' role to user {user.id}")
            return

        # If user has no roles, assign 'user' role
        if not user.roles.exists():
            user_role, _ = Role.objects.get_or_create(name='user')
            user.roles.add(user_role)
            logger.info(f"Assigned 'user' role to user {user.id}")
    except Exception as e:
        logger.error(f"Error assigning default role to user {user.id}: {str(e)}")

@login_required
@role_required('admin', 'compliance_officer', 'dpo')
def generate_report(request):
    """Generate a compliance report based on specified parameters."""
    if request.method != 'POST':
        return JsonResponse({'error': 'Only POST method is allowed'}, status=405)

    try:
        report_type = request.POST.get('report_type')
        date_from = request.POST.get('date_from')
        date_to = request.POST.get('date_to')

        if not all([report_type, date_from, date_to]):
            return JsonResponse({'error': 'Missing required parameters'}, status=400)

        # Convert string dates to datetime objects
        date_from = datetime.strptime(date_from, '%Y-%m-%d')
        date_to = datetime.strptime(date_to, '%Y-%m-%d')

        # Generate report based on type
        if report_type == 'data_processing':
            data = generate_processing_report(date_from, date_to)
        elif report_type == 'data_breaches':
            data = generate_breaches_report(date_from, date_to)
        elif report_type == 'user_requests':
            data = generate_requests_report(date_from, date_to)
        elif report_type == 'consent_management':
            data = generate_consent_report(date_from, date_to)
        elif report_type == 'compliance_audit':
            data = generate_audit_report(date_from, date_to)
        else:
            return JsonResponse({'error': 'Invalid report type'}, status=400)

        # Create report record
        report = Report.objects.create(
            type=report_type,
            date_from=date_from,
            date_to=date_to,
            generated_by=request.user,
            data=data
        )

        return JsonResponse({
            'success': True,
            'report_id': str(report.id),
            'message': 'Report generated successfully'
        })

    except Exception as e:
        logger.error(f"Error generating report: {str(e)}")
        return JsonResponse({'error': 'Failed to generate report'}, status=500)

@login_required
@role_required('admin', 'compliance_officer', 'dpo')
def download_report(request, report_id):
    """Download a generated report."""
    try:
        report = Report.objects.get(id=report_id)
        
        # Create the response
        response = HttpResponse(content_type='application/pdf')
        response['Content-Disposition'] = f'attachment; filename="{report.type}_{report.date_from.date()}_{report.date_to.date()}.pdf"'
        
        # Generate PDF
        generate_report_pdf(report, response)
        
        return response
    except Report.DoesNotExist:
        return JsonResponse({'error': 'Report not found'}, status=404)
    except Exception as e:
        logger.error(f"Error downloading report: {str(e)}")
        return JsonResponse({'error': 'Failed to download report'}, status=500)

@login_required
@role_required('admin', 'compliance_officer', 'dpo')
def schedule_report(request):
    """Schedule a recurring report."""
    if request.method != 'POST':
        return JsonResponse({'error': 'Only POST method is allowed'}, status=405)

    try:
        report_type = request.POST.get('report_type')
        frequency = request.POST.get('frequency')
        recipients = request.POST.getlist('recipients')

        if not all([report_type, frequency, recipients]):
            return JsonResponse({'error': 'Missing required parameters'}, status=400)

        # Create schedule
        schedule = ReportSchedule.objects.create(
            report_type=report_type,
            frequency=frequency,
            created_by=request.user
        )
        schedule.recipients.set(recipients)

        return JsonResponse({
            'success': True,
            'schedule_id': str(schedule.id),
            'message': 'Report scheduled successfully'
        })

    except Exception as e:
        logger.error(f"Error scheduling report: {str(e)}")
        return JsonResponse({'error': 'Failed to schedule report'}, status=500)

@login_required
@role_required('admin', 'compliance_officer', 'dpo')
def delete_report(request):
    """Delete a generated report."""
    if request.method != 'POST':
        return JsonResponse({'error': 'Only POST method is allowed'}, status=405)

    try:
        data = json.loads(request.body)
        report_id = data.get('report_id')

        if not report_id:
            return JsonResponse({'error': 'Report ID is required'}, status=400)

        report = Report.objects.get(id=report_id)
        report.delete()

        return JsonResponse({
            'success': True,
            'message': 'Report deleted successfully'
        })

    except Report.DoesNotExist:
        return JsonResponse({'error': 'Report not found'}, status=404)
    except Exception as e:
        logger.error(f"Error deleting report: {str(e)}")
        return JsonResponse({'error': 'Failed to delete report'}, status=500)

# Helper functions for report generation
def generate_processing_report(date_from, date_to):
    """Generate report for data processing activities."""
    activities = DataProcessingActivity.objects.filter(
        created_at__range=(date_from, date_to)
    )
    return {
        'total_activities': activities.count(),
        'high_risk_activities': activities.filter(risk_level='high').count(),
        'requires_dpia': activities.filter(dpia_required=True).count(),
        'activities_by_type': {
            activity_type: activities.filter(processing_type=activity_type).count()
            for activity_type, _ in DataProcessingActivity.PROCESSING_TYPES
        }
    }

def generate_breaches_report(date_from, date_to):
    """Generate report for data breaches."""
    breaches = DataBreach.objects.filter(
        date_discovered__range=(date_from, date_to)
    )
    return {
        'total_breaches': breaches.count(),
        'resolved_breaches': breaches.filter(resolved=True).count(),
        'pending_notifications': breaches.filter(notification_sent_to_authorities=False).count(),
        'breaches_by_severity': {
            severity: breaches.filter(severity=severity).count()
            for severity, _ in DataBreach.SEVERITY_CHOICES
        }
    }

def generate_requests_report(date_from, date_to):
    """Generate report for user data requests."""
    requests = DataRequest.objects.filter(
        request_date__range=(date_from, date_to)
    )
    return {
        'total_requests': requests.count(),
        'completed_requests': requests.filter(status='completed').count(),
        'pending_requests': requests.filter(status='pending').count(),
        'requests_by_type': {
            request_type: requests.filter(request_type=request_type).count()
            for request_type, _ in DataRequest.REQUEST_TYPES
        }
    }

def generate_consent_report(date_from, date_to):
    """Generate report for consent management."""
    consents = ConsentRecord.objects.filter(
        granted_at__range=(date_from, date_to)
    )
    return {
        'total_consents': consents.count(),
        'active_consents': consents.filter(status='active').count(),
        'withdrawn_consents': consents.filter(status='withdrawn').count(),
        'consents_by_type': {
            consent_type: consents.filter(consent_type=consent_type).count()
            for consent_type, _ in ConsentRecord.CONSENT_TYPES
        }
    }

def generate_audit_report(date_from, date_to):
    """Generate compliance audit report."""
    audit_logs = AuditLog.objects.filter(
        timestamp__range=(date_from, date_to)
    )
    return {
        'total_events': audit_logs.count(),
        'events_by_action': {
            action: audit_logs.filter(action=action).count()
            for action in audit_logs.values_list('action', flat=True).distinct()
        },
        'events_by_resource': {
            resource: audit_logs.filter(resource_type=resource).count()
            for resource in audit_logs.values_list('resource_type', flat=True).distinct()
        }
    }

def generate_report_pdf(report, response):
    """Generate PDF version of the report."""
    # Implementation of PDF generation
    pass

@login_required
@require_POST
def delete_report_schedule(request):
    """Delete a report schedule"""
    try:
        schedule_id = request.POST.get('schedule_id')
        if not schedule_id:
            return JsonResponse({'error': 'Schedule ID is required'}, status=400)
            
        schedule = get_object_or_404(ReportSchedule, id=schedule_id)
        
        # Check if user has permission to delete this schedule
        if not (request.user.is_staff or request.user.is_superuser or schedule.created_by == request.user):
            return JsonResponse({'error': 'Permission denied'}, status=403)
            
        schedule.delete()
        return JsonResponse({'message': 'Report schedule deleted successfully'})
    except Exception as e:
        logger.error(f"Error deleting report schedule: {str(e)}")
        return JsonResponse({'error': 'Failed to delete report schedule'}, status=500)

@login_required
@role_required('admin', 'compliance_officer', 'dpo')
def get_report_schedule(request):
    """Get report schedules for the current user"""
    try:
        # Get all schedules for the user or all schedules for staff
        if request.user.is_staff or request.user.is_superuser:
            schedules = ReportSchedule.objects.all()
        else:
            schedules = ReportSchedule.objects.filter(created_by=request.user)
            
        schedules_data = []
        for schedule in schedules:
            schedules_data.append({
                'id': schedule.id,
                'report_type': schedule.report_type,
                'frequency': schedule.frequency,
                'next_run': schedule.next_run.isoformat() if schedule.next_run else None,
                'last_run': schedule.last_run.isoformat() if schedule.last_run else None,
                'created_at': schedule.created_at.isoformat(),
                'created_by': schedule.created_by.email,
                'is_active': schedule.is_active
            })
            
        return JsonResponse({'schedules': schedules_data})
    except Exception as e:
        logger.error(f"Error fetching report schedules: {str(e)}")
        return JsonResponse({'error': 'Failed to fetch report schedules'}, status=500)

def calculate_security_score():
    """Calculate security measures compliance score."""
    try:
        weights = {
            'encryption': 0.25,
            'access_control': 0.25,
            'monitoring': 0.25,
            'incident_response': 0.25
        }
        
        # Check encryption measures
        encryption_score = 100  # Base score
        try:
            # Check if sensitive fields are encrypted
            if not EncryptedField.objects.exists():
                encryption_score -= 30
            
            # Check if data transfers use encryption
            transfers = DataTransfer.objects.exclude(encryption_method='none')
            if transfers.exists():
                encrypted_transfers = transfers.filter(encryption_method__in=['tls', 'ssl', 'pgp', 'aes']).count()
                encryption_score = (encrypted_transfers / transfers.count() * 100)
        except:
            encryption_score = 50  # Default if checks fail
        
        # Check access control measures
        access_score = 100  # Base score
        try:
            # Check 2FA adoption
            total_users = CustomUser.objects.filter(is_active=True).count()
            if total_users > 0:
                users_with_2fa = TwoFactorAuth.objects.filter(is_enabled=True).count()
                access_score = (users_with_2fa / total_users * 100)
            
            # Penalize if there are users without proper roles
            users_without_roles = CustomUser.objects.filter(roles__isnull=True).count()
            if users_without_roles > 0:
                access_score -= (users_without_roles / total_users * 20)
        except:
            access_score = 50  # Default if checks fail
        
        # Check monitoring measures
        monitoring_score = 100  # Base score
        try:
            # Check if audit logging is active
            recent_logs = AuditLog.objects.filter(
                timestamp__gte=timezone.now() - timedelta(days=7)
            ).exists()
            if not recent_logs:
                monitoring_score -= 50
            
            # Check if activity monitoring is in place
            recent_activity = ActivityLog.objects.filter(
                timestamp__gte=timezone.now() - timedelta(days=7)
            ).exists()
            if not recent_activity:
                monitoring_score -= 30
        except:
            monitoring_score = 50  # Default if checks fail
        
        # Check incident response measures
        response_score = 100  # Base score
        try:
            # Check breach response time
            recent_breaches = DataBreach.objects.filter(
                date_discovered__gte=timezone.now() - timedelta(days=90)
            )
            if recent_breaches.exists():
                timely_responses = 0
                for breach in recent_breaches:
                    if breach.date_reported and breach.date_discovered:
                        response_time = (breach.date_reported - breach.date_discovered).total_seconds() / 3600
                        if response_time <= 72:  # 72 hours GDPR requirement
                            timely_responses += 1
                response_score = (timely_responses / recent_breaches.count() * 100)
        except:
            response_score = 50  # Default if checks fail
        
        # Calculate weighted score
        total_score = (
            encryption_score * weights['encryption'] +
            access_score * weights['access_control'] +
            monitoring_score * weights['monitoring'] +
            response_score * weights['incident_response']
        )
        
        return round(total_score)
    except Exception as e:
        logger.error(f"Error calculating security score: {str(e)}")
        return 0

@login_required
def remove_trusted_device(request, device_id):
    """Remove a trusted device"""
    try:
        device = TrustedDevice.objects.get(id=device_id, user=request.user)
        device.delete()
        
        # Log the action
        ActivityLog.objects.create(
            user=request.user,
            action_type='security',
            action='remove_trusted_device',
            ip_address=request.META.get('REMOTE_ADDR'),
            user_agent=request.META.get('HTTP_USER_AGENT'),
            status='success',
            details={'device_id': device_id}
        )
        
        messages.success(request, _('Device has been removed from trusted devices.'))
    except TrustedDevice.DoesNotExist:
        messages.error(request, _('Device not found.'))
    except Exception as e:
        logger.error(f"Error removing trusted device for user {request.user.id}: {str(e)}")
        messages.error(request, _('An error occurred while removing the device.'))
    
    return redirect('gdpr_platform:trusted_devices')

@login_required
@role_required('admin', 'compliance_officer', 'dpo', 'user')
def security_overview(request):
    """Display security overview with user's security settings and status"""
    try:
        # Get user's security status
        two_factor_enabled = hasattr(request.user, 'totp_device')
        
        # Get active sessions
        active_sessions = UserSession.objects.filter(
            user=request.user,
            is_active=True
        ).order_by('-last_activity')
        
        # Get trusted devices
        trusted_devices = TrustedDevice.objects.filter(
            user=request.user,
            expires_at__gt=timezone.now()
        ).order_by('-last_used')
        
        # Get recent security-related activity
        security_logs = ActivityLog.objects.filter(
            user=request.user,
            action_type__in=['login', 'password', '2fa', 'security']
        ).order_by('-timestamp')[:10]
        
        context = {
            'title': _('Security Overview'),
            'two_factor_enabled': two_factor_enabled,
            'active_sessions': active_sessions,
            'trusted_devices': trusted_devices,
            'security_logs': security_logs,
            'last_password_change': request.user.last_password_change if hasattr(request.user, 'last_password_change') else None,
            'password_expiry_date': request.user.password_expiry_date if hasattr(request.user, 'password_expiry_date') else None,
        }
        
        return render(request, 'security/overview.html', context)
        
    except Exception as e:
        logger.error(f"Security overview error for user {request.user.id}: {str(e)}")
        messages.error(request, _('An error occurred loading the security overview.'))
        return redirect('gdpr_platform:dashboard')

@login_required
def two_factor_auth(request):
    """
    View for managing two-factor authentication settings.
    """
    try:
        # Get user's 2FA status
        two_factor_enabled = hasattr(request.user, 'two_factor_auth') and request.user.two_factor_auth.is_enabled
        
        # Get backup codes if 2FA is enabled
        backup_codes = None
        if two_factor_enabled:
            backup_codes = request.user.two_factor_auth.get_backup_codes()
        
        # Get QR code for setup if 2FA is not enabled
        qr_code = None
        if not two_factor_enabled:
            qr_code = generate_qr_code(request.user)
        
        context = {
            'title': _('Two-Factor Authentication'),
            'two_factor_enabled': two_factor_enabled,
            'backup_codes': backup_codes,
            'qr_code': qr_code,
        }
        
        return render(request, 'security/two_factor_auth.html', context)
        
    except Exception as e:
        logger.error(f"Error in two_factor_auth view: {str(e)}")
        messages.error(request, _('An error occurred while loading two-factor authentication settings.'))
        return redirect('gdpr_platform:security_overview')

@login_required
def terminate_all_sessions(request):
    """
    View for terminating all active sessions for the current user.
    """
    try:
        # Get all active sessions for the user
        active_sessions = UserSession.objects.filter(
            user=request.user,
            is_active=True
        )
        
        # Log the action before terminating sessions
        ActivityLog.objects.create(
            user=request.user,
            action='terminate_all_sessions',
            description='User terminated all active sessions',
            ip_address=get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', '')
        )
        
        # Terminate all sessions except the current one
        current_session_key = request.session.session_key
        for session in active_sessions:
            if session.session_key != current_session_key:
                session.is_active = False
                session.logout_time = timezone.now()
                session.end_reason = 'user_terminated'
                session.save()
        
        messages.success(request, _('All other active sessions have been terminated.'))
        
    except Exception as e:
        logger.error(f"Error terminating all sessions: {str(e)}")
        messages.error(request, _('An error occurred while terminating sessions.'))
    
    return redirect('gdpr_platform:trusted_devices')

@login_required
def security_settings(request):
    """Display and manage security settings"""
    try:
        # Get user's security status
        two_factor_enabled = hasattr(request.user, 'totp_device')
        
        # Get active sessions
        active_sessions = UserSession.objects.filter(
            user=request.user,
            is_active=True
        ).order_by('-login_time')
        
        # Get trusted devices
        trusted_devices = TrustedDevice.objects.filter(
            user=request.user,
            expires_at__gt=timezone.now()
        ).order_by('-last_used')
        
        # Get security logs
        security_logs = ActivityLog.objects.filter(
            user=request.user,
            action_type__in=['login', 'password', '2fa', 'security']
        ).order_by('-timestamp')[:10]
        
        context = {
            'title': _('Security Settings'),
            'two_factor_enabled': two_factor_enabled,
            'active_sessions': active_sessions,
            'trusted_devices': trusted_devices,
            'security_logs': security_logs,
            'user': request.user
        }
        
        return render(request, 'security/security_settings.html', context)
        
    except Exception as e:
        logger.error(f"Security settings error for user {request.user.id}: {str(e)}", exc_info=True)
        messages.error(request, _('An error occurred loading security settings.'))
        return redirect('gdpr_platform:dashboard')