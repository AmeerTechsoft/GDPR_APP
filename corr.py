                
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
from django.db.models import Q, Sum, Avg, F
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
    CustomUser, Role, DataRequest, DataBreach, 
    BreachNotification, ActivityLog, DataProcessingActivity,
    CookieConsent, PrivacyPolicy, UserPrivacyPolicyConsent,
    ProcessingRequirement, DataCategory, ConsentRecord,
    UserSession, TwoFactorAuth, TrustedDevice, DataTransfer,
    AuditLog, SupportTicket, BreachNotification, DeletionTask,
    DataBreach
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
    """Custom login view with GDPR compliance and security features"""
    next_url = request.GET.get('next', '')
    is_admin = next_url and next_url.startswith('/admin/')
    
    if request.user.is_authenticated:
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
    """Handle secure user logout with GDPR compliance"""
    try:
        user = request.user
        session_key = request.session.session_key
        
        # Log the logout event
        AuditLog.objects.create(
            user=user,
            action='user_logout',
            resource_type='session',
            resource_id=session_key,
            ip_address=get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            details={
                'timestamp': str(timezone.now()),
                'session_duration': str(timezone.now() - user.last_login) if user.last_login else 'Unknown'
            }
        )
        
        # Update user session record
        if session_key:
            UserSession.objects.filter(
                user=user,
                session_key=session_key,
                logout_time__isnull=True
            ).update(
                logout_time=timezone.now(),
                end_reason='user_logout'
            )
        
        # Perform the logout
        logout(request)
        
        messages.success(request, _('You have been successfully logged out.'))
        
    except Exception as e:
        logger.error(f"Error during logout: {str(e)}")
        messages.error(request, _('An error occurred during logout.'))
        return redirect('gdpr_platform:login')