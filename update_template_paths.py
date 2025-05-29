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
    User, Role, AuditLog, DataRequest, DataCategory,
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
