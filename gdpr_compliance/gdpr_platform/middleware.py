import time
import logging
from django.utils import timezone
from django.contrib import messages
from django.shortcuts import redirect
from django.urls import reverse, resolve
from django.conf import settings
from django.http import JsonResponse, HttpResponseForbidden
from .models import CookieConsent, UserSession, AuditLog, Role, ActivityLog
import re
import json
from django.utils.translation import gettext as _
from django.middleware.security import SecurityMiddleware
from django.contrib.auth import get_user_model
from django.core.cache import cache

logger = logging.getLogger('gdpr_platform')
User = get_user_model()

class CookieConsentMiddleware:
    """Middleware to enforce cookie consent"""
    def __init__(self, get_response):
        self.get_response = get_response
        self.exempt_urls = [
            'login',
            'logout',
            'register',
            'cookie_consent',
            'cookie_policy',
            'privacy_policy',
            'data_rights_dashboard',
            'landing',
            'static',
            'media',
            'password_reset',
            'password_reset_done',
            'password_reset_confirm',
            'password_reset_complete',
            'extend_session',
            'update_cookie_preferences',
            'admin_dashboard',
            'export_compliance_report',
        ]

    def __call__(self, request):
        if not request.user.is_authenticated:
            return self.get_response(request)

        # Skip cookie consent for admin users
        if request.user.is_staff or request.user.is_superuser:
            return self.get_response(request)

        # Allow static files and exempt URLs
        if request.path.startswith('/static/') or request.path.startswith('/media/'):
            return self.get_response(request)

        try:
            current_url = resolve(request.path_info).url_name
            if current_url in self.exempt_urls:
                return self.get_response(request)
        except:
            # If URL resolution fails, let it pass through
            return self.get_response(request)

        # Check for existing consent
        consent = CookieConsent.objects.filter(user=request.user).first()
        if not consent:
            messages.info(request, 'Please set your cookie preferences before continuing.')
            return redirect('gdpr_platform:cookie_consent')

        return self.get_response(request)

class SecurityHeadersMiddleware:
    """Middleware to add security headers"""
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        
        # Security Headers
        response['X-Content-Type-Options'] = 'nosniff'
        response['X-Frame-Options'] = 'DENY'
        response['X-XSS-Protection'] = '1; mode=block'
        response['Referrer-Policy'] = 'same-origin'
        
        if request.is_secure():
            response['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        
        return response

class UserActivityMiddleware:
    """Middleware to track user activity"""
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.user.is_authenticated:
            session = UserSession.objects.filter(
                user=request.user,
                session_key=request.session.session_key,
                is_active=True
            ).first()
            
            if not session:
                UserSession.objects.create(
                    user=request.user,
                    session_key=request.session.session_key,
                    ip_address=request.META.get('REMOTE_ADDR'),
                    user_agent=request.META.get('HTTP_USER_AGENT', '')
                )
            else:
                session.last_activity = timezone.now()
                session.save()

        return self.get_response(request)

class AuditLogMiddleware:
    """Middleware for audit logging"""
    def __init__(self, get_response):
        self.get_response = get_response
        self.sensitive_patterns = [
            r'password',
            r'token',
            r'credit_card',
            r'ssn',
        ]

    def __call__(self, request):
        response = self.get_response(request)
        
        if request.user.is_authenticated and request.method in ['POST', 'PUT', 'DELETE']:
            # Clean sensitive data
            clean_data = request.POST.copy()
            for pattern in self.sensitive_patterns:
                for key in request.POST.keys():
                    if re.search(pattern, key, re.I):
                        clean_data[key] = '[REDACTED]'
            
            AuditLog.objects.create(
                user=request.user,
                action=f"{request.method} {resolve(request.path_info).url_name}",
                resource_type=resolve(request.path_info).url_name,
                resource_id=request.resolver_match.kwargs.get('pk', ''),
                ip_address=request.META.get('REMOTE_ADDR'),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                details=json.dumps(dict(clean_data))
            )
        
        return response

class RBACMiddleware:
    """
    Role-Based Access Control Middleware
    Checks if a user has the required role to access a view
    """
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        return response

    def process_view(self, request, view_func, view_args, view_kwargs):
        # Skip RBAC check for authentication views
        if request.path.startswith('/gdpr/login/') or request.path.startswith('/gdpr/logout/') or request.path == '/gdpr/' or request.path.startswith('/gdpr/register/'):
            return None

        # Check if user is authenticated
        if not request.user.is_authenticated:
            return None

        # Get view name from resolver
        view_name = resolve(request.path).view_name
        
        # Skip RBAC check for static files
        if view_name is None or view_name.startswith('static'):
            return None

        # Get required roles from view
        required_roles = getattr(view_func, 'required_roles', None)
        
        # If no required roles, allow access
        if not required_roles:
            return None

        # Check if user has any of the required roles
        for role_name in required_roles:
            if request.user.has_role(role_name):
                return None

        # User doesn't have required role, deny access
        logger.warning(f"Access denied to {request.user.username} for {view_name}. Required roles: {required_roles}")
        messages.error(request, _("You don't have permission to access this page."))
        return HttpResponseForbidden("Access Denied")

class SessionTrackingMiddleware:
    """
    Middleware to track user sessions and activity
    """
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Process request
        if request.user.is_authenticated:
            self._track_session(request)
            self._track_activity(request)
        
        response = self.get_response(request)
        
        # Process response
        return response
    
    def _track_session(self, request):
        """Track user session"""
        session_key = request.session.session_key
        if not session_key:
            # Session hasn't been created yet
            return
        
        # Get client IP
        ip_address = self._get_client_ip(request)
        
        # Get or create session record
        session, created = UserSession.objects.get_or_create(
            user=request.user,
            session_key=session_key,
            defaults={
                'ip_address': ip_address,
                'user_agent': request.META.get('HTTP_USER_AGENT', ''),
                'is_active': True,
                'mfa_verified': getattr(request, 'mfa_verified', False)
            }
        )
        
        if not created:
            # Update last activity time
            session.last_activity = timezone.now()
            session.save(update_fields=['last_activity'])
    
    def _track_activity(self, request):
        """Track user activity"""
        # Skip tracking for static files and API requests
        path = request.path
        if path.startswith('/static/') or path.startswith('/media/') or path.startswith('/api/'):
            return
        
        # Get client IP
        ip_address = self._get_client_ip(request)
        
        # Determine action type
        if path.startswith('/gdpr/login/'):
            action_type = 'login'
        elif path.startswith('/gdpr/security/'):
            action_type = 'security'
        elif path.startswith('/gdpr/password/'):
            action_type = 'password'
        elif path.startswith('/gdpr/2fa/'):
            action_type = '2fa'
        else:
            action_type = 'navigation'
        
        # Create activity log
        ActivityLog.objects.create(
            user=request.user,
            action_type=action_type,
            action=f"Accessed {path}",
            ip_address=ip_address,
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            status='success',
            details={
                'method': request.method,
                'path': path,
                'query': request.GET.dict(),
                'referrer': request.META.get('HTTP_REFERER', '')
            }
        )
    
    def _get_client_ip(self, request):
        """Get client IP address"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip

class CachingMiddleware:
    """
    Middleware for implementing page and fragment caching
    """
    def __init__(self, get_response):
        self.get_response = get_response
        
        # Define URL patterns that should be cached
        self.cacheable_urls = [
            r'^/gdpr/privacy/policy/$',
            r'^/gdpr/landing/$',
            r'^/gdpr/data/processing/$',
        ]
        
        # Define URL patterns that should never be cached
        self.non_cacheable_urls = [
            r'^/gdpr/login/',
            r'^/gdpr/logout/',
            r'^/gdpr/register/',
            r'^/gdpr/settings/',
            r'^/gdpr/data/delete/',
            r'^/gdpr/data/export/',
            r'^/gdpr/data/rectify/',
        ]
        
        # Compile regex patterns
        self.cacheable_patterns = [re.compile(pattern) for pattern in self.cacheable_urls]
        self.non_cacheable_patterns = [re.compile(pattern) for pattern in self.non_cacheable_urls]
        
        # Cache settings
        self.default_timeout = 300  # 5 minutes
        
    def __call__(self, request):
        # Skip caching for non-GET requests
        if request.method != 'GET':
            return self.get_response(request)
        
        # Skip caching for authenticated users
        if request.user.is_authenticated:
            return self.get_response(request)
        
        # Check if URL should be cached
        path = request.path
        
        # Skip caching for non-cacheable URLs
        if any(pattern.match(path) for pattern in self.non_cacheable_patterns):
            return self.get_response(request)
        
        # Only cache specific URLs
        is_cacheable = any(pattern.match(path) for pattern in self.cacheable_patterns)
        if not is_cacheable:
            return self.get_response(request)
        
        # Generate cache key based on full URL
        cache_key = f"page_cache:{request.build_absolute_uri()}"
        
        # Try to get response from cache
        cached_response = cache.get(cache_key)
        if cached_response is not None:
            return cached_response
        
        # Generate response
        response = self.get_response(request)
        
        # Only cache successful responses
        if 200 <= response.status_code < 300:
            # Don't cache responses that set cookies
            if not response.cookies:
                cache.set(cache_key, response, self.default_timeout)
        
        return response

class QueryCachingMiddleware:
    """
    Middleware for caching database queries
    """
    def __init__(self, get_response):
        self.get_response = get_response
        
    def __call__(self, request):
        # Enable query caching for this request
        request.query_cache_enabled = True
        
        # Process request
        response = self.get_response(request)
        
        return response

class PerformanceMonitoringMiddleware:
    """
    Middleware to monitor and log performance metrics
    """
    def __init__(self, get_response):
        self.get_response = get_response
        
    def __call__(self, request):
        # Record start time
        start_time = timezone.now()
        
        # Process request
        response = self.get_response(request)
        
        # Calculate response time
        response_time = (timezone.now() - start_time).total_seconds() * 1000  # in milliseconds
        
        # Log slow responses (> 500ms)
        if response_time > 500:
            logger.warning(f"Slow response: {request.path} - {response_time:.2f}ms")
            
            # Add performance data to response headers in debug mode
            if settings.DEBUG:
                response['X-Response-Time'] = f"{response_time:.2f}ms"
        
        return response