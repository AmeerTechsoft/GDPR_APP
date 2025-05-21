from functools import wraps
from django.http import HttpResponseForbidden
from django.shortcuts import redirect
from django.contrib import messages
from django.utils.translation import gettext as _
import logging

logger = logging.getLogger(__name__)

def role_required(*roles):
    """
    Decorator for views that checks whether a user has a specific role,
    redirecting to the login page if necessary.
    """
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            if not request.user.is_authenticated:
                messages.error(request, _('Please log in to access this page.'))
                return redirect('gdpr_platform:login')
            
            # Admin/superuser always has access
            if request.user.is_staff or request.user.is_superuser:
                return view_func(request, *args, **kwargs)
            
            # Check if user has any of the required roles
            user_roles = request.user.roles.values_list('name', flat=True)
            if any(role in user_roles for role in roles):
                return view_func(request, *args, **kwargs)

            messages.error(request, _('You do not have permission to access this page.'))
            return redirect('gdpr_platform:dashboard')
        return _wrapped_view
    return decorator

def permission_required(*permissions):
    """
    Decorator to require specific permissions for accessing a view
    Usage: @permission_required('can_view_reports', 'can_edit_users')
    """
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            if not request.user.is_authenticated:
                return redirect('gdpr_platform:login')
            
            # Super admin bypass
            if request.user.is_superuser:
                return view_func(request, *args, **kwargs)
            
            # Check if user has all required permissions
            if not all(request.user.has_permission(perm) for perm in permissions):
                logger.warning(
                    f"Permission denied for user {request.user.username}. "
                    f"Required permissions: {permissions}"
                )
                messages.error(request, _('You do not have the required permissions to access this resource.'))
                return redirect('gdpr_platform:dashboard')
            
            return view_func(request, *args, **kwargs)
        return _wrapped_view
    return decorator

def dpo_required(view_func):
    """
    Decorator to require DPO role
    Usage: @dpo_required
    """
    return role_required('dpo')(view_func)

def admin_required(view_func):
    """
    Decorator for views that checks that the user is an admin,
    redirecting to the login page if necessary.
    """
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        if not request.user.is_authenticated:
            messages.error(request, _('Please log in to access this page.'))
            return redirect('gdpr_platform:login')
            
        if not (request.user.is_staff or request.user.is_superuser):
            messages.error(request, _('You do not have permission to access this page.'))
            return redirect('gdpr_platform:dashboard')
            
        return view_func(request, *args, **kwargs)
    return _wrapped_view

def compliance_officer_required(view_func):
    """
    Decorator to require compliance officer role
    Usage: @compliance_officer_required
    """
    return role_required('compliance_officer')(view_func)

def any_staff_role_required(view_func):
    """
    Decorator to require any staff role (admin, dpo, or compliance officer)
    Usage: @any_staff_role_required
    """
    return role_required('admin', 'dpo', 'compliance_officer')(view_func) 