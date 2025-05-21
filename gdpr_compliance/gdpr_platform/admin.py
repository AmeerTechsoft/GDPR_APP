from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.contrib.auth import get_user_model
from .models import (
    Role, UserSession, PrivacyPolicy, UserPrivacyPolicyConsent,
    DataExport, AuditLog, TwoFactorAuth, TrustedDevice,
    TrustSettings, ActivityLog, SystemSettings
)

User = get_user_model()

# Customize admin site
admin.site.site_header = 'GDPR Compliance Platform'
admin.site.site_title = 'GDPR Admin'
admin.site.index_title = 'Administration'

@admin.register(User)
class CustomUserAdmin(UserAdmin):
    list_display = ('username', 'email', 'first_name', 'last_name', 'is_active', 'date_joined')
    list_filter = ('is_active', 'roles', 'date_joined', 'account_status')
    search_fields = ('username', 'email', 'first_name', 'last_name')
    ordering = ('-date_joined',)
    filter_horizontal = ('roles', 'groups', 'user_permissions')
    
    fieldsets = (
        (None, {'fields': ('username', 'password')}),
        ('Personal Info', {'fields': ('first_name', 'last_name', 'email', 'phone_number', 'date_of_birth')}),
        ('Contact Info', {'fields': ('address', 'city', 'country', 'postal_code')}),
        ('Additional Info', {'fields': ('nationality', 'occupation', 'company', 'preferred_language')}),
        ('Security', {'fields': ('account_status', 'two_factor_enabled', 'last_login_ip')}),
        ('Roles & Permissions', {'fields': ('roles', 'is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions')}),
        ('Important Dates', {'fields': ('last_login', 'date_joined', 'last_privacy_acceptance')}),
    )
    
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('username', 'email', 'password1', 'password2'),
        }),
    )

@admin.register(Role)
class RoleAdmin(admin.ModelAdmin):
    list_display = ('name', 'description', 'is_active', 'created_at')
    list_filter = ('is_active', 'created_at')
    search_fields = ('name', 'description')
    ordering = ('name',)
    filter_horizontal = ('permissions',)
    readonly_fields = ('created_at', 'updated_at')

# Register models with custom admin classes
@admin.register(UserSession)
class UserSessionAdmin(admin.ModelAdmin):
    list_display = ('user', 'ip_address', 'login_time', 'last_activity', 'is_active', 'mfa_verified')
    list_filter = ('is_active', 'mfa_verified', 'login_time')
    search_fields = ('user__email', 'ip_address', 'user_agent')
    readonly_fields = ('login_time', 'last_activity', 'logout_time')
    ordering = ('-login_time',)

@admin.register(PrivacyPolicy)
class PrivacyPolicyAdmin(admin.ModelAdmin):
    list_display = ('version', 'effective_date', 'is_active', 'created_by')
    list_filter = ('is_active', 'effective_date')
    search_fields = ('version', 'content')
    readonly_fields = ('created_at', 'created_by')
    ordering = ('-effective_date',)

@admin.register(UserPrivacyPolicyConsent)
class UserPrivacyPolicyConsentAdmin(admin.ModelAdmin):
    list_display = ('user', 'policy', 'consent_date', 'ip_address')
    list_filter = ('consent_date', 'policy')
    search_fields = ('user__email', 'ip_address')
    readonly_fields = ('consent_date',)
    ordering = ('-consent_date',)

@admin.register(DataExport)
class DataExportAdmin(admin.ModelAdmin):
    list_display = ('user', 'request_date', 'completion_date', 'status', 'file_format')
    list_filter = ('status', 'file_format', 'request_date')
    search_fields = ('user__email',)
    readonly_fields = ('request_date', 'completion_date', 'file_size', 'download_count')
    ordering = ('-request_date',)

@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ('user', 'action', 'resource_type', 'timestamp', 'ip_address')
    list_filter = ('action', 'resource_type', 'timestamp')
    search_fields = ('user__email', 'ip_address', 'resource_id')
    readonly_fields = ('timestamp',)
    ordering = ('-timestamp',)

@admin.register(TwoFactorAuth)
class TwoFactorAuthAdmin(admin.ModelAdmin):
    list_display = ('user', 'is_enabled', 'created_at', 'updated_at')
    list_filter = ('is_enabled', 'created_at')
    search_fields = ('user__email',)
    readonly_fields = ('created_at', 'updated_at')
    ordering = ('-created_at',)

@admin.register(TrustedDevice)
class TrustedDeviceAdmin(admin.ModelAdmin):
    list_display = ('user', 'device_id', 'last_used', 'expires_at', 'is_expired')
    list_filter = ('added_on', 'last_used')
    search_fields = ('user__email', 'device_id', 'ip_address')
    readonly_fields = ('added_on', 'last_used')
    ordering = ('-last_used',)

@admin.register(TrustSettings)
class TrustSettingsAdmin(admin.ModelAdmin):
    list_display = ('user', 'trust_duration', 'require_2fa_new_ip', 'max_trusted_devices')
    list_filter = ('trust_duration', 'require_2fa_new_ip')
    search_fields = ('user__email',)
    readonly_fields = ('created_at', 'updated_at')
    ordering = ('user',)

@admin.register(ActivityLog)
class ActivityLogAdmin(admin.ModelAdmin):
    list_display = ('user', 'action_type', 'action', 'status', 'timestamp')
    list_filter = ('action_type', 'status', 'timestamp')
    search_fields = ('user__email', 'action', 'ip_address')
    readonly_fields = ('timestamp',)
    ordering = ('-timestamp',)

@admin.register(SystemSettings)
class SystemSettingsAdmin(admin.ModelAdmin):
    list_display = ('key', 'category', 'is_encrypted', 'last_modified_by', 'updated_at')
    list_filter = ('category', 'is_encrypted')
    search_fields = ('key', 'description')
    readonly_fields = ('created_at', 'updated_at', 'last_modified_by')
    ordering = ['category', 'key']  # Match the model's Meta ordering

    def save_model(self, request, obj, form, change):
        obj.last_modified_by = request.user
        super().save_model(request, obj, form, change)
