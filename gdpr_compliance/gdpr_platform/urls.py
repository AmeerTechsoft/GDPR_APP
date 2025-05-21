from django.urls import path
from django.contrib.auth import views as auth_views
from . import views

app_name = 'gdpr_platform'

urlpatterns = [
    # Landing and Authentication URLs
    path('', views.landing, name='landing'),
    path('login/', views.custom_login, name='login'),
    path('logout/', views.custom_logout, name='logout'),
    path('register/', views.register, name='register'),

    # Dashboard URLs - Role specific
    path('dashboard/', views.dashboard, name='dashboard'),
    path('admin/dashboard/', views.admin_dashboard, name='admin_dashboard'),
    path('dpo/dashboard/', views.dpo_dashboard, name='dpo_dashboard'),
    path('compliance/dashboard/', views.compliance_dashboard, name='compliance_dashboard'),
    path('user/dashboard/', views.user_dashboard, name='user_dashboard'),

    # Settings and Profile URLs
    path('settings/', views.settings, name='settings'),
    path('security/2fa/setup/', views.setup_2fa, name='setup_2fa'),
    path('security/2fa/disable/', views.disable_2fa, name='disable_2fa'),
    path('security/devices/', views.trusted_devices, name='trusted_devices'),
    
    # Custom Password Reset URLs
    path('reset-password/', 
        auth_views.PasswordResetView.as_view(
            template_name='auth/password_reset.html',
            email_template_name='emails/password_reset_email.html',
            subject_template_name='emails/password_reset_subject.txt',
            success_url='/gdpr/reset-password/done/'
        ), 
        name='custom_password_reset'
    ),
    path('reset-password/done/',
        auth_views.PasswordResetDoneView.as_view(
            template_name='auth/password_reset_done.html'
        ),
        name='custom_password_reset_done'
    ),
    path('reset-password/confirm/<uidb64>/<token>/',
        auth_views.PasswordResetConfirmView.as_view(
            template_name='auth/password_reset_confirm.html',
            success_url='/gdpr/reset-password/complete/'
        ),
        name='custom_password_reset_confirm'
    ),
    path('reset-password/complete/',
        auth_views.PasswordResetCompleteView.as_view(
            template_name='auth/password_reset_complete.html'
        ),
        name='custom_password_reset_complete'
    ),
    
    # Main Application URLs
    path('settings/', views.settings, name='settings'),
    
    # GDPR Data Rights URLs
    path('data/delete/', views.handle_data_deletion, name='data_deletion'),
    path('data/export/', views.export_user_data, name='data_export'),
    path('data/rectify/', views.data_rectification, name='data_rectification'),
    path('data/processing/', views.data_processing, name='data_processing'),
    path('data/transfers/', views.cross_border_transfers, name='cross_border_transfers'),
    
    # Cookie and Privacy Settings URLs
    path('cookies/update/', views.update_cookie_consent, name='update_cookie_consent'),
    path('privacy/settings/', views.privacy_settings, name='privacy_settings'),
    path('privacy/policy/', views.privacy_policy, name='privacy_policy'),
    path('privacy/policy/consent/', views.update_privacy_policy_consent, name='update_policy_consent'),
    path('privacy/policy/manage/', views.manage_privacy_policy, name='manage_privacy_policy'),
    
    # Security URLs
    path('security/', views.security_dashboard, name='security_dashboard'),
    path('security/devices/revoke/', views.revoke_session, name='revoke_session'),
    path('security/devices/revoke-all/', views.revoke_all_sessions, name='revoke_all_sessions'),
    path('security/sessions/terminate/', views.terminate_session, name='terminate_session'),

    # Admin Dashboard URLs
    path('admin/users/', views.user_management, name='user_management'),
    path('admin/system/', views.system_settings, name='system_settings'),

    # Compliance and Monitoring URLs
    path('activity-log/', views.activity_log, name='activity_log'),
    #path('api/activity-log/<int:log_id>/', views.get_activity_log_details, name='get_activity_log_details'),
    path('api/activity-log/export/', views.export_activity_log, name='export_activity_log'),
    path('breaches/', views.manage_breaches, name='manage_breaches'),
    path('breaches/<uuid:breach_id>/', views.breach_details, name='breach_details'),
    path('breaches/notifications/', views.data_breach_notifications, name='breach_notifications'),
    path('breaches/acknowledge/<int:notification_id>/', views.acknowledge_breach, name='acknowledge_breach'),
    path('processing/overview/', views.processing_overview, name='processing_overview'),
    path('processing/activities/', views.processing_activities, name='processing_activities'),
    path('compliance/reports/', views.compliance_reports, name='compliance_reports'),
    path('data/requests/', views.data_requests_overview, name='data_requests'),
    path('data/requests/<int:request_id>/', views.request_details, name='request_details'),
    path('preferences/marketing/update/', views.update_marketing_preferences, name='update_marketing_preferences'),

    # DPO URLs
    path('dpo/dashboard/', views.dpo_dashboard, name='dpo_dashboard'),
    path('dpo/processing/', views.data_processing, name='data_processing'),
    path('dpo/transfers/', views.cross_border_transfers, name='cross_border_transfers'),

    # Report URLs
    path('compliance/reports/generate/', views.generate_report, name='generate_report'),
    path('compliance/reports/download/<uuid:report_id>/', views.download_report, name='download_report'),
    path('compliance/reports/schedule/', views.schedule_report, name='schedule_report'),
    path('compliance/reports/delete/', views.delete_report, name='delete_report'),
    path('compliance/reports/schedule/delete/', views.delete_report_schedule, name='delete_report_schedule'),
    path('compliance/reports/schedule/list/', views.get_report_schedule, name='get_report_schedule'),
]
