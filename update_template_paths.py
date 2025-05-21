import os
import re

def update_template_paths(file_path):
    # Template path mappings
    template_mappings = {
        # Admin templates
        'admin/admin_dashboard.html': 'admin_templates/admin_dashboard.html',
        'admin/system_settings.html': 'admin_templates/system_settings.html',
        'admin/user_management.html': 'admin_templates/user_management.html',
        'admin/compliance_report.html': 'admin_templates/compliance_report.html',
        'admin/gdpr_dashboard.html': 'admin_templates/gdpr_dashboard.html',
        
        # DPO templates
        'gdpr/dpo_dashboard.html': 'dpo_templates/dpo_dashboard.html',
        'gdpr/breach_notifications.html': 'dpo_templates/breach_notifications.html',
        'gdpr/data_processing.html': 'dpo_templates/data_processing.html',
        'gdpr/data_processing_log.html': 'dpo_templates/data_processing_log.html',
        'gdpr/cross_border_transfers.html': 'dpo_templates/cross_border_transfers.html',
        
        # Compliance Officer templates
        'gdpr/compliance_dashboard.html': 'compliance_officer_templates/compliance_dashboard.html',
        'gdpr/activity_log.html': 'compliance_officer_templates/activity_log.html',
        'gdpr/data_requests_overview.html': 'compliance_officer_templates/data_requests_overview.html',
        'gdpr/processing_overview.html': 'compliance_officer_templates/processing_overview.html',
        'gdpr/processing_activities.html': 'compliance_officer_templates/processing_activities.html',
        'gdpr/manage_breaches.html': 'compliance_officer_templates/manage_breaches.html',
        
        # User templates
        'gdpr/dashboard.html': 'user_templates/dashboard.html',
        'gdpr/privacy_settings.html': 'user_templates/privacy_settings.html',
        'gdpr/data_export.html': 'user_templates/data_export.html',
        'gdpr/data_deletion.html': 'user_templates/data_deletion.html',
        'gdpr/data_rectification.html': 'user_templates/data_rectification.html',
        'gdpr/activity_log.html': 'user_templates/activity_log.html',
        'gdpr/trusted_devices.html': 'user_templates/trusted_devices.html',
        'gdpr/settings.html': 'user_templates/settings.html',
        'gdpr/cookie_consent.html': 'user_templates/cookie_consent.html',
        'gdpr/consent_dashboard.html': 'user_templates/consent_dashboard.html',
        'gdpr/submit_data_request.html': 'user_templates/submit_data_request.html',
        'dashboard/user_dashboard.html': 'user_templates/user_dashboard.html',
    }
    
    # Read the file content
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Replace template paths
    for old_path, new_path in template_mappings.items():
        content = content.replace(f"'{old_path}'", f"'{new_path}'")
    
    # Write the updated content back
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(content)
        print(f"Updated template paths in {file_path}")

def main():
    # Update views.py
    views_file = 'gdpr_compliance/gdpr_platform/views.py'
    if os.path.exists(views_file):
        update_template_paths(views_file)
    else:
        print(f"File not found: {views_file}")
    
    # Update admin_views.py
    admin_views_file = 'gdpr_compliance/gdpr_platform/admin_views.py'
    if os.path.exists(admin_views_file):
        update_template_paths(admin_views_file)
    else:
        print(f"File not found: {admin_views_file}")

if __name__ == '__main__':
    main() 