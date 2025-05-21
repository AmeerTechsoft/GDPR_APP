import os
import shutil

def create_role_dirs():
    base_path = 'gdpr_compliance/gdpr_platform/templates'
    role_dirs = [
        'admin_templates',
        'dpo_templates',
        'compliance_officer_templates',
        'user_templates'
    ]
    
    for dir_name in role_dirs:
        dir_path = os.path.join(base_path, dir_name)
        if not os.path.exists(dir_path):
            os.makedirs(dir_path)
            print(f"Created directory: {dir_path}")

def move_templates():
    base_path = 'gdpr_compliance/gdpr_platform/templates'
    
    # Define template mappings
    template_mappings = {
        'admin_templates': [
            ('admin/admin_dashboard.html', 'admin_dashboard.html'),
            ('admin/system_settings.html', 'system_settings.html'),
            ('admin/user_management.html', 'user_management.html'),
            ('admin/compliance_report.html', 'compliance_report.html'),
        ],
        'dpo_templates': [
            ('gdpr/dpo_dashboard.html', 'dpo_dashboard.html'),
            ('gdpr/breach_notifications.html', 'breach_notifications.html'),
            ('gdpr/data_processing.html', 'data_processing.html'),
            ('gdpr/data_processing_log.html', 'data_processing_log.html'),
            ('gdpr/cross_border_transfers.html', 'cross_border_transfers.html'),
        ],
        'compliance_officer_templates': [
            ('gdpr/compliance_dashboard.html', 'compliance_dashboard.html'),
            ('gdpr/activity_log.html', 'activity_log.html'),
            ('gdpr/data_requests_overview.html', 'data_requests_overview.html'),
            ('gdpr/processing_overview.html', 'processing_overview.html'),
            ('gdpr/processing_activities.html', 'processing_activities.html'),
            ('gdpr/manage_breaches.html', 'manage_breaches.html'),
        ],
        'user_templates': [
            ('gdpr/dashboard.html', 'dashboard.html'),
            ('gdpr/privacy_settings.html', 'privacy_settings.html'),
            ('gdpr/data_export.html', 'data_export.html'),
            ('gdpr/data_deletion.html', 'data_deletion.html'),
            ('gdpr/data_rectification.html', 'data_rectification.html'),
            ('gdpr/activity_log.html', 'activity_log.html'),
            ('gdpr/trusted_devices.html', 'trusted_devices.html'),
            ('gdpr/settings.html', 'settings.html'),
            ('gdpr/cookie_consent.html', 'cookie_consent.html'),
            ('gdpr/consent_dashboard.html', 'consent_dashboard.html'),
            ('gdpr/submit_data_request.html', 'submit_data_request.html'),
        ]
    }
    
    # Move templates to their respective directories
    for role_dir, templates in template_mappings.items():
        for src_template, dest_template in templates:
            src_path = os.path.join(base_path, src_template)
            dest_path = os.path.join(base_path, role_dir, dest_template)
            
            if os.path.exists(src_path):
                try:
                    shutil.copy2(src_path, dest_path)
                    print(f"Copied {src_path} to {dest_path}")
                except Exception as e:
                    print(f"Error copying {src_path}: {str(e)}")
            else:
                print(f"Source file not found: {src_path}")

if __name__ == '__main__':
    create_role_dirs()
    move_templates() 