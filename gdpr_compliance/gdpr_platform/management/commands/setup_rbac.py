from django.core.management.base import BaseCommand
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from django.utils.translation import gettext as _
from gdpr_platform.models import Role, CustomUser, DataRequest, PrivacyPolicy, AuditLog

class Command(BaseCommand):
    help = 'Sets up initial RBAC roles and permissions'

    def handle(self, *args, **kwargs):
        self.stdout.write('Setting up RBAC roles and permissions...')
        
        # Create roles
        roles = {
            'admin': {
                'description': 'Full system access',
                'permissions': [
                    ('view_user', 'Can view user'),
                    ('add_user', 'Can add user'),
                    ('change_user', 'Can change user'),
                    ('delete_user', 'Can delete user'),
                    ('manage_roles', 'Can manage roles'),
                    ('view_audit_log', 'Can view audit log'),
                    ('manage_privacy_policy', 'Can manage privacy policy'),
                    ('manage_system_settings', 'Can manage system settings'),
                ]
            },
            'compliance_officer': {
                'description': 'Manages GDPR compliance',
                'permissions': [
                    ('view_audit_log', 'Can view audit log'),
                    ('view_data_request', 'Can view data request'),
                    ('process_data_request', 'Can process data request'),
                    ('view_privacy_policy', 'Can view privacy policy'),
                    ('manage_privacy_policy', 'Can manage privacy policy'),
                    ('view_compliance_reports', 'Can view compliance reports'),
                ]
            },
            'dpo': {
                'description': 'Data Protection Officer',
                'permissions': [
                    ('view_audit_log', 'Can view audit log'),
                    ('view_data_breach', 'Can view data breach'),
                    ('manage_data_breach', 'Can manage data breach'),
                    ('view_data_processing', 'Can view data processing'),
                    ('manage_data_processing', 'Can manage data processing'),
                    ('view_compliance_reports', 'Can view compliance reports'),
                ]
            },
            'user': {
                'description': 'Regular user',
                'permissions': [
                    ('view_own_data', 'Can view own data'),
                    ('export_own_data', 'Can export own data'),
                    ('request_data_deletion', 'Can request data deletion'),
                    ('manage_privacy_settings', 'Can manage privacy settings'),
                ]
            }
        }
        
        # Get or create content types
        user_ct = ContentType.objects.get_for_model(CustomUser)
        request_ct = ContentType.objects.get_for_model(DataRequest)
        policy_ct = ContentType.objects.get_for_model(PrivacyPolicy)
        audit_ct = ContentType.objects.get_for_model(AuditLog)
        
        # Create roles and permissions
        for role_name, role_data in roles.items():
            role, created = Role.objects.get_or_create(
                name=role_name,
                defaults={'description': role_data['description']}
            )
            
            if created:
                self.stdout.write(f'Created role: {role_name}')
            
            # Create and assign permissions
            for codename, name in role_data['permissions']:
                # Determine content type based on permission
                if 'user' in codename:
                    ct = user_ct
                elif 'data_request' in codename:
                    ct = request_ct
                elif 'privacy_policy' in codename:
                    ct = policy_ct
                elif 'audit' in codename:
                    ct = audit_ct
                else:
                    ct = user_ct  # Default to user content type
                
                permission, created = Permission.objects.get_or_create(
                    codename=codename,
                    content_type=ct,
                    defaults={'name': name}
                )
                
                role.permissions.add(permission)
                if created:
                    self.stdout.write(f'Created permission: {codename}')
        
        self.stdout.write(self.style.SUCCESS('Successfully set up RBAC roles and permissions')) 