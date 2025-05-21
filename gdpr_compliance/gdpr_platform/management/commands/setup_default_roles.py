from django.core.management.base import BaseCommand
from gdpr_platform.models import Role

class Command(BaseCommand):
    help = 'Creates default roles if they do not exist'

    def handle(self, *args, **options):
        # Define default roles with descriptions
        default_roles = {
            Role.ADMIN: 'Administrator with full system access',
            Role.COMPLIANCE_OFFICER: 'Responsible for ensuring GDPR compliance',
            Role.DATA_PROTECTION_OFFICER: 'Oversees data protection strategy and implementation',
            Role.REGULAR_USER: 'Standard user with basic access rights'
        }

        created_count = 0
        for role_name, description in default_roles.items():
            role, created = Role.objects.get_or_create(
                name=role_name,
                defaults={
                    'description': description,
                    'is_active': True
                }
            )
            if created:
                created_count += 1
                self.stdout.write(f'Created role: {role_name}')
            else:
                self.stdout.write(f'Role already exists: {role_name}')

        self.stdout.write(self.style.SUCCESS(f'Successfully created {created_count} roles.'))