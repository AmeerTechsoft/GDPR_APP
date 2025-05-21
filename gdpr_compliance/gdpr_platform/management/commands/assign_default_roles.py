from django.core.management.base import BaseCommand
from django.db.models import Count
from gdpr_platform.models import CustomUser, Role

class Command(BaseCommand):
    help = 'Assigns the default regular user role to users who have no roles'

    def handle(self, *args, **options):
        # Get users with no roles
        users_without_roles = CustomUser.objects.annotate(
            role_count=Count('roles')
        ).filter(role_count=0)

        if not users_without_roles.exists():
            self.stdout.write(self.style.SUCCESS('All users have roles assigned.'))
            return

        try:
            regular_user_role = Role.objects.get(name=Role.REGULAR_USER)
        except Role.DoesNotExist:
            self.stdout.write(self.style.ERROR('Regular user role does not exist. Please create it first.'))
            return

        count = 0
        for user in users_without_roles:
            user.roles.add(regular_user_role)
            count += 1
            self.stdout.write(f'Assigned regular user role to {user.username}')

        self.stdout.write(self.style.SUCCESS(f'Successfully assigned roles to {count} users.')) 