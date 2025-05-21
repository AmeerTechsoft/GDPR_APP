from django.core.management.base import BaseCommand
from django.utils import timezone
from django.db.models import Q
from gdpr_platform.models import User, UserSession, DataExport
from datetime import timedelta
import logging

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = 'Cleanup user data based on retention policies'

    def handle(self, *args, **options):
        self.stdout.write('Starting user data cleanup...')
        
        # Process users scheduled for deletion
        scheduled_users = User.objects.filter(
            account_status='scheduled_deletion',
            scheduled_deletion_date__lte=timezone.now()
        )
        
        for user in scheduled_users:
            try:
                # Immediate deletion for sensitive data
                if user.get_retention_period('sensitive_data') == 0:
                    user.government_id = None
                    user.emergency_contact = None
                    user.social_profiles = None
                
                # Check retention period for preferences
                if timezone.now() - user.scheduled_deletion_date >= timedelta(
                    days=user.get_retention_period('preferences')
                ):
                    user.marketing_preferences = {}
                    user.device_info = {}
                    user.profile_photo = None
                
                # Check retention period for personal info
                personal_info_retention = timedelta(
                    days=user.get_retention_period('personal_info')
                )
                if timezone.now() - user.scheduled_deletion_date >= personal_info_retention:
                    user.anonymize_data()
                
                user.save()
                logger.info(f'Processed deletion for user {user.id}')
                
            except Exception as e:
                logger.error(f'Error processing deletion for user {user.id}: {str(e)}')
        
        # Cleanup old sessions
        old_sessions = UserSession.objects.filter(
            Q(logout_time__lte=timezone.now() - timedelta(days=30)) |
            Q(last_activity__lte=timezone.now() - timedelta(days=30))
        )
        deleted_sessions = old_sessions.delete()
        logger.info(f'Deleted {deleted_sessions[0]} old sessions')
        
        # Cleanup expired data exports
        expired_exports = DataExport.objects.filter(
            expires_at__lte=timezone.now()
        )
        for export in expired_exports:
            try:
                if export.data_file:
                    export.data_file.delete()
                export.delete()
                logger.info(f'Deleted expired data export {export.id}')
            except Exception as e:
                logger.error(f'Error deleting data export {export.id}: {str(e)}')
        
        self.stdout.write(self.style.SUCCESS('User data cleanup completed successfully')) 