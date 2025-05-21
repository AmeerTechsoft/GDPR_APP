from django.db.models.signals import pre_save, post_save, pre_delete
from django.dispatch import receiver
from django.utils import timezone
from .models import User, AuditLog, UserSession
import logging

logger = logging.getLogger(__name__)

@receiver(pre_save, sender=User)
def handle_sensitive_data_changes(sender, instance, **kwargs):
    """Handle changes to sensitive user data"""
    if instance.pk:  # If this is an update
        old_instance = User.objects.get(pk=instance.pk)
        
        # Check for changes in sensitive fields
        sensitive_fields = ['government_id', 'emergency_contact', 'address']
        changes = {}
        
        for field in sensitive_fields:
            old_value = getattr(old_instance, field)
            new_value = getattr(instance, field)
            if old_value != new_value:
                changes[field] = 'modified'
        
        if changes:
            AuditLog.objects.create(
                user=instance,
                action='sensitive_data_modified',
                details={'fields_modified': list(changes.keys())},
                timestamp=timezone.now()
            )

@receiver(post_save, sender=User)
def handle_user_creation(sender, instance, created, **kwargs):
    """Handle new user creation and updates"""
    if created:
        # Log user creation
        AuditLog.objects.create(
            user=instance,
            action='user_created',
            timestamp=timezone.now()
        )
        
        # Initialize default retention policies if not set
        if not instance.data_retention_policy:
            instance.data_retention_policy = {
                'personal_info': {'retention_period': 2555, 'unit': 'days'},
                'sensitive_data': {'retention_period': 0, 'unit': 'days'},
                'professional_info': {'retention_period': 2555, 'unit': 'days'},
                'preferences': {'retention_period': 30, 'unit': 'days'},
                'security_logs': {'retention_period': 365, 'unit': 'days'},
            }
            instance.save()

@receiver(pre_delete, sender=User)
def handle_user_deletion(sender, instance, **kwargs):
    """Handle user deletion"""
    try:
        # Log deletion attempt
        AuditLog.objects.create(
            user=instance,
            action='user_deleted',
            timestamp=timezone.now()
        )
        
        # Clean up related sessions
        UserSession.objects.filter(user=instance).delete()
        
        # Ensure sensitive data is cleared
        instance.government_id = None
        instance.emergency_contact = None
        instance.social_profiles = None
        instance.save()
        
        logger.info(f'User {instance.id} deletion processed successfully')
    except Exception as e:
        logger.error(f'Error during user deletion: {str(e)}') 