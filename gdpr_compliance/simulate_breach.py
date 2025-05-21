import os
import django
from datetime import datetime

# Set up Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'gdpr_compliance.settings')
django.setup()

from gdpr_platform.models import DataBreach, CustomUser, BreachNotification
from django.utils import timezone
from django.conf import settings
import logging

logger = logging.getLogger(__name__)

def simulate_data_breach():
    try:
        # Create a simulated data breach
        breach = DataBreach.objects.create(
            title="Simulated Security Incident",
            description="A simulated data breach for testing the incident response system. "
                     "Unauthorized access detected in the user authentication system.",
            date_discovered=timezone.now(),
            severity='high',
            breach_type='unauthorized_access',
            affected_data_categories=[
                'personal_information',
                'contact_details',
                'authentication_data'
            ],
            impact_assessment="Potential unauthorized access to user authentication data. "
                           "No evidence of data exfiltration, but precautionary measures being taken.",
            status='investigating'
        )

        # Get all users to simulate as affected
        affected_users = CustomUser.objects.all()
        breach.affected_users.add(*affected_users)

        # Create notifications for affected users
        for user in affected_users:
            BreachNotification.objects.create(
                breach=breach,
                recipient=user,
                status='pending',
                notification_method='email',
                notification_data={
                    'compromised_data': breach.affected_data_categories,
                    'severity': breach.severity,
                    'date_discovered': breach.date_discovered.isoformat()
                }
            )

        # Update breach notification status
        breach.authority_notified = True
        breach.authority_notification_date = timezone.now()
        breach.users_notified = True
        breach.user_notification_date = timezone.now()
        breach.save()

        print(f"Simulated data breach created with ID: {breach.id}")
        print(f"Affected users: {affected_users.count()}")
        print(f"Notifications created: {BreachNotification.objects.filter(breach=breach).count()}")
        return breach

    except Exception as e:
        logger.error(f"Error simulating data breach: {str(e)}")
        raise

if __name__ == '__main__':
    simulate_data_breach() 