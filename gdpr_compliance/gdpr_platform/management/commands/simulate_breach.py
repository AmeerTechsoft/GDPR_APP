from django.core.management.base import BaseCommand
from django.utils import timezone
from gdpr_platform.models import DataBreach, BreachNotification
from django.contrib.auth import get_user_model
import os
import django


class Command(BaseCommand):
#     help = 'Simulates a data breach incident for testing purposes'

#     def add_arguments(self, parser):
#         parser.add_argument(
#             '--severity',
#             type=str,
#             default='medium',
#             choices=['low', 'medium', 'high', 'critical'],
#             help='Severity level of the simulated breach'
#         )
#         parser.add_argument(
#             '--users',
#             type=int,
#             default=5,
#             help='Number of users to affect (default: 5)'
#         )
#         parser.add_argument(
#             '--notify',
#             action='store_true',
#             help='Send actual email notifications'
#         )

#     def handle(self, *args, **options):
#         severity = options['severity']
#         num_users = options['users']
#         should_notify = options['notify']

#         # Enhanced breach scenarios with specific data types affected
#         scenarios = {
#             'low': {
#                 'title': 'Minor Data Exposure Incident',
#                 'description': 'A temporary misconfiguration led to limited exposure of non-sensitive user data.',
#                 'remediation': 'Configuration has been corrected and access logs have been reviewed.',
#                 'compromised_data': [
#                     'Public profile information',
#                     'Username'
#                 ]
#             },
#             'medium': {
#                 'title': 'Unauthorized Access Attempt',
#                 'description': 'Suspicious login attempts detected from unknown IP addresses.',
#                 'remediation': 'Account security measures enhanced and affected users notified.',
#                 'compromised_data': [
#                     'Email addresses',
#                     'Login timestamps',
#                     'IP addresses'
#                 ]
#             },
#             'high': {
#                 'title': 'Data Security Breach',
#                 'description': 'Unauthorized access detected to user profile information and encrypted data.',
#                 'remediation': 'Systems secured, passwords reset, and enhanced monitoring implemented.',
#                 'compromised_data': [
#                     'Full name',
#                     'Email address',
#                     'Phone numbers',
#                     'Encrypted password hashes',
#                     'Account preferences'
#                 ]
#             },
#             'critical': {
#                 'title': 'Major Security Incident',
#                 'description': 'Significant data breach affecting user personal information and system data.',
#                 'remediation': 'Emergency security protocols activated, external security audit initiated.',
#                 'compromised_data': [
#                     'Full name',
#                     'Email address',
#                     'Phone numbers',
#                     'Address information',
#                     'Account history',
#                     'User preferences',
#                     'Session data'
#                 ]
#             }
#         }

#         scenario = scenarios[severity]

#         # Create the breach incident with compromised data details
#         breach = DataBreach.objects.create(
#             title=scenario['title'],
#             description=scenario['description'],
#             severity=severity,
#             date_discovered=timezone.now(),
#             date_reported=timezone.now(),
#             remediation_steps=scenario['remediation'],
#             notification_sent_to_authorities=(severity in ['high', 'critical']),
#             affected_data_categories=', '.join(scenario['compromised_data'])
#         )

#         # Select random users to affect
#         all_users = list(User.objects.all())
#         if len(all_users) < num_users:
#             num_users = len(all_users)
        
#         affected_users = random.sample(all_users, num_users)

#         # Create notifications for affected users
#         for user in affected_users:
#             notification = BreachNotification.objects.create(
#                 user=user,
#                 breach=breach,
#                 notification_method='email',
#                 compromised_data=scenario['compromised_data']
#             )

#             if should_notify:
#                 # Send actual email notification with enhanced context
#                 context = {
#                     'user': user,
#                     'breach': breach,
#                     'notification': notification,
#                     'compromised_data': scenario['compromised_data'],
#                     'protocol': 'https',
#                     'domain': settings.ALLOWED_HOSTS[0] if settings.ALLOWED_HOSTS else 'localhost:8000'
#                 }
                
#                 email_html = render_to_string('emails/breach_notification.html', context)
#                 email_subject = f'Security Alert: {breach.title}'
                
#                 try:
#                     send_mail(
#                         subject=email_subject,
#                         message='Please view this email in HTML format.',
#                         from_email=settings.DEFAULT_FROM_EMAIL,
#                         recipient_list=[user.email],
#                         html_message=email_html,
#                         fail_silently=False,
#                     )
#                     self.stdout.write(self.style.SUCCESS(f'Notification sent to {user.email}'))
#                 except Exception as e:
#                     self.stdout.write(self.style.ERROR(f'Failed to send notification to {user.email}: {str(e)}'))

#         self.stdout.write(self.style.SUCCESS(
#             f'Successfully simulated {severity} breach incident:\n'
#             f'Title: {breach.title}\n'
#             f'Affected Users: {num_users}\n'
#             f'Compromised Data: {", ".join(scenario["compromised_data"])}\n'
#             f'Notifications {"sent" if should_notify else "simulated"}'
#         )) 

    # Set up Django environment
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'gdpr_compliance.settings')
    django.setup()

    User = get_user_model()

    def simulate_breach():
        # Create a high-severity breach
        breach = DataBreach.objects.create(
            title='Data Security Breach',
            description='Unauthorized access detected to user profile information and encrypted data.',
            severity='high',
            date_discovered=timezone.now(),
            date_reported=timezone.now(),
            breach_type='unauthorized_access',
            impact_assessment='High risk to user privacy and data security.',
            remediation_steps='Systems secured, passwords reset, and enhanced monitoring implemented.',
            affected_data_categories=['Full name', 'Email address', 'Phone numbers', 'Account preferences'],
            authority_notified=True,
            users_notified=True
        )

        # Affect 5 random users
        affected_users = User.objects.all()[:5]
        breach.affected_users.add(*affected_users)

        # Create notifications
        for user in affected_users:
            BreachNotification.objects.create(
                breach=breach,
                recipient=user,
                status='sent',
                sent_at=timezone.now(),
                notification_method='email',
                notification_data={
                    'compromised_data': breach.affected_data_categories,
                    'severity': breach.severity,
                    'remediation': breach.remediation_steps
                }
            )

        print(f'Created breach {breach.id} affecting {affected_users.count()} users')

    if __name__ == '__main__':
        simulate_breach() 