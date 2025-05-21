from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.conf import settings
from django.utils import timezone
from typing import List, Dict, Any
import logging
from celery import shared_task
from ..models import DataBreach, CustomUser

logger = logging.getLogger(__name__)

class NotificationService:
    """Service for handling GDPR-related notifications"""
    
    def __init__(self):
        self.email_templates = {
            'breach_user': 'emails/breach_notification.txt',
            'breach_stakeholder': 'emails/breach_stakeholder_notification.txt',
        }
    
    def notify_breach_affected_users(self, breach_id: int):
        """Send notifications to users affected by a breach"""
        try:
            breach = DataBreach.objects.get(id=breach_id)
            affected_users = breach.affected_users.all()
            
            # Prepare common context
            measures_taken = [
                "Implemented additional security measures",
                "Enhanced monitoring systems",
                "Updated access controls",
                "Conducted security audit"
            ]
            
            for user in affected_users:
                context = {
                    'user': user,
                    'breach': breach,
                    'settings': settings,
                    'measures_taken': measures_taken
                }
                
                # Send email notification
                self._send_breach_email(
                    template_name=self.email_templates['breach_user'],
                    context=context,
                    recipient_email=user.email,
                    subject=f"Important Security Notice - {settings.PLATFORM_NAME}"
                )
                
                # Log notification
                breach.BreachNotification_set.create(
                    user=user,
                    notified_at=timezone.now()
                )
                
        except Exception as e:
            logger.error(f"Error notifying breach affected users: {str(e)}")
            raise
    
    def notify_breach_stakeholders(self, breach_id: int):
        """Send notifications to stakeholders about a breach"""
        try:
            breach = DataBreach.objects.get(id=breach_id)
            
            # Get stakeholders (DPO, Compliance Officers, Admins)
            stakeholders = CustomUser.objects.filter(
                roles__name__in=['dpo', 'compliance_officer', 'admin']
            ).distinct()
            
            # Get response plan
            response_plan = self._get_response_plan(breach)
            
            for user in stakeholders:
                context = {
                    'user': user,
                    'breach': breach,
                    'settings': settings,
                    'response_plan': response_plan
                }
                
                # Send email notification
                self._send_breach_email(
                    template_name=self.email_templates['breach_stakeholder'],
                    context=context,
                    recipient_email=user.email,
                    subject=f"URGENT: Data Breach Incident {breach.id} - Action Required"
                )
                
        except Exception as e:
            logger.error(f"Error notifying breach stakeholders: {str(e)}")
            raise
    
    def _send_breach_email(self, template_name: str, context: Dict[str, Any],
                          recipient_email: str, subject: str):
        """Send email using template"""
        try:
            # Render email content
            email_content = render_to_string(template_name, context)
            
            # Send email
            send_mail(
                subject=subject,
                message=email_content,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[recipient_email],
                fail_silently=False
            )
            
            logger.info(f"Sent breach notification email to {recipient_email}")
            
        except Exception as e:
            logger.error(f"Error sending breach email: {str(e)}")
            raise
    
    def _get_response_plan(self, breach: DataBreach) -> Dict[str, Any]:
        """Get formatted response plan for stakeholder notification"""
        return {
            'phases': {
                'containment': {
                    'status': 'in_progress',
                    'tasks': [
                        'Isolate affected systems',
                        'Block suspicious IP addresses',
                        'Reset compromised credentials'
                    ]
                },
                'investigation': {
                    'status': 'pending',
                    'tasks': [
                        'Analyze breach scope and impact',
                        'Identify affected data types',
                        'Determine breach vector'
                    ]
                },
                'remediation': {
                    'status': 'pending',
                    'tasks': [
                        'Patch vulnerabilities',
                        'Update security measures',
                        'Implement additional monitoring'
                    ]
                }
            },
            'timeline': [
                {
                    'timestamp': breach.date_discovered,
                    'phase': 'detection',
                    'status': 'completed'
                },
                {
                    'timestamp': timezone.now(),
                    'phase': 'containment',
                    'status': 'in_progress'
                }
            ],
            'notifications': {
                'authorities': {
                    'status': 'pending',
                    'due_by': breach.date_discovered + timezone.timedelta(hours=72)
                },
                'affected_users': {
                    'status': 'in_progress',
                    'due_by': breach.date_discovered + timezone.timedelta(hours=24)
                }
            }
        }

# Global notification service instance
notification_service = NotificationService()

@shared_task
def send_breach_notifications(breach_id: int):
    """Celery task to send breach notifications"""
    notification_service.notify_breach_affected_users(breach_id)
    notification_service.notify_breach_stakeholders(breach_id) 