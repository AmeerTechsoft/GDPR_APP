from django.utils import timezone
from django.conf import settings
from django.core.mail import send_mail
from django.template.loader import render_to_string
from datetime import timedelta, datetime
import json
import logging
from typing import Dict, List, Any
from celery import shared_task
from ..models import (
    DataBreach, BreachNotification, ActivityLog,
    DataProcessingActivity, CustomUser
)
from .encryption import encryption_service

logger = logging.getLogger(__name__)

class IncidentResponseService:
    """
    Service for managing data breach incident response
    """
    
    def __init__(self):
        self.response_phases = [
            'identification',
            'containment',
            'eradication',
            'recovery',
            'lessons_learned'
        ]
        self.severity_thresholds = {
            'low': {'affected_users': 10, 'sensitive_data': False},
            'medium': {'affected_users': 100, 'sensitive_data': False},
            'high': {'affected_users': 1000, 'sensitive_data': True},
            'critical': {'affected_users': 10000, 'sensitive_data': True}
        }
    
    def initiate_response(self, breach_id: int) -> Dict[str, Any]:
        """
        Initiate incident response process
        """
        try:
            breach = DataBreach.objects.get(id=breach_id)
            
            # Create initial response plan
            response_plan = self._create_response_plan(breach)
            
            # Update breach with response plan
            breach.response_plan = json.dumps(response_plan)
            breach.save()
            
            # Start response phases
            self._execute_response_phase.delay(breach_id, 'identification')
            
            return {
                'status': 'initiated',
                'breach_id': breach_id,
                'response_plan': response_plan
            }
            
        except Exception as e:
            logger.error(f"Response initiation error: {str(e)}")
            return {'status': 'error', 'error': str(e)}
    
    def _create_response_plan(self, breach: DataBreach) -> Dict[str, Any]:
        """Create incident response plan"""
        return {
            'phases': {
                'identification': {
                    'status': 'pending',
                    'tasks': [
                        'identify_affected_data',
                        'assess_breach_scope',
                        'determine_severity'
                    ]
                },
                'containment': {
                    'status': 'pending',
                    'tasks': [
                        'isolate_affected_systems',
                        'block_unauthorized_access',
                        'preserve_evidence'
                    ]
                },
                'eradication': {
                    'status': 'pending',
                    'tasks': [
                        'remove_malicious_content',
                        'patch_vulnerabilities',
                        'strengthen_controls'
                    ]
                },
                'recovery': {
                    'status': 'pending',
                    'tasks': [
                        'restore_systems',
                        'verify_security',
                        'resume_operations'
                    ]
                },
                'lessons_learned': {
                    'status': 'pending',
                    'tasks': [
                        'analyze_incident',
                        'update_procedures',
                        'conduct_training'
                    ]
                }
            },
            'timeline': [],
            'notifications': {
                'authorities': {'status': 'pending', 'due_by': None},
                'affected_users': {'status': 'pending', 'due_by': None},
                'stakeholders': {'status': 'pending', 'due_by': None}
            }
        }
    
    @shared_task
    def _execute_response_phase(breach_id: int, phase: str):
        """Execute specific response phase"""
        try:
            breach = DataBreach.objects.get(id=breach_id)
            response_plan = json.loads(breach.response_plan)
            
            if phase == 'identification':
                # Identify affected data and users
                affected_data = _identify_affected_data(breach)
                severity = _assess_severity(affected_data)
                
                # Update breach details
                breach.severity = severity
                breach.affected_data = json.dumps(affected_data)
                breach.save()
                
                # Schedule notifications if necessary
                if severity in ['high', 'critical']:
                    _schedule_notifications.delay(breach_id)
                
                # Move to containment phase
                _execute_response_phase.delay(breach_id, 'containment')
                
            elif phase == 'containment':
                # Implement containment measures
                _implement_containment_measures(breach)
                
                # Move to eradication phase
                _execute_response_phase.delay(breach_id, 'eradication')
                
            elif phase == 'eradication':
                # Remove vulnerabilities
                _eradicate_vulnerabilities(breach)
                
                # Move to recovery phase
                _execute_response_phase.delay(breach_id, 'recovery')
                
            elif phase == 'recovery':
                # Restore and verify systems
                _restore_systems(breach)
                
                # Move to lessons learned phase
                _execute_response_phase.delay(breach_id, 'lessons_learned')
                
            elif phase == 'lessons_learned':
                # Conduct post-incident analysis
                _conduct_post_incident_analysis(breach)
                
                # Mark incident as resolved
                breach.resolved = True
                breach.resolution_date = timezone.now()
                breach.save()
            
            # Update response plan
            response_plan['phases'][phase]['status'] = 'completed'
            response_plan['timeline'].append({
                'phase': phase,
                'timestamp': timezone.now().isoformat(),
                'status': 'completed'
            })
            breach.response_plan = json.dumps(response_plan)
            breach.save()
            
        except Exception as e:
            logger.error(f"Response phase execution error: {str(e)}")
            _handle_phase_error(breach_id, phase, str(e))
    
    @staticmethod
    def _identify_affected_data(breach: DataBreach) -> Dict[str, Any]:
        """Identify affected data and users"""
        # Implementation of data identification
        pass
    
    @staticmethod
    def _assess_severity(affected_data: Dict[str, Any]) -> str:
        """Assess breach severity"""
        # Implementation of severity assessment
        pass
    
    @staticmethod
    def _implement_containment_measures(breach: DataBreach):
        """Implement containment measures"""
        # Implementation of containment measures
        pass
    
    @staticmethod
    def _eradicate_vulnerabilities(breach: DataBreach):
        """Remove vulnerabilities"""
        # Implementation of vulnerability eradication
        pass
    
    @staticmethod
    def _restore_systems(breach: DataBreach):
        """Restore and verify systems"""
        # Implementation of system restoration
        pass
    
    @staticmethod
    def _conduct_post_incident_analysis(breach: DataBreach):
        """Conduct post-incident analysis"""
        # Implementation of post-incident analysis
        pass
    
    @shared_task
    def _schedule_notifications(breach_id: int):
        """Schedule and send required notifications"""
        try:
            breach = DataBreach.objects.get(id=breach_id)
            
            # Calculate notification deadlines
            discovery_time = breach.date_discovered
            authority_deadline = discovery_time + timedelta(hours=72)
            user_deadline = discovery_time + timedelta(days=7)
            
            # Schedule notifications
            _notify_authorities.delay(breach_id, authority_deadline)
            _notify_affected_users.delay(breach_id, user_deadline)
            _notify_stakeholders.delay(breach_id)
            
        except Exception as e:
            logger.error(f"Notification scheduling error: {str(e)}")
    
    @shared_task
    def _notify_authorities(breach_id: int, deadline: datetime):
        """Notify supervisory authorities"""
        try:
            breach = DataBreach.objects.get(id=breach_id)
            
            # Prepare notification content
            notification = {
                'breach_details': json.loads(breach.description),
                'affected_users': breach.affected_users.count(),
                'measures_taken': breach.remediation_steps,
                'contact_details': settings.DPO_CONTACT_INFO
            }
            
            # Send notification to authorities
            # Implementation depends on country-specific requirements
            
            # Update breach record
            breach.notification_sent_to_authorities = True
            breach.save()
            
            # Log notification
            ActivityLog.objects.create(
                action='authority_notification_sent',
                details=json.dumps({
                    'breach_id': breach_id,
                    'timestamp': timezone.now().isoformat()
                })
            )
            
        except Exception as e:
            logger.error(f"Authority notification error: {str(e)}")
    
    @shared_task
    def _notify_affected_users(breach_id: int, deadline: datetime):
        """Notify affected users"""
        try:
            breach = DataBreach.objects.get(id=breach_id)
            affected_users = breach.affected_users.all()
            
            for user in affected_users:
                # Create notification record
                notification = BreachNotification.objects.create(
                    user=user,
                    breach=breach
                )
                
                # Send email notification
                context = {
                    'user': user,
                    'breach': breach,
                    'measures_taken': breach.remediation_steps
                }
                
                send_mail(
                    subject='Important: Data Breach Notification',
                    message=render_to_string(
                        'emails/breach_notification.txt',
                        context
                    ),
                    from_email=settings.DEFAULT_FROM_EMAIL,
                    recipient_list=[user.email]
                )
                
                # Update notification record
                notification.notified_at = timezone.now()
                notification.save()
            
        except Exception as e:
            logger.error(f"User notification error: {str(e)}")
    
    @shared_task
    def _notify_stakeholders(breach_id: int):
        """Notify internal stakeholders"""
        try:
            breach = DataBreach.objects.get(id=breach_id)
            
            # Get stakeholder list
            stakeholders = CustomUser.objects.filter(
                roles__name__in=['admin', 'dpo', 'compliance_officer']
            )
            
            # Send notifications
            for stakeholder in stakeholders:
                context = {
                    'user': stakeholder,
                    'breach': breach,
                    'response_plan': json.loads(breach.response_plan)
                }
                
                send_mail(
                    subject='Data Breach Incident Response Update',
                    message=render_to_string(
                        'emails/breach_stakeholder_notification.txt',
                        context
                    ),
                    from_email=settings.DEFAULT_FROM_EMAIL,
                    recipient_list=[stakeholder.email]
                )
            
        except Exception as e:
            logger.error(f"Stakeholder notification error: {str(e)}")
    
    @staticmethod
    def _handle_phase_error(breach_id: int, phase: str, error: str):
        """Handle errors in response phase execution"""
        try:
            breach = DataBreach.objects.get(id=breach_id)
            response_plan = json.loads(breach.response_plan)
            
            # Update phase status
            response_plan['phases'][phase]['status'] = 'error'
            response_plan['timeline'].append({
                'phase': phase,
                'timestamp': timezone.now().isoformat(),
                'status': 'error',
                'error': error
            })
            
            # Save updated plan
            breach.response_plan = json.dumps(response_plan)
            breach.save()
            
            # Log error
            ActivityLog.objects.create(
                action='incident_response_error',
                details=json.dumps({
                    'breach_id': breach_id,
                    'phase': phase,
                    'error': error,
                    'timestamp': timezone.now().isoformat()
                })
            )
            
            # Notify DPO
            _notify_dpo_error.delay(breach_id, phase, error)
            
        except Exception as e:
            logger.error(f"Error handling error: {str(e)}")

# Global incident response service instance
incident_response_service = IncidentResponseService()

@shared_task
def _notify_dpo_error(breach_id: int, phase: str, error: str):
    """Notify DPO about response phase error"""
    try:
        breach = DataBreach.objects.get(id=breach_id)
        dpo = CustomUser.objects.filter(roles__name='dpo').first()
        
        if dpo:
            context = {
                'user': dpo,
                'breach': breach,
                'phase': phase,
                'error': error
            }
            
            send_mail(
                subject='Incident Response Error Alert',
                message=render_to_string(
                    'emails/breach_response_error.txt',
                    context
                ),
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[dpo.email]
            )
            
    except Exception as e:
        logger.error(f"DPO error notification error: {str(e)}") 