from django.utils import timezone
from django.db.models import Q
from datetime import timedelta
import json
import logging
from typing import Dict, List, Any
from celery import shared_task
from ..models import (
    DataProcessingActivity, DataRequest, CrossBorderTransfer,
    PrivacyPolicy, UserPrivacyPolicyConsent, DataBreach,
    ActivityLog
)

logger = logging.getLogger(__name__)

class ComplianceCheckerService:
    """
    Service for automated GDPR compliance verification
    """
    
    def __init__(self):
        self.compliance_rules = {
            'data_retention': {
                'max_retention_period': 730,  # days
                'check_frequency': 30,  # days
            },
            'consent_validity': {
                'max_age': 365,  # days
                'check_frequency': 90,  # days
            },
            'breach_notification': {
                'max_notification_delay': 72,  # hours
                'check_frequency': 1,  # days
            },
            'data_request_response': {
                'max_response_time': 30,  # days
                'check_frequency': 7,  # days
            }
        }
    
    def run_compliance_check(self) -> Dict[str, Any]:
        """
        Run comprehensive compliance check
        """
        try:
            results = {
                'timestamp': timezone.now(),
                'overall_status': 'compliant',
                'checks': {}
            }
            
            # Run individual checks
            checks = [
                self._check_data_retention,
                self._check_consent_validity,
                self._check_breach_notifications,
                self._check_data_requests,
                self._check_processing_activities,
                self._check_cross_border_transfers
            ]
            
            for check in checks:
                check_result = check()
                results['checks'][check.__name__] = check_result
                if check_result['status'] == 'non_compliant':
                    results['overall_status'] = 'non_compliant'
            
            # Log compliance check results
            self._log_compliance_check(results)
            
            # Schedule remediation tasks if needed
            if results['overall_status'] == 'non_compliant':
                self._schedule_remediation_tasks(results)
            
            return results
            
        except Exception as e:
            logger.error(f"Compliance check error: {str(e)}")
            return {
                'timestamp': timezone.now(),
                'overall_status': 'error',
                'error': str(e)
            }
    
    def _check_data_retention(self) -> Dict[str, Any]:
        """Check data retention compliance"""
        try:
            max_period = self.compliance_rules['data_retention']['max_retention_period']
            cutoff_date = timezone.now() - timedelta(days=max_period)
            
            # Check for data beyond retention period
            expired_data = DataProcessingActivity.objects.filter(
                retention_end_date__lt=cutoff_date,
                status='active'
            )
            
            if expired_data.exists():
                return {
                    'status': 'non_compliant',
                    'issues': [{
                        'type': 'expired_data_retention',
                        'count': expired_data.count(),
                        'details': 'Data retained beyond maximum retention period'
                    }],
                    'remediation': 'schedule_data_deletion'
                }
            
            return {'status': 'compliant'}
            
        except Exception as e:
            logger.error(f"Data retention check error: {str(e)}")
            return {'status': 'error', 'error': str(e)}
    
    def _check_consent_validity(self) -> Dict[str, Any]:
        """Check consent validity"""
        try:
            max_age = self.compliance_rules['consent_validity']['max_age']
            cutoff_date = timezone.now() - timedelta(days=max_age)
            
            # Check for expired consents
            expired_consents = UserPrivacyPolicyConsent.objects.filter(
                consent_date__lt=cutoff_date,
                is_active=True
            )
            
            if expired_consents.exists():
                return {
                    'status': 'non_compliant',
                    'issues': [{
                        'type': 'expired_consent',
                        'count': expired_consents.count(),
                        'details': 'User consents have expired'
                    }],
                    'remediation': 'renew_user_consents'
                }
            
            return {'status': 'compliant'}
            
        except Exception as e:
            logger.error(f"Consent validity check error: {str(e)}")
            return {'status': 'error', 'error': str(e)}
    
    def _check_breach_notifications(self) -> Dict[str, Any]:
        """Check breach notification compliance"""
        try:
            max_delay = self.compliance_rules['breach_notification']['max_notification_delay']
            cutoff_time = timezone.now() - timedelta(hours=max_delay)
            
            # Check for unnotified breaches
            unnotified_breaches = DataBreach.objects.filter(
                date_discovered__lt=cutoff_time,
                notification_sent_to_authorities=False
            )
            
            if unnotified_breaches.exists():
                return {
                    'status': 'non_compliant',
                    'issues': [{
                        'type': 'delayed_breach_notification',
                        'count': unnotified_breaches.count(),
                        'details': 'Data breaches not reported within 72 hours'
                    }],
                    'remediation': 'send_breach_notifications'
                }
            
            return {'status': 'compliant'}
            
        except Exception as e:
            logger.error(f"Breach notification check error: {str(e)}")
            return {'status': 'error', 'error': str(e)}
    
    def _check_data_requests(self) -> Dict[str, Any]:
        """Check data request response compliance"""
        try:
            max_response_time = self.compliance_rules['data_request_response']['max_response_time']
            cutoff_date = timezone.now() - timedelta(days=max_response_time)
            
            # Check for overdue requests
            overdue_requests = DataRequest.objects.filter(
                request_date__lt=cutoff_date,
                status='pending'
            )
            
            if overdue_requests.exists():
                return {
                    'status': 'non_compliant',
                    'issues': [{
                        'type': 'overdue_data_requests',
                        'count': overdue_requests.count(),
                        'details': 'Data subject requests not processed within time limit'
                    }],
                    'remediation': 'process_overdue_requests'
                }
            
            return {'status': 'compliant'}
            
        except Exception as e:
            logger.error(f"Data request check error: {str(e)}")
            return {'status': 'error', 'error': str(e)}
    
    def _check_processing_activities(self) -> Dict[str, Any]:
        """Check processing activities compliance"""
        try:
            issues = []
            
            # Check for processing without legal basis
            invalid_processing = DataProcessingActivity.objects.filter(
                Q(legal_basis__isnull=True) | Q(legal_basis='')
            )
            if invalid_processing.exists():
                issues.append({
                    'type': 'missing_legal_basis',
                    'count': invalid_processing.count(),
                    'details': 'Processing activities without valid legal basis'
                })
            
            # Check for high-risk processing without impact assessment
            high_risk_processing = DataProcessingActivity.objects.filter(
                risk_level='high',
                impact_assessment_date__isnull=True
            )
            if high_risk_processing.exists():
                issues.append({
                    'type': 'missing_impact_assessment',
                    'count': high_risk_processing.count(),
                    'details': 'High-risk processing without impact assessment'
                })
            
            if issues:
                return {
                    'status': 'non_compliant',
                    'issues': issues,
                    'remediation': 'review_processing_activities'
                }
            
            return {'status': 'compliant'}
            
        except Exception as e:
            logger.error(f"Processing activities check error: {str(e)}")
            return {'status': 'error', 'error': str(e)}
    
    def _check_cross_border_transfers(self) -> Dict[str, Any]:
        """Check cross-border transfer compliance"""
        try:
            issues = []
            
            # Check for transfers without adequate safeguards
            invalid_transfers = CrossBorderTransfer.objects.filter(
                Q(transfer_mechanism__isnull=True) |
                Q(safeguards__isnull=True)
            )
            if invalid_transfers.exists():
                issues.append({
                    'type': 'invalid_transfer_mechanism',
                    'count': invalid_transfers.count(),
                    'details': 'Cross-border transfers without adequate safeguards'
                })
            
            # Check for expired transfer agreements
            expired_transfers = CrossBorderTransfer.objects.filter(
                expiry_date__lt=timezone.now(),
                status='active'
            )
            if expired_transfers.exists():
                issues.append({
                    'type': 'expired_transfer_agreement',
                    'count': expired_transfers.count(),
                    'details': 'Expired cross-border transfer agreements'
                })
            
            if issues:
                return {
                    'status': 'non_compliant',
                    'issues': issues,
                    'remediation': 'review_cross_border_transfers'
                }
            
            return {'status': 'compliant'}
            
        except Exception as e:
            logger.error(f"Cross-border transfer check error: {str(e)}")
            return {'status': 'error', 'error': str(e)}
    
    def _log_compliance_check(self, results: Dict[str, Any]):
        """Log compliance check results"""
        ActivityLog.objects.create(
            action='compliance_check',
            details=json.dumps(results)
        )
    
    def _schedule_remediation_tasks(self, results: Dict[str, Any]):
        """Schedule remediation tasks for non-compliant items"""
        for check_name, check_result in results['checks'].items():
            if check_result.get('status') == 'non_compliant':
                remediation_task = check_result.get('remediation')
                if remediation_task:
                    schedule_remediation.delay(
                        remediation_task,
                        check_result['issues']
                    )

# Global compliance checker service instance
compliance_checker_service = ComplianceCheckerService()

@shared_task
def schedule_remediation(task_type: str, issues: List[Dict[str, Any]]):
    """Schedule and execute remediation tasks"""
    # Implementation of remediation scheduling
    pass

@shared_task
def run_scheduled_compliance_check():
    """Run scheduled compliance check"""
    compliance_checker_service.run_compliance_check() 