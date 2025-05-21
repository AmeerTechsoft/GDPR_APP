from django.db.models import Q
from django.utils import timezone
from datetime import timedelta
import json
import logging
from typing import Dict, List, Any
from django.core.cache import cache
from celery import shared_task
from ..models import (
    DataBreach, UserSession, ActivityLog,
    DataProcessingActivity, BreachNotification, CustomUser,
    AuditLog
)
from .encryption import encryption_service
from .notification import notification_service
from django.conf import settings

logger = logging.getLogger(__name__)

class BreachDetectionService:
    """
    Service for real-time breach detection and automated response
    """
    
    def __init__(self):
        self.anomaly_thresholds = {
            'failed_logins': {
                'count': 5,  # Number of failed logins
                'window': 15,  # Time window in minutes
                'severity': 'medium'
            },
            'data_access': {
                'count': 100,  # Number of records
                'window': 15,  # Time window in minutes
                'severity': 'medium'
            },
            'unusual_time': {
                'start': 22,  # 10 PM
                'end': 5,     # 5 AM
                'severity': 'low'
            },
            'multiple_countries': {
                'count': 3,  # Different countries
                'window': 60,  # Time window in minutes
                'severity': 'high'
            },
            'sensitive_data': {
                'count': 50,  # Number of sensitive records
                'window': 15,  # Time window in minutes
                'severity': 'high'
            },
            'bulk_deletion': {
                'count': 100,  # Number of records
                'window': 5,   # Time window in minutes
                'severity': 'high'
            },
            'unauthorized_export': {
                'count': 1000,  # Number of records
                'window': 60,   # Time window in minutes
                'severity': 'high'
            },
            'api_abuse': {
                'count': 1000,  # Number of requests
                'window': 5,    # Time window in minutes
                'severity': 'medium'
            },
            'concurrent_sessions': {
                'count': 3,     # Number of active sessions
                'severity': 'medium'
            }
        }
        self.time_window = timedelta(minutes=15)
        self.sensitive_data_types = [
            'health_data',
            'financial_data',
            'biometric_data',
            'genetic_data',
            'racial_data',
            'political_opinions',
            'religious_beliefs',
            'sexual_orientation'
        ]
        self.automated_responses = {
            'excessive_failed_logins': [
                self._block_user_login,
                self._force_password_reset,
                self._notify_security_team
            ],
            'multiple_country_access': [
                self._block_suspicious_ips,
                self._force_2fa,
                self._notify_security_team
            ],
            'excessive_sensitive_data_access': [
                self._revoke_sensitive_access,
                self._notify_dpo,
                self._log_sensitive_access
            ],
            'bulk_deletion': [
                self._suspend_deletion_rights,
                self._backup_deleted_data,
                self._notify_dpo
            ],
            'unauthorized_export': [
                self._block_data_export,
                self._log_export_attempt,
                self._notify_security_team
            ],
            'api_abuse': [
                self._rate_limit_api,
                self._block_abusive_ips,
                self._notify_security_team
            ],
            'concurrent_sessions': [
                self._terminate_old_sessions,
                self._force_2fa,
                self._notify_user
            ]
        }
    
    def monitor_activity(self, user_id: str, activity_type: str, details: Dict[str, Any]):
        """
        Monitor user activity for potential breaches
        """
        try:
            # Get recent activity for user
            recent_activity = self._get_recent_activity(user_id)
            recent_activity.append({
                'timestamp': timezone.now(),
                'type': activity_type,
                'details': details
            })
            
            # Check for anomalies
            anomalies = self._detect_anomalies(recent_activity)
            if anomalies:
                self._handle_potential_breach(user_id, anomalies, recent_activity)
            
            # Update activity cache
            self._update_activity_cache(user_id, recent_activity)
            
        except Exception as e:
            logger.error(f"Activity monitoring error: {str(e)}")
    
    def _get_recent_activity(self, user_id: str) -> List[Dict[str, Any]]:
        """Get recent activity from cache"""
        cache_key = f"user_activity_{user_id}"
        activity = cache.get(cache_key, [])
        
        # Filter out old activity
        cutoff_time = timezone.now() - self.time_window
        return [a for a in activity if a['timestamp'] > cutoff_time]
    
    def _detect_anomalies(self, activity: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Enhanced anomaly detection with more specific rules
        """
        anomalies = []
        current_time = timezone.now()
        
        # Check failed login attempts
        failed_logins = self._count_recent_activity(
            activity, 
            'login', 
            lambda x: x['details'].get('status') == 'failed',
            self.anomaly_thresholds['failed_logins']['window']
        )
        if failed_logins >= self.anomaly_thresholds['failed_logins']['count']:
            anomalies.append({
                'type': 'excessive_failed_logins',
                'severity': self.anomaly_thresholds['failed_logins']['severity'],
                'details': {'count': failed_logins}
            })
        
        # Check data access patterns
        data_access = self._count_recent_activity(
            activity, 
            'data_access',
            None,
            self.anomaly_thresholds['data_access']['window']
        )
        if data_access >= self.anomaly_thresholds['data_access']['count']:
            anomalies.append({
                'type': 'excessive_data_access',
                'severity': self.anomaly_thresholds['data_access']['severity'],
                'details': {'count': data_access}
            })
        
        # Check for unusual access times
        current_hour = current_time.hour
        if (current_hour >= self.anomaly_thresholds['unusual_time']['start'] or 
            current_hour <= self.anomaly_thresholds['unusual_time']['end']):
            anomalies.append({
                'type': 'unusual_access_time',
                'severity': self.anomaly_thresholds['unusual_time']['severity'],
                'details': {'hour': current_hour}
            })
        
        # Check for access from multiple countries
        countries = self._get_recent_unique_values(
            activity,
            'country',
            self.anomaly_thresholds['multiple_countries']['window']
        )
        if len(countries) >= self.anomaly_thresholds['multiple_countries']['count']:
            anomalies.append({
                'type': 'multiple_country_access',
                'severity': self.anomaly_thresholds['multiple_countries']['severity'],
                'details': {'countries': list(countries)}
            })
        
        # Check sensitive data access
        sensitive_access = self._count_recent_activity(
            activity,
            'data_access',
            lambda x: any(t in x['details'].get('data_types', []) 
                         for t in self.sensitive_data_types),
            self.anomaly_thresholds['sensitive_data']['window']
        )
        if sensitive_access >= self.anomaly_thresholds['sensitive_data']['count']:
            anomalies.append({
                'type': 'excessive_sensitive_data_access',
                'severity': self.anomaly_thresholds['sensitive_data']['severity'],
                'details': {'count': sensitive_access}
            })
        
        # Check for bulk deletions
        deletions = self._count_recent_activity(
            activity,
            'data_deletion',
            None,
            self.anomaly_thresholds['bulk_deletion']['window']
        )
        if deletions >= self.anomaly_thresholds['bulk_deletion']['count']:
            anomalies.append({
                'type': 'bulk_deletion',
                'severity': self.anomaly_thresholds['bulk_deletion']['severity'],
                'details': {'count': deletions}
            })
        
        # Check for unauthorized exports
        exports = self._count_recent_activity(
            activity,
            'data_export',
            None,
            self.anomaly_thresholds['unauthorized_export']['window']
        )
        if exports >= self.anomaly_thresholds['unauthorized_export']['count']:
            anomalies.append({
                'type': 'unauthorized_export',
                'severity': self.anomaly_thresholds['unauthorized_export']['severity'],
                'details': {'count': exports}
            })
        
        # Check for API abuse
        api_requests = self._count_recent_activity(
            activity,
            'api_request',
            None,
            self.anomaly_thresholds['api_abuse']['window']
        )
        if api_requests >= self.anomaly_thresholds['api_abuse']['count']:
            anomalies.append({
                'type': 'api_abuse',
                'severity': self.anomaly_thresholds['api_abuse']['severity'],
                'details': {'count': api_requests}
            })
        
        # Check for concurrent sessions
        active_sessions = self._count_concurrent_sessions(activity)
        if active_sessions >= self.anomaly_thresholds['concurrent_sessions']['count']:
            anomalies.append({
                'type': 'concurrent_sessions',
                'severity': self.anomaly_thresholds['concurrent_sessions']['severity'],
                'details': {'count': active_sessions}
            })
        
        return anomalies
    
    def _count_recent_activity(self, activity: List[Dict[str, Any]], 
                             activity_type: str, condition_func: callable = None,
                             window_minutes: int = 15) -> int:
        """Count recent activity of a specific type within time window"""
        cutoff_time = timezone.now() - timedelta(minutes=window_minutes)
        return sum(1 for a in activity 
                  if a['type'] == activity_type 
                  and a['timestamp'] >= cutoff_time
                  and (condition_func is None or condition_func(a)))
    
    def _get_recent_unique_values(self, activity: List[Dict[str, Any]], 
                                field: str, window_minutes: int = 15) -> set:
        """Get unique values for a field from recent activity"""
        cutoff_time = timezone.now() - timedelta(minutes=window_minutes)
        return set(a['details'].get(field) for a in activity 
                  if a['timestamp'] >= cutoff_time 
                  and field in a['details'])
    
    def _count_concurrent_sessions(self, activity: List[Dict[str, Any]]) -> int:
        """Count number of concurrent active sessions"""
        active_sessions = set()
        for a in activity:
            if a['type'] == 'session':
                if a['details'].get('action') == 'login':
                    active_sessions.add(a['details'].get('session_id'))
                elif a['details'].get('action') == 'logout':
                    active_sessions.discard(a['details'].get('session_id'))
        return len(active_sessions)
    
    def _handle_potential_breach(self, user_id: str, anomalies: List[Dict[str, Any]], 
                               activity: List[Dict[str, Any]]):
        """Enhanced breach handling with automated responses"""
        try:
            # Calculate risk score
            risk_score = self._calculate_risk_score(anomalies)
            
            # Create breach incident
            breach = DataBreach.objects.create(
                title=f"Potential Security Breach - User {user_id}",
                description=json.dumps({
                    'anomalies': anomalies,
                    'activity': activity
                }),
                severity='high' if risk_score > 0.7 else 'medium',
                date_discovered=timezone.now(),
                ai_detected=True,
                risk_score=risk_score
            )
            
            # Execute automated responses
            self._execute_automated_responses(breach, anomalies, user_id)
            
            # Send notifications
            send_breach_notifications.delay(breach.id)
            
        except Exception as e:
            logger.error(f"Breach handling error: {str(e)}")
    
    def _execute_automated_responses(self, breach: DataBreach, 
                                  anomalies: List[Dict[str, Any]], user_id: str):
        """Execute automated responses based on anomaly types"""
        try:
            for anomaly in anomalies:
                anomaly_type = anomaly['type']
                if anomaly_type in self.automated_responses:
                    for response_func in self.automated_responses[anomaly_type]:
                        try:
                            response_func(breach, user_id, anomaly)
                        except Exception as e:
                            logger.error(f"Response function error: {str(e)}")
                            continue
        except Exception as e:
            logger.error(f"Error executing automated responses: {str(e)}")
    
    def _block_user_login(self, breach: DataBreach, user_id: str, 
                         anomaly: Dict[str, Any]):
        """Temporarily block user login"""
        try:
            user = CustomUser.objects.get(id=user_id)
            user.is_active = False
            user.save()
            
            # Set reactivation time
            cache.set(f"login_blocked_{user_id}", True, timeout=3600)  # 1 hour
            
            logger.info(f"Blocked login for user {user_id}")
        except Exception as e:
            logger.error(f"Error blocking user login: {str(e)}")
    
    def _force_password_reset(self, breach: DataBreach, user_id: str, 
                            anomaly: Dict[str, Any]):
        """Force user to reset password"""
        try:
            user = CustomUser.objects.get(id=user_id)
            user.set_unusable_password()
            user.save()
            
            # Send password reset email
            # Implementation depends on your password reset flow
            logger.info(f"Forced password reset for user {user_id}")
        except Exception as e:
            logger.error(f"Error forcing password reset: {str(e)}")
    
    def _block_suspicious_ips(self, breach: DataBreach, user_id: str, 
                            anomaly: Dict[str, Any]):
        """Block suspicious IP addresses"""
        try:
            suspicious_ips = anomaly['details'].get('countries', {}).values()
            for ip in suspicious_ips:
                cache.set(f"blocked_ip_{ip}", True, timeout=3600)  # 1 hour
            
            logger.info(f"Blocked suspicious IPs: {suspicious_ips}")
        except Exception as e:
            logger.error(f"Error blocking suspicious IPs: {str(e)}")
    
    def _force_2fa(self, breach: DataBreach, user_id: str, 
                  anomaly: Dict[str, Any]):
        """Force 2FA for user"""
        try:
            user = CustomUser.objects.get(id=user_id)
            user.two_factor_enabled = True
            user.save()
            
            logger.info(f"Forced 2FA for user {user_id}")
        except Exception as e:
            logger.error(f"Error forcing 2FA: {str(e)}")
    
    def _revoke_sensitive_access(self, breach: DataBreach, user_id: str, 
                               anomaly: Dict[str, Any]):
        """Revoke access to sensitive data"""
        try:
            user = CustomUser.objects.get(id=user_id)
            # Implementation depends on your permission system
            sensitive_permissions = [
                'view_sensitive_data',
                'export_sensitive_data'
            ]
            user.user_permissions.remove(*sensitive_permissions)
            
            logger.info(f"Revoked sensitive access for user {user_id}")
        except Exception as e:
            logger.error(f"Error revoking sensitive access: {str(e)}")
    
    def _backup_deleted_data(self, breach: DataBreach, user_id: str, 
                           anomaly: Dict[str, Any]):
        """Create backup of deleted data"""
        try:
            # Implementation depends on your backup system
            deleted_count = anomaly['details'].get('count', 0)
            logger.info(f"Backup triggered for {deleted_count} deleted items")
        except Exception as e:
            logger.error(f"Error creating backup: {str(e)}")
    
    def _rate_limit_api(self, breach: DataBreach, user_id: str, 
                       anomaly: Dict[str, Any]):
        """Implement stricter rate limiting"""
        try:
            cache.set(f"strict_rate_limit_{user_id}", True, timeout=3600)  # 1 hour
            logger.info(f"Enabled strict rate limiting for user {user_id}")
        except Exception as e:
            logger.error(f"Error setting rate limit: {str(e)}")
    
    def _block_abusive_ips(self, breach: DataBreach, user_id: str, anomaly: Dict[str, Any]):
        """Block IPs associated with API abuse"""
        try:
            user = CustomUser.objects.get(id=user_id)
            # Get recent IP addresses from activity logs
            recent_ips = ActivityLog.objects.filter(
                user=user,
                action='api_request',
                timestamp__gte=timezone.now() - timedelta(hours=1)
            ).values_list('ip_address', flat=True).distinct()

            # Block each IP
            for ip in recent_ips:
                cache.set(f"blocked_ip_{ip}", True, timeout=7200)  # 2 hours
                
                # Log the action
                AuditLog.objects.create(
                    user=user,
                    action='block_abusive_ip',
                    resource_type='ip_address',
                    resource_id=ip,
                    details={
                        'reason': 'API abuse detected',
                        'anomaly': anomaly,
                        'breach_id': str(breach.id)
                    }
                )
            
            # Update breach record
            breach.containment_measures = json.dumps({
                'action': 'block_abusive_ips',
                'timestamp': timezone.now().isoformat(),
                'details': f'Blocked {len(recent_ips)} abusive IPs',
                'ips': list(recent_ips)
            })
            breach.save()
            
            logger.warning(f"Blocked {len(recent_ips)} abusive IPs for user {user_id}")
        except Exception as e:
            logger.error(f"Error blocking abusive IPs: {str(e)}")
    
    def _terminate_old_sessions(self, breach: DataBreach, user_id: str, 
                              anomaly: Dict[str, Any]):
        """Terminate all but the most recent session"""
        try:
            from django.contrib.sessions.models import Session
            user = CustomUser.objects.get(id=user_id)
            
            # Keep only the most recent session
            sessions = Session.objects.filter(usersession__user=user)
            if sessions.count() > 1:
                most_recent = sessions.latest('usersession__last_activity')
                sessions.exclude(pk=most_recent.pk).delete()
            
            logger.info(f"Terminated old sessions for user {user_id}")
        except Exception as e:
            logger.error(f"Error terminating sessions: {str(e)}")
    
    def _notify_security_team(self, breach: DataBreach, user_id: str, 
                            anomaly: Dict[str, Any]):
        """Notify security team"""
        try:
            notification_service.notify_breach_stakeholders(breach.id)
            logger.info(f"Notified security team about breach {breach.id}")
        except Exception as e:
            logger.error(f"Error notifying security team: {str(e)}")
    
    def _notify_dpo(self, breach: DataBreach, user_id: str, 
                   anomaly: Dict[str, Any]):
        """Notify DPO specifically"""
        try:
            dpo = CustomUser.objects.filter(roles__name='dpo').first()
            if dpo:
                notification_service._send_breach_email(
                    template_name='emails/breach_stakeholder_notification.txt',
                    context={
                        'user': dpo,
                        'breach': breach,
                        'settings': settings,
                        'response_plan': notification_service._get_response_plan(breach)
                    },
                    recipient_email=dpo.email,
                    subject=f"URGENT: DPO Action Required - Breach {breach.id}"
                )
            logger.info(f"Notified DPO about breach {breach.id}")
        except Exception as e:
            logger.error(f"Error notifying DPO: {str(e)}")
    
    def _notify_user(self, breach: DataBreach, user_id: str, 
                    anomaly: Dict[str, Any]):
        """Notify affected user"""
        try:
            user = CustomUser.objects.get(id=user_id)
            notification_service.notify_breach_affected_users(breach.id)
            logger.info(f"Notified user {user_id} about breach {breach.id}")
        except Exception as e:
            logger.error(f"Error notifying user: {str(e)}")
    
    def _calculate_risk_score(self, anomalies: List[Dict[str, Any]]) -> float:
        """Calculate risk score based on anomalies"""
        severity_weights = {
            'high': 1.0,
            'medium': 0.6,
            'low': 0.3
        }
        
        total_weight = sum(severity_weights[a['severity']] for a in anomalies)
        return min(1.0, total_weight / 3.0)  # Normalize to 0-1 range
    
    def _update_activity_cache(self, user_id: str, activity: List[Dict[str, Any]]):
        """Update activity cache"""
        cache_key = f"user_activity_{user_id}"
        cache.set(cache_key, activity, timeout=int(self.time_window.total_seconds()))

    def _log_sensitive_access(self, user_id: str, data_type: str, access_type: str):
        """Log sensitive data access"""
        try:
            AuditLog.objects.create(
                user_id=user_id,
                action=f"sensitive_data_{access_type}",
                data_type=data_type,
                timestamp=timezone.now()
            )
            logger.info(f"Logged sensitive data {access_type} for user {user_id}")
        except Exception as e:
            logger.error(f"Failed to log sensitive data access: {str(e)}")

    def _suspend_deletion_rights(self, user_id: str):
        """Suspend user's deletion rights"""
        try:
            user = CustomUser.objects.get(id=user_id)
            # Remove deletion permissions
            deletion_perm = 'can_delete_user_data'
            if user.has_permission(deletion_perm):
                for role in user.roles.all():
                    if deletion_perm in role.permissions.values_list('codename', flat=True):
                        role.permissions.remove(deletion_perm)
            
            # Log the action
            AuditLog.objects.create(
                user=user,
                action='suspend_deletion_rights',
                resource_type='user_permissions',
                resource_id=str(user.id),
                details={'reason': 'Suspicious bulk deletion detected'}
            )
            
            logger.warning(f"Suspended deletion rights for user {user_id}")
        except Exception as e:
            logger.error(f"Error suspending deletion rights: {str(e)}")

    def _block_data_export(self, breach: DataBreach, user_id: str, anomaly: Dict[str, Any]):
        """Block user's data export capabilities"""
        try:
            user = CustomUser.objects.get(id=user_id)
            # Remove export permissions
            export_perm = 'can_export_user_data'
            if user.has_permission(export_perm):
                for role in user.roles.all():
                    if export_perm in role.permissions.values_list('codename', flat=True):
                        role.permissions.remove(export_perm)
            
            # Log the action
            AuditLog.objects.create(
                user=user,
                action='block_data_export',
                resource_type='user_permissions',
                resource_id=str(user.id),
                details={
                    'reason': 'Unauthorized export attempt detected',
                    'anomaly': anomaly
                }
            )
            
            # Update breach record
            breach.containment_measures = json.dumps({
                'action': 'block_data_export',
                'timestamp': timezone.now().isoformat(),
                'details': 'Blocked data export capabilities'
            })
            breach.save()
            
            logger.warning(f"Blocked data export capabilities for user {user_id}")
        except Exception as e:
            logger.error(f"Error blocking data export: {str(e)}")

    def _log_export_attempt(self, breach: DataBreach, user_id: str, anomaly: Dict[str, Any]):
        """Log unauthorized export attempt"""
        try:
            user = CustomUser.objects.get(id=user_id)
            AuditLog.objects.create(
                user=user,
                action='unauthorized_export_attempt',
                resource_type='data_export',
                resource_id=str(user.id),
                details={
                    'anomaly': anomaly,
                    'breach_id': str(breach.id)
                }
            )
            logger.warning(f"Logged unauthorized export attempt for user {user_id}")
        except Exception as e:
            logger.error(f"Error logging export attempt: {str(e)}")

# Global breach detection service instance
breach_detection_service = BreachDetectionService()

@shared_task
def notify_breach_stakeholders(breach_id: int):
    """Notify relevant stakeholders about the breach"""
    # Implementation of stakeholder notification
    pass

@shared_task
def schedule_breach_notification(breach_id: int):
    """Schedule GDPR authority notification within 72 hours"""
    # Implementation of notification scheduling
    pass

@shared_task
def send_breach_notifications(breach_id: int):
    """Send notifications related to the breach"""
    # Implementation of notification sending
    pass 