from django.conf import settings
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils import timezone
from django.db.models import Q
from .models import DataBreach, BreachNotification, CustomUser
from .services import NotificationService, AuditLogService
import logging
import threading
import time

logger = logging.getLogger(__name__)

class BreachMonitor:
    def __init__(self):
        self.monitoring_active = False
        self.monitor_thread = None
        self.suspicious_ips = set()
        self.failed_login_attempts = {}
        self.request_rate_limits = {}
        self.session_anomalies = {}
        self.data_access_patterns = {}
        self.known_user_ips = {}
        
    def start_monitoring(self):
        """Start the monitoring system"""
        if not self.monitoring_active:
            self.monitoring_active = True
            self.monitor_thread = threading.Thread(target=self._monitor_loop)
            self.monitor_thread.daemon = True
            self.monitor_thread.start()
            logger.info("Breach monitoring system started")

    def stop_monitoring(self):
        """Stop the monitoring system"""
        self.monitoring_active = False
        if self.monitor_thread:
            self.monitor_thread.join()
            logger.info("Breach monitoring system stopped")

    def _monitor_loop(self):
        """Main monitoring loop"""
        while self.monitoring_active:
            try:
                self._check_for_breaches()
                time.sleep(300)  # Check every 5 minutes
            except Exception as e:
                logger.error(f"Error in monitoring loop: {str(e)}")

    def _check_for_breaches(self):
        """Check various indicators for potential breaches"""
        self._check_failed_logins()
        self._check_request_rates()
        self._check_suspicious_ips()
        self._check_session_anomalies()
        self._check_data_access_patterns()
        self._check_geographic_anomalies()

    def log_failed_login(self, user_id, ip_address):
        """Log failed login attempts"""
        timestamp = timezone.now()
        if user_id not in self.failed_login_attempts:
            self.failed_login_attempts[user_id] = []
        self.failed_login_attempts[user_id].append((timestamp, ip_address))
        self._evaluate_failed_logins(user_id)

    def log_request(self, ip_address, endpoint):
        """Log API/endpoint requests"""
        timestamp = timezone.now()
        if ip_address not in self.request_rate_limits:
            self.request_rate_limits[ip_address] = []
        self.request_rate_limits[ip_address].append((timestamp, endpoint))
        self._evaluate_request_rate(ip_address)

    def log_session_activity(self, user_id, session_id, ip_address):
        """Log user session activity"""
        timestamp = timezone.now()
        if user_id not in self.session_anomalies:
            self.session_anomalies[user_id] = []
        self.session_anomalies[user_id].append((timestamp, session_id, ip_address))
        self._evaluate_session_patterns(user_id)

    def log_data_access(self, user_id, data_type, operation):
        """Log data access patterns"""
        timestamp = timezone.now()
        if user_id not in self.data_access_patterns:
            self.data_access_patterns[user_id] = []
        self.data_access_patterns[user_id].append((timestamp, data_type, operation))
        self._evaluate_data_access(user_id)

    def _evaluate_failed_logins(self, user_id):
        """Evaluate failed login patterns"""
        recent_attempts = [
            attempt for attempt in self.failed_login_attempts.get(user_id, [])
            if (timezone.now() - attempt[0]).seconds < 3600
        ]
        
        if len(recent_attempts) >= 5:
            self._trigger_breach_alert(
                severity='medium',
                title='Multiple Failed Login Attempts Detected',
                description=f'Multiple failed login attempts detected for user ID {user_id}',
                affected_users=[user_id],
                compromised_data=['Login credentials']
            )

    def _evaluate_request_rate(self, ip_address):
        """Evaluate request rate patterns"""
        recent_requests = [
            req for req in self.request_rate_limits.get(ip_address, [])
            if (timezone.now() - req[0]).seconds < 60
        ]
        
        if len(recent_requests) > 100:  # More than 100 requests per minute
            self.suspicious_ips.add(ip_address)
            self._trigger_breach_alert(
                severity='high',
                title='Suspicious Request Rate Detected',
                description=f'High request rate detected from IP {ip_address}',
                affected_users=self._get_affected_users(),
                compromised_data=['API access patterns', 'System resources']
            )

    def _check_session_anomalies(self):
        """Check for suspicious session patterns"""
        for user_id, sessions in self.session_anomalies.items():
            recent_sessions = [
                session for session in sessions
                if (timezone.now() - session[0]).seconds < 3600
            ]
            
            # Check for concurrent sessions from different IPs
            active_ips = set(session[2] for session in recent_sessions)
            if len(active_ips) > 2:  # More than 2 different IPs in an hour
                self._trigger_breach_alert(
                    severity='high',
                    title='Multiple Concurrent Sessions Detected',
                    description='User accessing account from multiple locations',
                    affected_users=[user_id],
                    compromised_data=['Account access', 'Session tokens']
                )

    def _check_data_access_patterns(self):
        """Check for unusual data access patterns"""
        for user_id, accesses in self.data_access_patterns.items():
            recent_accesses = [
                access for access in accesses
                if (timezone.now() - access[0]).seconds < 300  # Last 5 minutes
            ]
            
            # Check for rapid data access
            if len(recent_accesses) > 50:  # More than 50 data accesses in 5 minutes
                self._trigger_breach_alert(
                    severity='medium',
                    title='Unusual Data Access Pattern Detected',
                    description='High frequency of data access operations detected',
                    affected_users=[user_id],
                    compromised_data=['User data', 'System access patterns']
                )

    def _check_geographic_anomalies(self):
        """Check for geographic location anomalies"""
        for user_id, attempts in self.failed_login_attempts.items():
            if user_id in self.known_user_ips:
                usual_ip = self.known_user_ips[user_id]
                user = CustomUser.objects.get(id=user_id)  # Fetch user to get last_login
                last_login_ip = user.last_login_ip  # Hypothetical field

                recent_attempts = [
                    attempt for attempt in attempts
                    if (timezone.now() - attempt[0]).seconds < 86400  # Last 24 hours
                ]
                
                # Check for attempts from significantly different locations
                for attempt in recent_attempts:
                    if self._is_suspicious_location(usual_ip, attempt[1]) and \
                       self._is_suspicious_location(last_login_ip, attempt[1]):
                        self._trigger_breach_alert(
                            severity='high',
                            title='Geographic Location Anomaly',
                            description='Login attempt from unusual location detected',
                            affected_users=[user_id],
                            compromised_data=['Account credentials']
                        )

    def _is_suspicious_location(self, usual_ip, current_ip):
        """
        Check if the current IP is suspiciously different from usual IP
        This is a simplified check - in production, you'd want to use a GeoIP database
        """
        return usual_ip.split('.')[0:2] != current_ip.split('.')[0:2]

    def update_known_ip(self, user_id, ip_address):
        """Update known good IP for a user"""
        self.known_user_ips[user_id] = ip_address

    def _trigger_breach_alert(self, severity, title, description, affected_users, compromised_data):
        """Create breach incident and notify users and admins"""
        breach = DataBreach.objects.create(
            title=title,
            description=description,
            severity=severity,
            date_discovered=timezone.now(),
            date_reported=timezone.now(),
            remediation_steps='Investigation in progress. Security measures enhanced.',
            notification_sent_to_authorities=(severity in ['high', 'critical']),
            affected_data_categories=', '.join(compromised_data)
        )

        # Notify affected users
        for user_id in affected_users:
            try:
                user = CustomUser.objects.get(id=user_id)
                notification = BreachNotification.objects.create(
                    user=user,
                    breach=breach,
                    notification_method='email',
                    compromised_data=compromised_data
                )

                context = {
                    'user': user,
                    'breach': breach,
                    'notification': notification,
                    'compromised_data': compromised_data,
                    'protocol': 'https',
                    'domain': settings.ALLOWED_HOSTS[0] if settings.ALLOWED_HOSTS else 'localhost:8000'
                }

                # Send user notification
                self._send_notification(user.email, context)

                # Send admin notification
                admin_emails = [admin[1] for admin in settings.ADMINS]
                for admin_email in admin_emails:
                    self._send_notification(admin_email, context, is_admin=True)

            except CustomUser.DoesNotExist:
                logger.error(f"User {user_id} not found for breach notification")
            except Exception as e:
                logger.error(f"Error sending breach notification: {str(e)}")

    def _send_notification(self, email, context, is_admin=False):
        """Send email notification to user or admin"""
        template = 'emails/breach_notification.html'
        email_subject = f'Security Alert: {context["breach"].title}'
        if is_admin:
            email_subject = f'[ADMIN] {email_subject}'

        email_html = render_to_string(template, context)
        
        try:
            send_mail(
                subject=email_subject,
                message='Please view this email in HTML format.',
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[email],
                html_message=email_html,
                fail_silently=False,
            )
            logger.info(f"Breach notification sent to {email}")
        except Exception as e:
            logger.error(f"Failed to send breach notification to {email}: {str(e)}")

    def _get_affected_users(self):
        """Get list of potentially affected users"""
        return list(CustomUser.objects.values_list('id', flat=True))

    def _evaluate_data_access(self, user_id):
        """Evaluate data access patterns"""
        recent_accesses = [
            access for access in self.data_access_patterns.get(user_id, [])
            if (timezone.now() - access[0]).seconds < 300  # Last 5 minutes
        ]
        
        if len(recent_accesses) > 50:  # More than 50 data accesses in 5 minutes
            self._trigger_breach_alert(
                severity='medium',
                title='Unusual Data Access Pattern Detected',
                description='High frequency of data access operations detected',
                affected_users=[user_id],
                compromised_data=['User data', 'System access patterns']
            )

    def _check_failed_logins(self):
        """Check for patterns in failed login attempts"""
        current_time = timezone.now()
        
        # Check each user's failed login attempts
        for user_id, attempts in self.failed_login_attempts.items():
            # Filter for recent attempts (last hour)
            recent_attempts = [
                attempt for attempt in attempts
                if (current_time - attempt[0]).seconds < 3600
            ]
            
            # Clear old attempts
            self.failed_login_attempts[user_id] = recent_attempts
            
            # Check for suspicious patterns
            if len(recent_attempts) >= 5:
                unique_ips = len(set(attempt[1] for attempt in recent_attempts))
                
                # Multiple failures from different IPs
                if unique_ips >= 3:
                    self._trigger_breach_alert(
                        severity='high',
                        title='Distributed Login Attack Detected',
                        description=f'Multiple failed login attempts from different IPs for user ID {user_id}',
                        affected_users=[user_id],
                        compromised_data=['Login credentials']
                    )
                # Multiple failures from same IP
                elif len(recent_attempts) >= 10:
                    self._trigger_breach_alert(
                        severity='medium',
                        title='Brute Force Attack Detected',
                        description=f'Multiple failed login attempts detected for user ID {user_id}',
                        affected_users=[user_id],
                        compromised_data=['Login credentials']
                    )
                
                # Add suspicious IPs to monitoring
                for attempt in recent_attempts:
                    self.suspicious_ips.add(attempt[1])
        
        # Clean up old data from suspicious_ips
        for ip in list(self.suspicious_ips):
            if not any(
                ip == attempt[1] and (current_time - attempt[0]).seconds < 86400  # 24 hours
                for attempts in self.failed_login_attempts.values()
                for attempt in attempts
            ):
                self.suspicious_ips.remove(ip)

    def _check_request_rates(self):
        """Check for suspicious request rate patterns"""
        current_time = timezone.now()
        
        # Check each IP's request patterns
        for ip_address, requests in self.request_rate_limits.items():
            # Filter for recent requests (last minute)
            recent_requests = [
                req for req in requests
                if (current_time - req[0]).seconds < 60
            ]
            
            # Clear old requests
            self.request_rate_limits[ip_address] = recent_requests
            
            # Check for rate limiting violations
            if len(recent_requests) > 100:  # More than 100 requests per minute
                self.suspicious_ips.add(ip_address)
                
                # Group requests by endpoint to detect targeted attacks
                endpoint_counts = {}
                for _, endpoint in recent_requests:
                    endpoint_counts[endpoint] = endpoint_counts.get(endpoint, 0) + 1
                
                # Check for endpoint-specific attacks
                for endpoint, count in endpoint_counts.items():
                    if count > 50:  # More than 50 requests to same endpoint
                        self._trigger_breach_alert(
                            severity='high',
                            title='Endpoint Attack Detected',
                            description=f'High request rate to endpoint {endpoint} from IP {ip_address}',
                            affected_users=self._get_affected_users(),
                            compromised_data=['API access', 'System resources']
                        )
                
                # General rate limit breach
                self._trigger_breach_alert(
                    severity='medium',
                    title='Rate Limit Breach Detected',
                    description=f'Request rate limit exceeded for IP {ip_address}',
                    affected_users=self._get_affected_users(),
                    compromised_data=['System resources']
                )
            
            # Check for suspicious patterns
            if len(recent_requests) > 20:  # More than 20 requests in a minute
                endpoints = [req[1] for req in recent_requests]
                unique_endpoints = len(set(endpoints))
                
                # Check for API scanning (hitting many different endpoints)
                if unique_endpoints > 15:  # More than 15 different endpoints
                    self._trigger_breach_alert(
                        severity='high',
                        title='API Scanning Detected',
                        description=f'Multiple endpoint scanning detected from IP {ip_address}',
                        affected_users=self._get_affected_users(),
                        compromised_data=['API structure', 'System resources']
                    )
        
        # Clean up old data
        for ip in list(self.request_rate_limits.keys()):
            if not any(
                (current_time - req[0]).seconds < 3600  # 1 hour
                for req in self.request_rate_limits[ip]
            ):
                del self.request_rate_limits[ip]

    def _check_suspicious_ips(self):
        """Monitor and evaluate suspicious IP addresses"""
        current_time = timezone.now()
        
        # Check each suspicious IP's recent activity
        for ip in list(self.suspicious_ips):
            # Collect all activity from this IP
            failed_logins = sum(
                1 for attempts in self.failed_login_attempts.values()
                for attempt in attempts
                if attempt[1] == ip and (current_time - attempt[0]).seconds < 3600
            )
            
            high_rate_requests = sum(
                1 for requests in self.request_rate_limits.get(ip, [])
                if (current_time - requests[0]).seconds < 3600
            )
            
            suspicious_sessions = sum(
                1 for sessions in self.session_anomalies.values()
                for session in sessions
                if session[2] == ip and (current_time - session[0]).seconds < 3600
            )
            
            # Calculate threat score
            threat_score = 0
            if failed_logins >= 5:
                threat_score += 2
            if failed_logins >= 10:
                threat_score += 3
            
            if high_rate_requests >= 100:
                threat_score += 2
            if high_rate_requests >= 200:
                threat_score += 3
            
            if suspicious_sessions >= 2:
                threat_score += 2
            if suspicious_sessions >= 4:
                threat_score += 3
            
            # Take action based on threat score
            if threat_score >= 8:
                self._trigger_breach_alert(
                    severity='critical',
                    title='High-Risk IP Address Detected',
                    description=f'IP {ip} shows multiple suspicious activities: '
                              f'{failed_logins} failed logins, '
                              f'{high_rate_requests} high-rate requests, '
                              f'{suspicious_sessions} suspicious sessions',
                    affected_users=self._get_affected_users(),
                    compromised_data=[
                        'Login credentials',
                        'API access',
                        'Session security',
                        'System resources'
                    ]
                )
            elif threat_score >= 5:
                self._trigger_breach_alert(
                    severity='high',
                    title='Suspicious IP Activity Detected',
                    description=f'IP {ip} shows concerning activity patterns',
                    affected_users=self._get_affected_users(),
                    compromised_data=['System security']
                )
            
            # Remove IP from monitoring if no recent activity
            if failed_logins == 0 and high_rate_requests == 0 and suspicious_sessions == 0:
                self.suspicious_ips.remove(ip)
                logger.info(f"IP {ip} removed from suspicious IPs monitoring - no recent activity")

# Initialize the global monitor instance
breach_monitor = BreachMonitor() 