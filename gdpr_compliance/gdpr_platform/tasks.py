from celery import shared_task
from django.utils import timezone
from django.contrib.auth import get_user_model
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.conf import settings
from django.db.models import Q
import logging
from datetime import timedelta
import os

from .models import (
    DataBreach, DataRequest, ProcessingActivity, ConsentRecord,
    AuditLog, CrossBorderTransfer, CookieConsent, PrivacyPolicy,
    DataCategory, UserSession, Report, ReportSchedule, DeletionTask,
    UserPrivacyPolicyConsent, DataExport, TrustedDevice
)

logger = logging.getLogger('gdpr_platform')
User = get_user_model()

# Data Retention Tasks

@shared_task
def cleanup_expired_data():
    """
    Scheduled task to clean up expired data based on retention policies
    This should run daily during off-peak hours
    """
    logger.info("Starting scheduled data cleanup task")
    
    # Get current time
    now = timezone.now()
    
    # Clean up expired sessions
    expired_sessions = UserSession.objects.filter(
        is_active=True,
        last_activity__lt=now - timedelta(hours=24)
    )
    session_count = expired_sessions.count()
    expired_sessions.update(is_active=False, end_reason='expired')
    logger.info(f"Cleaned up {session_count} expired sessions")
    
    # Clean up expired trusted devices
    expired_devices = TrustedDevice.objects.filter(expires_at__lt=now)
    device_count = expired_devices.count()
    expired_devices.delete()
    logger.info(f"Cleaned up {device_count} expired trusted devices")
    
    # Clean up expired data exports
    expired_exports = DataExport.objects.filter(expires_at__lt=now)
    export_count = expired_exports.count()
    
    # Delete export files from disk
    for export in expired_exports:
        if export.file and os.path.exists(export.file.path):
            try:
                os.remove(export.file.path)
            except Exception as e:
                logger.error(f"Error deleting export file {export.file.path}: {e}")
    
    # Delete database records
    expired_exports.delete()
    logger.info(f"Cleaned up {export_count} expired data exports")
    
    # Process scheduled data deletions
    process_scheduled_deletions()
    
    # Log completion
    logger.info("Completed scheduled data cleanup task")
    
    return {
        'expired_sessions': session_count,
        'expired_devices': device_count,
        'expired_exports': export_count,
    }

@shared_task
def process_scheduled_deletions():
    """Process scheduled data deletion tasks"""
    now = timezone.now()
    
    # Get pending deletion tasks that are due
    pending_tasks = DeletionTask.objects.filter(
        status='scheduled',
        scheduled_date__lte=now
    )
    
    task_count = pending_tasks.count()
    success_count = 0
    failed_count = 0
    
    for task in pending_tasks:
        try:
            # Update task status
            task.status = 'in_progress'
            task.save(update_fields=['status'])
            
            # Process deletion based on task type
            if task.task_type == 'user_account':
                # Anonymize user data
                user = task.user
                user.anonymize_data()
                user.is_deleted = True
                user.save()
                
            elif task.task_type == 'user_data_category':
                # Delete specific data category
                user = task.user
                category = task.description
                if hasattr(user, category):
                    setattr(user, category, None)
                    user.save()
                    
            elif task.task_type == 'expired_data':
                # This is handled by category-specific cleanup tasks
                pass
            
            # Mark task as completed
            task.status = 'completed'
            task.completed_date = timezone.now()
            task.save(update_fields=['status', 'completed_date'])
            success_count += 1
            
        except Exception as e:
            # Log error and mark task as failed
            logger.error(f"Error processing deletion task {task.id}: {e}")
            task.status = 'failed'
            task.error_message = str(e)
            task.save(update_fields=['status', 'error_message'])
            failed_count += 1
    
    logger.info(f"Processed {task_count} deletion tasks: {success_count} succeeded, {failed_count} failed")
    
    return {
        'processed': task_count,
        'succeeded': success_count,
        'failed': failed_count,
    }

# Monitoring Tasks

@shared_task
def monitor_data_breaches():
    """
    Scheduled task to monitor data breaches and send notifications
    This should run hourly
    """
    logger.info("Starting scheduled data breach monitoring task")
    
    # Get current time
    now = timezone.now()
    
    # Find breaches approaching notification deadline
    approaching_deadline = DataBreach.objects.filter(
        status='investigating',
        authority_notified=False,
        notification_deadline__lt=now + timedelta(hours=12),  # Less than 12 hours remaining
        notification_deadline__gt=now  # Deadline not yet passed
    )
    
    # Send alerts for breaches approaching deadline
    for breach in approaching_deadline:
        # Calculate hours remaining
        hours_remaining = (breach.notification_deadline - now).total_seconds() / 3600
        
        # Log alert
        logger.warning(f"Data breach {breach.id} approaching notification deadline: {hours_remaining:.1f} hours remaining")
        
        # Send email alerts to DPO and compliance officers
        dpo_users = User.objects.filter(roles__name='dpo')
        compliance_officers = User.objects.filter(roles__name='compliance_officer')
        
        recipients = list(dpo_users.values_list('email', flat=True)) + list(compliance_officers.values_list('email', flat=True))
        
        if recipients:
            try:
                subject = f"URGENT: Data Breach Notification Deadline Approaching ({hours_remaining:.1f} hours)"
                message = render_to_string('emails/breach_deadline_alert.html', {
                    'breach': breach,
                    'hours_remaining': hours_remaining,
                    'notification_deadline': breach.notification_deadline,
                })
                send_mail(
                    subject=subject,
                    message=message,
                    from_email=settings.DEFAULT_FROM_EMAIL,
                    recipient_list=recipients,
                    html_message=message,
                    fail_silently=False,
                )
                logger.info(f"Sent breach deadline alert for breach {breach.id} to {len(recipients)} recipients")
            except Exception as e:
                logger.error(f"Error sending breach deadline alert for breach {breach.id}: {e}")
    
    # Find breaches with passed deadline
    passed_deadline = DataBreach.objects.filter(
        status='investigating',
        authority_notified=False,
        notification_deadline__lt=now  # Deadline passed
    )
    
    # Log breaches with passed deadline
    for breach in passed_deadline:
        hours_passed = (now - breach.notification_deadline).total_seconds() / 3600
        logger.error(f"Data breach {breach.id} notification deadline passed {hours_passed:.1f} hours ago")
    
    logger.info("Completed scheduled data breach monitoring task")
    
    return {
        'approaching_deadline': approaching_deadline.count(),
        'passed_deadline': passed_deadline.count(),
    }

@shared_task
def monitor_data_requests():
    """
    Scheduled task to monitor data requests and send notifications
    This should run daily
    """
    logger.info("Starting scheduled data request monitoring task")
    
    # Get current time
    now = timezone.now()
    
    # Find requests approaching due date
    approaching_due = DataRequest.objects.filter(
        status__in=['pending', 'processing'],
        due_date__lt=now + timedelta(days=3),  # Less than 3 days remaining
        due_date__gt=now  # Due date not yet passed
    )
    
    # Send alerts for requests approaching due date
    for request in approaching_due:
        # Calculate days remaining
        days_remaining = (request.due_date - now).days + 1
        
        # Log alert
        logger.warning(f"Data request {request.id} approaching due date: {days_remaining} days remaining")
        
        # Send email alerts to assigned staff
        recipients = []
        if request.assigned_to:
            recipients.append(request.assigned_to.email)
        
        # Also notify DPO and compliance officers for high-priority requests
        if days_remaining <= 1:  # 1 day or less remaining
            dpo_users = User.objects.filter(roles__name='dpo')
            compliance_officers = User.objects.filter(roles__name='compliance_officer')
            recipients.extend(list(dpo_users.values_list('email', flat=True)))
            recipients.extend(list(compliance_officers.values_list('email', flat=True)))
        
        if recipients:
            try:
                subject = f"Data Request {request.tracking_id} Due Soon ({days_remaining} days)"
                message = render_to_string('emails/request_due_alert.html', {
                    'request': request,
                    'days_remaining': days_remaining,
                    'due_date': request.due_date,
                })
                send_mail(
                    subject=subject,
                    message=message,
                    from_email=settings.DEFAULT_FROM_EMAIL,
                    recipient_list=recipients,
                    html_message=message,
                    fail_silently=False,
                )
                logger.info(f"Sent request due alert for request {request.id} to {len(recipients)} recipients")
            except Exception as e:
                logger.error(f"Error sending request due alert for request {request.id}: {e}")
    
    # Find overdue requests
    overdue = DataRequest.objects.filter(
        status__in=['pending', 'processing'],
        due_date__lt=now  # Due date passed
    )
    
    # Log overdue requests
    for request in overdue:
        days_overdue = (now - request.due_date).days
        logger.error(f"Data request {request.id} is overdue by {days_overdue} days")
    
    logger.info("Completed scheduled data request monitoring task")
    
    return {
        'approaching_due': approaching_due.count(),
        'overdue': overdue.count(),
    }

# Reporting Tasks

@shared_task
def generate_scheduled_reports():
    """
    Generate reports based on schedule
    This should run daily
    """
    logger.info("Starting scheduled report generation task")
    
    # Get current time
    now = timezone.now()
    
    # Find report schedules that are due
    due_schedules = ReportSchedule.objects.filter(
        is_active=True,
        next_run__lte=now
    )
    
    report_count = 0
    
    for schedule in due_schedules:
        try:
            # Generate report based on type
            if schedule.report_type == 'data_processing':
                report_data = generate_processing_report(
                    date_from=now - timedelta(days=30),  # Last 30 days
                    date_to=now
                )
            elif schedule.report_type == 'data_breaches':
                report_data = generate_breaches_report(
                    date_from=now - timedelta(days=30),
                    date_to=now
                )
            elif schedule.report_type == 'user_requests':
                report_data = generate_requests_report(
                    date_from=now - timedelta(days=30),
                    date_to=now
                )
            elif schedule.report_type == 'consent_management':
                report_data = generate_consent_report(
                    date_from=now - timedelta(days=30),
                    date_to=now
                )
            elif schedule.report_type == 'compliance_audit':
                report_data = generate_audit_report(
                    date_from=now - timedelta(days=30),
                    date_to=now
                )
            else:
                logger.error(f"Unknown report type: {schedule.report_type}")
                continue
            
            # Create report
            report = Report.objects.create(
                type=schedule.report_type,
                date_from=now - timedelta(days=30),
                date_to=now,
                generated_by=None,  # System-generated
                data=report_data
            )
            
            # Update schedule
            schedule.last_run = now
            schedule.next_run = calculate_next_run(schedule)
            schedule.save(update_fields=['last_run', 'next_run'])
            
            # Send report to recipients
            for recipient in schedule.recipients.all():
                try:
                    subject = f"Scheduled Report: {schedule.get_report_type_display()}"
                    message = render_to_string('emails/scheduled_report.html', {
                        'report': report,
                        'schedule': schedule,
                        'recipient': recipient,
                    })
                    send_mail(
                        subject=subject,
                        message=message,
                        from_email=settings.DEFAULT_FROM_EMAIL,
                        recipient_list=[recipient.email],
                        html_message=message,
                        fail_silently=False,
                    )
                except Exception as e:
                    logger.error(f"Error sending report to {recipient.email}: {e}")
            
            report_count += 1
            logger.info(f"Generated scheduled report {report.id} for {schedule.report_type}")
        
        except Exception as e:
            logger.error(f"Error generating scheduled report for {schedule.id}: {e}")
    
    logger.info(f"Completed scheduled report generation task: generated {report_count} reports")
    
    return {
        'generated_reports': report_count,
    }

def calculate_next_run(schedule):
    """Calculate next run time based on frequency"""
    now = timezone.now()
    
    if schedule.frequency == 'daily':
        return now + timedelta(days=1)
    elif schedule.frequency == 'weekly':
        return now + timedelta(weeks=1)
    elif schedule.frequency == 'monthly':
        # Approximate a month as 30 days
        return now + timedelta(days=30)
    elif schedule.frequency == 'quarterly':
        # Approximate a quarter as 90 days
        return now + timedelta(days=90)
    else:
        # Default to daily
        return now + timedelta(days=1)

# Report Generation Functions

def generate_processing_report(date_from, date_to):
    """Generate processing activities report"""
    activities = ProcessingActivity.objects.filter(
        created_at__gte=date_from,
        created_at__lte=date_to
    )
    
    return {
        'total_activities': activities.count(),
        'by_risk_level': {
            'low': activities.filter(risk_level='low').count(),
            'medium': activities.filter(risk_level='medium').count(),
            'high': activities.filter(risk_level='high').count(),
        },
        'by_legal_basis': {
            'consent': activities.filter(legal_basis='consent').count(),
            'contract': activities.filter(legal_basis='contract').count(),
            'legal_obligation': activities.filter(legal_basis='legal_obligation').count(),
            'vital_interests': activities.filter(legal_basis='vital_interests').count(),
            'public_task': activities.filter(legal_basis='public_task').count(),
            'legitimate_interests': activities.filter(legal_basis='legitimate_interests').count(),
        },
        'dpia_required': activities.filter(dpia_required=True).count(),
        'dpia_completed': activities.filter(dpia_completed=True).count(),
        'cross_border_transfers': activities.filter(cross_border_transfer=True).count(),
    }

def generate_breaches_report(date_from, date_to):
    """Generate data breaches report"""
    breaches = DataBreach.objects.filter(
        date_reported__gte=date_from,
        date_reported__lte=date_to
    )
    
    return {
        'total_breaches': breaches.count(),
        'by_severity': {
            'low': breaches.filter(severity='low').count(),
            'medium': breaches.filter(severity='medium').count(),
            'high': breaches.filter(severity='high').count(),
            'critical': breaches.filter(severity='critical').count(),
        },
        'by_status': {
            'investigating': breaches.filter(status='investigating').count(),
            'contained': breaches.filter(status='contained').count(),
            'resolved': breaches.filter(status='resolved').count(),
            'monitoring': breaches.filter(status='monitoring').count(),
        },
        'by_type': {
            'unauthorized_access': breaches.filter(breach_type='unauthorized_access').count(),
            'data_leak': breaches.filter(breach_type='data_leak').count(),
            'system_breach': breaches.filter(breach_type='system_breach').count(),
            'malware': breaches.filter(breach_type='malware').count(),
            'phishing': breaches.filter(breach_type='phishing').count(),
            'insider_threat': breaches.filter(breach_type='insider_threat').count(),
            'other': breaches.filter(breach_type='other').count(),
        },
        'authority_notified': breaches.filter(authority_notified=True).count(),
        'users_notified': breaches.filter(users_notified=True).count(),
        'ai_detected': breaches.filter(ai_detected=True).count(),
        'resolved': breaches.filter(resolved=True).count(),
    }

def generate_requests_report(date_from, date_to):
    """Generate data requests report"""
    requests = DataRequest.objects.filter(
        request_date__gte=date_from,
        request_date__lte=date_to
    )
    
    return {
        'total_requests': requests.count(),
        'by_type': {
            'access': requests.filter(request_type='access').count(),
            'deletion': requests.filter(request_type='deletion').count(),
            'rectification': requests.filter(request_type='rectification').count(),
            'portability': requests.filter(request_type='portability').count(),
            'restriction': requests.filter(request_type='restriction').count(),
            'objection': requests.filter(request_type='objection').count(),
        },
        'by_status': {
            'pending': requests.filter(status='pending').count(),
            'processing': requests.filter(status='processing').count(),
            'completed': requests.filter(status='completed').count(),
            'rejected': requests.filter(status='rejected').count(),
            'extended': requests.filter(status='extended').count(),
            'withdrawn': requests.filter(status='withdrawn').count(),
        },
        'average_completion_time': calculate_average_completion_time(requests),
        'overdue': requests.filter(
            status__in=['pending', 'processing'],
            due_date__lt=timezone.now()
        ).count(),
    }

def calculate_average_completion_time(requests):
    """Calculate average completion time in days"""
    completed_requests = requests.filter(
        status='completed',
        completion_date__isnull=False
    )
    
    if not completed_requests:
        return None
    
    total_days = 0
    count = 0
    
    for request in completed_requests:
        days = (request.completion_date - request.request_date).days
        total_days += days
        count += 1
    
    return total_days / count if count > 0 else None

def generate_consent_report(date_from, date_to):
    """Generate consent management report"""
    consents = ConsentRecord.objects.filter(
        granted_at__gte=date_from,
        granted_at__lte=date_to
    )
    
    # Get privacy policy consents
    policy_consents = UserPrivacyPolicyConsent.objects.filter(
        consent_date__gte=date_from,
        consent_date__lte=date_to
    )
    
    # Get cookie consents
    cookie_consents = CookieConsent.objects.filter(
        timestamp__gte=date_from,
        timestamp__lte=date_to
    )
    
    return {
        'total_consents': consents.count(),
        'by_type': {
            'privacy_policy': consents.filter(consent_type='privacy_policy').count(),
            'cookie_usage': consents.filter(consent_type='cookie_usage').count(),
            'marketing': consents.filter(consent_type='marketing').count(),
            'data_processing': consents.filter(consent_type='data_processing').count(),
            'data_sharing': consents.filter(consent_type='data_sharing').count(),
            'special_category': consents.filter(consent_type='special_category').count(),
        },
        'by_status': {
            'active': consents.filter(status='active').count(),
            'withdrawn': consents.filter(status='withdrawn').count(),
            'expired': consents.filter(status='expired').count(),
        },
        'privacy_policy_consents': policy_consents.count(),
        'cookie_consents': {
            'total': cookie_consents.count(),
            'analytics_accepted': cookie_consents.filter(analytics_cookies=True).count(),
            'marketing_accepted': cookie_consents.filter(marketing_cookies=True).count(),
            'functional_accepted': cookie_consents.filter(functional_cookies=True).count(),
        },
    }

def generate_audit_report(date_from, date_to):
    """Generate audit log report"""
    logs = AuditLog.objects.filter(
        timestamp__gte=date_from,
        timestamp__lte=date_to
    )
    
    return {
        'total_logs': logs.count(),
        'by_action': {
            'login': logs.filter(action='login').count(),
            'logout': logs.filter(action='logout').count(),
            'password_reset': logs.filter(action='password_reset').count(),
            'data_access': logs.filter(action='data_access').count(),
            'data_modification': logs.filter(action='data_modification').count(),
            'data_deletion': logs.filter(action='data_deletion').count(),
            'api_access': logs.filter(action='api_access').count(),
            'webhook': logs.filter(action__startswith='webhook').count(),
        },
        'by_resource_type': {
            'user': logs.filter(resource_type='user').count(),
            'data_breach': logs.filter(resource_type='data_breach').count(),
            'data_request': logs.filter(resource_type='data_request').count(),
            'processing_activity': logs.filter(resource_type='processing_activity').count(),
            'consent_record': logs.filter(resource_type='consent_record').count(),
            'api': logs.filter(resource_type='api').count(),
        },
    } 