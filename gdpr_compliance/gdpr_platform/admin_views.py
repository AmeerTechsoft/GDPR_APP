from django.contrib.admin.views.decorators import staff_member_required
from django.shortcuts import render
from django.db.models import Count, Q, Avg, F
from django.utils import timezone
from datetime import timedelta
from .models import (
    DataRequest, CookieConsent, DataBreach,
    DataProcessingActivity, UserPrivacyPolicyConsent,
    AuditLog, UserSession
)
from django.template.loader import get_template
from weasyprint import HTML
from django.http import HttpResponse

@staff_member_required
def gdpr_dashboard(request):
    # Time ranges
    now = timezone.now()
    last_30_days = now - timedelta(days=30)
    last_7_days = now - timedelta(days=7)

    # Data Request Metrics
    data_requests = {
        'total': DataRequest.objects.count(),
        'pending': DataRequest.objects.filter(status='pending').count(),
        'completed': DataRequest.objects.filter(status='completed').count(),
        'rejected': DataRequest.objects.filter(status='rejected').count(),
        'last_30_days': DataRequest.objects.filter(request_date__gte=last_30_days).count(),
        'by_type': DataRequest.objects.values('request_type').annotate(count=Count('id')),
    }

    # Cookie Consent Metrics
    cookie_consents = {
        'total': CookieConsent.objects.count(),
        'analytics_accepted': CookieConsent.objects.filter(analytics_cookies=True).count(),
        'marketing_accepted': CookieConsent.objects.filter(marketing_cookies=True).count(),
        'functional_accepted': CookieConsent.objects.filter(functional_cookies=True).count(),
        'last_7_days': CookieConsent.objects.filter(timestamp__gte=last_7_days).count(),
    }

    # Data Breach Metrics
    data_breaches = {
        'total': DataBreach.objects.count(),
        'unresolved': DataBreach.objects.filter(resolved=False).count(),
        'high_severity': DataBreach.objects.filter(severity='high', resolved=False).count(),
        'pending_notifications': DataBreach.objects.filter(
            notification_sent_to_authorities=False,
            resolved=False
        ).count(),
        'last_30_days': DataBreach.objects.filter(date_discovered__gte=last_30_days).count(),
    }

    # Processing Activity Metrics
    processing_activities = {
        'total': DataProcessingActivity.objects.count(),
        'by_type': DataProcessingActivity.objects.values('activity_type').annotate(count=Count('id')),
        'by_legal_basis': DataProcessingActivity.objects.values('legal_basis').annotate(count=Count('id')),
        'last_7_days': DataProcessingActivity.objects.filter(timestamp__gte=last_7_days).count(),
    }

    # Privacy Policy Metrics
    privacy_policy = {
        'total_versions': UserPrivacyPolicyConsent.objects.values('policy').distinct().count(),
        'pending_acceptances': UserPrivacyPolicyConsent.objects.filter(
            Q(policy__is_active=True) & ~Q(user__in=UserPrivacyPolicyConsent.objects.values('user'))
        ).count(),
        'last_30_days_acceptances': UserPrivacyPolicyConsent.objects.filter(
            consent_date__gte=last_30_days
        ).count(),
    }

    # Security Metrics
    security_metrics = {
        'active_sessions': UserSession.objects.filter(is_active=True).count(),
        'mfa_enabled_users': UserSession.objects.filter(mfa_verified=True).distinct('user').count(),
        'suspicious_activities': AuditLog.objects.filter(
            timestamp__gte=last_7_days,
            action__in=['login_failed', 'suspicious_activity']
        ).count(),
    }

    context = {
        'data_requests': data_requests,
        'cookie_consents': cookie_consents,
        'data_breaches': data_breaches,
        'processing_activities': processing_activities,
        'privacy_policy': privacy_policy,
        'security_metrics': security_metrics,
        'title': 'GDPR Compliance Dashboard',
    }

    return render(request, 'admin_templates/gdpr_dashboard.html', context)

@staff_member_required
def export_compliance_report(request):
    # Time range for the report
    end_date = timezone.now()
    start_date = end_date - timedelta(days=30)

    # Gather all relevant data
    data = {
        'period': f"{start_date.date()} to {end_date.date()}",
        'data_requests': {
            'total': DataRequest.objects.filter(request_date__range=(start_date, end_date)).count(),
            'by_type': dict(DataRequest.objects.filter(
                request_date__range=(start_date, end_date)
            ).values('request_type').annotate(count=Count('id')).values_list('request_type', 'count')),
            'average_completion_time': DataRequest.objects.filter(
                status='completed',
                completion_date__range=(start_date, end_date)
            ).exclude(completion_date=None).aggregate(
                avg_time=Avg(F('completion_date') - F('request_date'))
            )['avg_time'],
        },
        'data_breaches': {
            'total': DataBreach.objects.filter(date_discovered__range=(start_date, end_date)).count(),
            'by_severity': dict(DataBreach.objects.filter(
                date_discovered__range=(start_date, end_date)
            ).values('severity').annotate(count=Count('id')).values_list('severity', 'count')),
            'average_resolution_time': DataBreach.objects.filter(
                resolved=True,
                resolution_date__range=(start_date, end_date)
            ).exclude(resolution_date=None).aggregate(
                avg_time=Avg(F('resolution_date') - F('date_discovered'))
            )['avg_time'],
        },
        'consent_metrics': {
            'total_updates': CookieConsent.objects.filter(timestamp__range=(start_date, end_date)).count(),
            'acceptance_rate': {
                'analytics': CookieConsent.objects.filter(
                    timestamp__range=(start_date, end_date),
                    analytics_cookies=True
                ).count() / CookieConsent.objects.filter(timestamp__range=(start_date, end_date)).count() * 100,
                'marketing': CookieConsent.objects.filter(
                    timestamp__range=(start_date, end_date),
                    marketing_cookies=True
                ).count() / CookieConsent.objects.filter(timestamp__range=(start_date, end_date)).count() * 100,
                'functional': CookieConsent.objects.filter(
                    timestamp__range=(start_date, end_date),
                    functional_cookies=True
                ).count() / CookieConsent.objects.filter(timestamp__range=(start_date, end_date)).count() * 100,
            },
        },
        'processing_activities': {
            'total': DataProcessingActivity.objects.filter(timestamp__range=(start_date, end_date)).count(),
            'by_type': dict(DataProcessingActivity.objects.filter(
                timestamp__range=(start_date, end_date)
            ).values('activity_type').annotate(count=Count('id')).values_list('activity_type', 'count')),
            'by_legal_basis': dict(DataProcessingActivity.objects.filter(
                timestamp__range=(start_date, end_date)
            ).values('legal_basis').annotate(count=Count('id')).values_list('legal_basis', 'count')),
        },
    }

    # Generate PDF report
    template = get_template('admin_templates/compliance_report.html')
    html = template.render({'data': data})
    
    # Create PDF
    pdf = HTML(string=html).write_pdf()
    
    # Create response
    response = HttpResponse(pdf, content_type='application/pdf')
    response['Content-Disposition'] = f'attachment; filename="compliance_report_{end_date.date()}.pdf"'
    
    return response 