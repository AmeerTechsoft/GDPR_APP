from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth import get_user_model
from django.utils import timezone
from django.conf import settings
from django.db.models import Q
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _
from django.shortcuts import get_object_or_404
import json
import logging
import hmac
import hashlib
import base64
from functools import wraps
from datetime import datetime, timedelta
import uuid

from .models import (
    DataBreach, DataRequest, ProcessingActivity, ConsentRecord,
    AuditLog, CrossBorderTransfer, CookieConsent, PrivacyPolicy,
    DataCategory, UserSession, Report
)

logger = logging.getLogger('gdpr_platform')
User = get_user_model()

# API Authentication and Security

def api_key_required(view_func):
    """Decorator to require API key for access"""
    @wraps(view_func)
    def wrapped_view(request, *args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        
        if not api_key:
            return JsonResponse({
                'error': 'API key is required',
                'code': 'missing_api_key'
            }, status=401)
        
        # Validate API key (using constant-time comparison to prevent timing attacks)
        valid_key = settings.API_KEY if hasattr(settings, 'API_KEY') else None
        if not valid_key or not hmac.compare_digest(api_key, valid_key):
            return JsonResponse({
                'error': 'Invalid API key',
                'code': 'invalid_api_key'
            }, status=401)
        
        # Log API access
        AuditLog.objects.create(
            user=None,
            action='api_access',
            resource_type='api',
            resource_id=request.path,
            ip_address=request.META.get('REMOTE_ADDR', ''),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            details={
                'method': request.method,
                'path': request.path,
                'query_params': request.GET.dict()
            }
        )
        
        return view_func(request, *args, **kwargs)
    
    return wrapped_view

def validate_webhook_signature(request):
    """Validate webhook signature"""
    signature = request.headers.get('X-Webhook-Signature')
    if not signature:
        return False
    
    # Get webhook secret
    webhook_secret = settings.WEBHOOK_SECRET if hasattr(settings, 'WEBHOOK_SECRET') else None
    if not webhook_secret:
        return False
    
    # Calculate expected signature
    expected_signature = hmac.new(
        webhook_secret.encode(),
        request.body,
        hashlib.sha256
    ).hexdigest()
    
    # Compare signatures using constant-time comparison
    return hmac.compare_digest(signature, expected_signature)

# API Endpoints

@csrf_exempt
@require_http_methods(["GET"])
@api_key_required
def api_root(request):
    """API root endpoint with available endpoints"""
    return JsonResponse({
        'name': 'GDPR Compliance Platform API',
        'version': '1.0',
        'endpoints': {
            'data_breaches': '/api/v1/breaches/',
            'data_requests': '/api/v1/requests/',
            'processing_activities': '/api/v1/processing/',
            'consent_records': '/api/v1/consent/',
            'audit_logs': '/api/v1/audit/',
            'transfers': '/api/v1/transfers/',
            'reports': '/api/v1/reports/',
            'users': '/api/v1/users/',
            'webhooks': '/api/v1/webhooks/',
        }
    })

# Data Breach API Endpoints

@csrf_exempt
@require_http_methods(["GET", "POST"])
@api_key_required
def data_breaches(request):
    """List or create data breaches"""
    if request.method == "GET":
        # Filter parameters
        status = request.GET.get('status')
        severity = request.GET.get('severity')
        date_from = request.GET.get('date_from')
        date_to = request.GET.get('date_to')
        
        # Start with all breaches
        breaches = DataBreach.objects.all()
        
        # Apply filters
        if status:
            breaches = breaches.filter(status=status)
        if severity:
            breaches = breaches.filter(severity=severity)
        if date_from:
            try:
                date_from = datetime.strptime(date_from, '%Y-%m-%d')
                breaches = breaches.filter(date_discovered__gte=date_from)
            except ValueError:
                return JsonResponse({'error': 'Invalid date_from format. Use YYYY-MM-DD'}, status=400)
        if date_to:
            try:
                date_to = datetime.strptime(date_to, '%Y-%m-%d')
                breaches = breaches.filter(date_discovered__lte=date_to)
            except ValueError:
                return JsonResponse({'error': 'Invalid date_to format. Use YYYY-MM-DD'}, status=400)
        
        # Pagination
        page = int(request.GET.get('page', 1))
        page_size = min(int(request.GET.get('page_size', 10)), 100)  # Limit max page size
        start = (page - 1) * page_size
        end = start + page_size
        
        # Prepare response
        total_count = breaches.count()
        breaches_page = breaches[start:end]
        
        # Format response
        result = {
            'count': total_count,
            'page': page,
            'page_size': page_size,
            'total_pages': (total_count + page_size - 1) // page_size,
            'results': [
                {
                    'id': str(breach.id),
                    'title': breach.title,
                    'severity': breach.severity,
                    'status': breach.status,
                    'date_discovered': breach.date_discovered.isoformat(),
                    'date_reported': breach.date_reported.isoformat(),
                    'breach_type': breach.breach_type,
                    'affected_users_count': breach.affected_users.count(),
                    'authority_notified': breach.authority_notified,
                    'users_notified': breach.users_notified,
                    'notification_deadline': breach.notification_deadline.isoformat() if breach.notification_deadline else None,
                    'risk_score': breach.risk_score,
                    'resolved': breach.resolved,
                    'resolution_date': breach.resolution_date.isoformat() if breach.resolution_date else None,
                }
                for breach in breaches_page
            ]
        }
        
        return JsonResponse(result)
    
    elif request.method == "POST":
        try:
            # Parse request body
            data = json.loads(request.body)
            
            # Required fields
            required_fields = ['title', 'description', 'severity', 'breach_type', 'affected_data_categories']
            for field in required_fields:
                if field not in data:
                    return JsonResponse({'error': f'Missing required field: {field}'}, status=400)
            
            # Create breach
            breach = DataBreach(
                title=data['title'],
                description=data['description'],
                date_discovered=datetime.strptime(data.get('date_discovered', datetime.now().isoformat()), '%Y-%m-%dT%H:%M:%S.%f'),
                severity=data['severity'],
                breach_type=data['breach_type'],
                affected_data_categories=data['affected_data_categories'],
                impact_assessment=data.get('impact_assessment', ''),
                status=data.get('status', 'investigating'),
                ai_detected=data.get('ai_detected', False),
                risk_score=data.get('risk_score', 0.0),
                anomaly_details=data.get('anomaly_details', {}),
            )
            
            # Save breach
            breach.save()
            
            # Add affected users if provided
            if 'affected_user_ids' in data:
                for user_id in data['affected_user_ids']:
                    try:
                        user = User.objects.get(id=user_id)
                        breach.affected_users.add(user)
                    except User.DoesNotExist:
                        logger.warning(f"User with ID {user_id} not found when creating breach")
            
            # Create response
            return JsonResponse({
                'id': str(breach.id),
                'title': breach.title,
                'status': breach.status,
                'date_reported': breach.date_reported.isoformat(),
                'notification_deadline': breach.notification_deadline.isoformat(),
            }, status=201)
        
        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON'}, status=400)
        except Exception as e:
            logger.exception("Error creating data breach via API")
            return JsonResponse({'error': str(e)}, status=500)

@csrf_exempt
@require_http_methods(["GET", "PUT", "DELETE"])
@api_key_required
def data_breach_detail(request, breach_id):
    """Retrieve, update or delete a data breach"""
    try:
        breach = get_object_or_404(DataBreach, id=breach_id)
        
        if request.method == "GET":
            # Return detailed breach information
            result = {
                'id': str(breach.id),
                'title': breach.title,
                'description': breach.description,
                'severity': breach.severity,
                'status': breach.status,
                'date_discovered': breach.date_discovered.isoformat(),
                'date_reported': breach.date_reported.isoformat(),
                'breach_type': breach.breach_type,
                'affected_users_count': breach.affected_users.count(),
                'affected_data_categories': breach.affected_data_categories,
                'impact_assessment': breach.impact_assessment,
                'authority_notified': breach.authority_notified,
                'authority_notification_date': breach.authority_notification_date.isoformat() if breach.authority_notification_date else None,
                'users_notified': breach.users_notified,
                'user_notification_date': breach.user_notification_date.isoformat() if breach.user_notification_date else None,
                'notification_deadline': breach.notification_deadline.isoformat() if breach.notification_deadline else None,
                'containment_measures': breach.containment_measures,
                'remediation_steps': breach.remediation_steps,
                'ai_detected': breach.ai_detected,
                'risk_score': breach.risk_score,
                'anomaly_details': breach.anomaly_details,
                'resolved': breach.resolved,
                'resolution_date': breach.resolution_date.isoformat() if breach.resolution_date else None,
                'lessons_learned': breach.lessons_learned,
            }
            
            return JsonResponse(result)
        
        elif request.method == "PUT":
            try:
                # Parse request body
                data = json.loads(request.body)
                
                # Update fields
                if 'title' in data:
                    breach.title = data['title']
                if 'description' in data:
                    breach.description = data['description']
                if 'severity' in data:
                    breach.severity = data['severity']
                if 'status' in data:
                    breach.status = data['status']
                if 'breach_type' in data:
                    breach.breach_type = data['breach_type']
                if 'affected_data_categories' in data:
                    breach.affected_data_categories = data['affected_data_categories']
                if 'impact_assessment' in data:
                    breach.impact_assessment = data['impact_assessment']
                if 'containment_measures' in data:
                    breach.containment_measures = data['containment_measures']
                if 'remediation_steps' in data:
                    breach.remediation_steps = data['remediation_steps']
                if 'authority_notified' in data:
                    breach.authority_notified = data['authority_notified']
                    if data['authority_notified'] and not breach.authority_notification_date:
                        breach.authority_notification_date = timezone.now()
                if 'users_notified' in data:
                    breach.users_notified = data['users_notified']
                    if data['users_notified'] and not breach.user_notification_date:
                        breach.user_notification_date = timezone.now()
                if 'resolved' in data:
                    breach.resolved = data['resolved']
                    if data['resolved'] and not breach.resolution_date:
                        breach.resolution_date = timezone.now()
                if 'lessons_learned' in data:
                    breach.lessons_learned = data['lessons_learned']
                
                # Save breach
                breach.save()
                
                # Return updated breach
                return JsonResponse({
                    'id': str(breach.id),
                    'title': breach.title,
                    'status': breach.status,
                    'updated_at': timezone.now().isoformat(),
                })
            
            except json.JSONDecodeError:
                return JsonResponse({'error': 'Invalid JSON'}, status=400)
            except Exception as e:
                logger.exception(f"Error updating data breach {breach_id} via API")
                return JsonResponse({'error': str(e)}, status=500)
        
        elif request.method == "DELETE":
            # Delete breach
            breach.delete()
            
            # Return success response
            return JsonResponse({
                'success': True,
                'message': f'Data breach {breach_id} deleted successfully'
            })
    
    except Exception as e:
        logger.exception(f"Error in data_breach_detail for {breach_id}")
        return JsonResponse({'error': str(e)}, status=500)

# Data Request API Endpoints

@csrf_exempt
@require_http_methods(["GET", "POST"])
@api_key_required
def data_requests(request):
    """List or create data requests"""
    if request.method == "GET":
        # Filter parameters
        request_type = request.GET.get('request_type')
        status = request.GET.get('status')
        date_from = request.GET.get('date_from')
        date_to = request.GET.get('date_to')
        
        # Start with all requests
        requests = DataRequest.objects.all()
        
        # Apply filters
        if request_type:
            requests = requests.filter(request_type=request_type)
        if status:
            requests = requests.filter(status=status)
        if date_from:
            try:
                date_from = datetime.strptime(date_from, '%Y-%m-%d')
                requests = requests.filter(request_date__gte=date_from)
            except ValueError:
                return JsonResponse({'error': 'Invalid date_from format. Use YYYY-MM-DD'}, status=400)
        if date_to:
            try:
                date_to = datetime.strptime(date_to, '%Y-%m-%d')
                requests = requests.filter(request_date__lte=date_to)
            except ValueError:
                return JsonResponse({'error': 'Invalid date_to format. Use YYYY-MM-DD'}, status=400)
        
        # Pagination
        page = int(request.GET.get('page', 1))
        page_size = min(int(request.GET.get('page_size', 10)), 100)  # Limit max page size
        start = (page - 1) * page_size
        end = start + page_size
        
        # Prepare response
        total_count = requests.count()
        requests_page = requests[start:end]
        
        # Format response
        result = {
            'count': total_count,
            'page': page,
            'page_size': page_size,
            'total_pages': (total_count + page_size - 1) // page_size,
            'results': [
                {
                    'id': req.id,
                    'user_id': str(req.user.id),
                    'user_email': req.user.email,
                    'request_type': req.request_type,
                    'status': req.status,
                    'request_date': req.request_date.isoformat(),
                    'completion_date': req.completion_date.isoformat() if req.completion_date else None,
                    'tracking_id': str(req.tracking_id),
                    'data_categories': req.data_categories,
                    'due_date': req.due_date.isoformat() if req.due_date else None,
                }
                for req in requests_page
            ]
        }
        
        return JsonResponse(result)
    
    elif request.method == "POST":
        try:
            # Parse request body
            data = json.loads(request.body)
            
            # Required fields
            required_fields = ['user_id', 'request_type']
            for field in required_fields:
                if field not in data:
                    return JsonResponse({'error': f'Missing required field: {field}'}, status=400)
            
            # Get user
            try:
                user = User.objects.get(id=data['user_id'])
            except User.DoesNotExist:
                return JsonResponse({'error': f'User with ID {data["user_id"]} not found'}, status=404)
            
            # Create request
            data_request = DataRequest(
                user=user,
                request_type=data['request_type'],
                status=data.get('status', 'pending'),
                notes=data.get('notes', ''),
                description=data.get('description', ''),
                data_categories=data.get('data_categories', []),
                file_format=data.get('file_format', 'json'),
            )
            
            # Set due date (default: 30 days)
            due_date = timezone.now() + timedelta(days=30)
            data_request.due_date = due_date
            
            # Save request
            data_request.save()
            
            # Create response
            return JsonResponse({
                'id': data_request.id,
                'tracking_id': str(data_request.tracking_id),
                'request_type': data_request.request_type,
                'status': data_request.status,
                'request_date': data_request.request_date.isoformat(),
                'due_date': data_request.due_date.isoformat(),
            }, status=201)
        
        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON'}, status=400)
        except Exception as e:
            logger.exception("Error creating data request via API")
            return JsonResponse({'error': str(e)}, status=500)

# Webhook Endpoints

@csrf_exempt
@require_http_methods(["POST"])
def webhook_receiver(request, webhook_type):
    """Receive webhook events from external systems"""
    # Validate webhook signature
    if not validate_webhook_signature(request):
        return JsonResponse({
            'error': 'Invalid webhook signature',
            'code': 'invalid_signature'
        }, status=401)
    
    try:
        # Parse request body
        data = json.loads(request.body)
        
        # Process webhook based on type
        if webhook_type == 'breach_notification':
            # Process breach notification from external system
            process_breach_notification(data)
        elif webhook_type == 'data_request':
            # Process data request from external system
            process_data_request(data)
        elif webhook_type == 'consent_update':
            # Process consent update from external system
            process_consent_update(data)
        else:
            return JsonResponse({'error': f'Unknown webhook type: {webhook_type}'}, status=400)
        
        # Return success response
        return JsonResponse({
            'success': True,
            'message': f'Webhook {webhook_type} processed successfully',
            'timestamp': timezone.now().isoformat()
        })
    
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)
    except Exception as e:
        logger.exception(f"Error processing webhook {webhook_type}")
        return JsonResponse({'error': str(e)}, status=500)

# Webhook Processing Functions

def process_breach_notification(data):
    """Process breach notification from external system"""
    # Create data breach
    breach = DataBreach(
        title=data.get('title', 'External System Breach'),
        description=data.get('description', ''),
        date_discovered=datetime.strptime(data.get('date_discovered', datetime.now().isoformat()), '%Y-%m-%dT%H:%M:%S.%f'),
        severity=data.get('severity', 'medium'),
        breach_type=data.get('breach_type', 'system_breach'),
        affected_data_categories=data.get('affected_data_categories', {}),
        impact_assessment=data.get('impact_assessment', ''),
        status='investigating',
        ai_detected=False,
        risk_score=data.get('risk_score', 0.5),
    )
    
    # Save breach
    breach.save()
    
    # Log webhook event
    AuditLog.objects.create(
        user=None,
        action='webhook_breach_notification',
        resource_type='data_breach',
        resource_id=str(breach.id),
        ip_address='webhook',
        user_agent='webhook',
        details={
            'webhook_data': data,
            'breach_id': str(breach.id),
        }
    )
    
    return breach

def process_data_request(data):
    """Process data request from external system"""
    # Get user
    try:
        user = User.objects.get(email=data.get('user_email'))
    except User.DoesNotExist:
        logger.error(f"User with email {data.get('user_email')} not found in webhook")
        raise ValueError(f"User with email {data.get('user_email')} not found")
    
    # Create data request
    request = DataRequest(
        user=user,
        request_type=data.get('request_type', 'access'),
        status='pending',
        notes=data.get('notes', 'Created via webhook'),
        description=data.get('description', ''),
        data_categories=data.get('data_categories', []),
    )
    
    # Set due date (default: 30 days)
    due_date = timezone.now() + timedelta(days=30)
    request.due_date = due_date
    
    # Save request
    request.save()
    
    # Log webhook event
    AuditLog.objects.create(
        user=None,
        action='webhook_data_request',
        resource_type='data_request',
        resource_id=str(request.id),
        ip_address='webhook',
        user_agent='webhook',
        details={
            'webhook_data': data,
            'request_id': request.id,
        }
    )
    
    return request

def process_consent_update(data):
    """Process consent update from external system"""
    # Get user
    try:
        user = User.objects.get(email=data.get('user_email'))
    except User.DoesNotExist:
        logger.error(f"User with email {data.get('user_email')} not found in webhook")
        raise ValueError(f"User with email {data.get('user_email')} not found")
    
    # Create consent record
    consent = ConsentRecord(
        user=user,
        consent_type=data.get('consent_type', 'data_processing'),
        status='active',
        purpose=data.get('purpose', ''),
        data_categories=data.get('data_categories', {}),
        processing_activities=data.get('processing_activities', {}),
        third_parties=data.get('third_parties', {}),
        collection_method='external_system',
        proof_of_consent=data.get('proof', {}),
        policy_version=data.get('policy_version', ''),
        form_version=data.get('form_version', ''),
    )
    
    # Set valid until (default: 1 year)
    valid_until = timezone.now() + timedelta(days=365)
    consent.valid_until = valid_until
    
    # Save consent
    consent.save()
    
    # Log webhook event
    AuditLog.objects.create(
        user=None,
        action='webhook_consent_update',
        resource_type='consent_record',
        resource_id=str(consent.id),
        ip_address='webhook',
        user_agent='webhook',
        details={
            'webhook_data': data,
            'consent_id': str(consent.id),
        }
    )
    
    return consent 