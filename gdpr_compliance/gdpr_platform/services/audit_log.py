from django.utils import timezone
from django.conf import settings
from typing import Dict, Any, List
import logging
from ..models import AuditLog, CustomUser

logger = logging.getLogger(__name__)

class AuditLogService:
    """Service for managing audit logs"""

    def log_activity(self, user_id: str, action: str, resource_type: str, 
                    resource_id: str, details: Dict[str, Any] = None) -> bool:
        """
        Log an activity in the audit log
        """
        try:
            user = CustomUser.objects.get(id=user_id)
            
            AuditLog.objects.create(
                user=user,
                action=action,
                resource_type=resource_type,
                resource_id=resource_id,
                ip_address=self._get_client_ip(),
                user_agent=self._get_user_agent(),
                details=details or {}
            )
            
            logger.info(f"Audit log created for {action} by user {user_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to create audit log: {str(e)}")
            return False

    def get_user_activity(self, user_id: str, 
                         start_date=None, end_date=None) -> List[AuditLog]:
        """
        Get audit logs for a specific user
        """
        try:
            filters = {'user_id': user_id}
            
            if start_date:
                filters['timestamp__gte'] = start_date
            if end_date:
                filters['timestamp__lte'] = end_date
                
            return AuditLog.objects.filter(**filters).order_by('-timestamp')
            
        except Exception as e:
            logger.error(f"Failed to retrieve user activity: {str(e)}")
            return []

    def get_resource_activity(self, resource_type: str, resource_id: str,
                            start_date=None, end_date=None) -> List[AuditLog]:
        """
        Get audit logs for a specific resource
        """
        try:
            filters = {
                'resource_type': resource_type,
                'resource_id': resource_id
            }
            
            if start_date:
                filters['timestamp__gte'] = start_date
            if end_date:
                filters['timestamp__lte'] = end_date
                
            return AuditLog.objects.filter(**filters).order_by('-timestamp')
            
        except Exception as e:
            logger.error(f"Failed to retrieve resource activity: {str(e)}")
            return []

    def get_activity_by_action(self, action: str,
                             start_date=None, end_date=None) -> List[AuditLog]:
        """
        Get audit logs for a specific action type
        """
        try:
            filters = {'action': action}
            
            if start_date:
                filters['timestamp__gte'] = start_date
            if end_date:
                filters['timestamp__lte'] = end_date
                
            return AuditLog.objects.filter(**filters).order_by('-timestamp')
            
        except Exception as e:
            logger.error(f"Failed to retrieve action activity: {str(e)}")
            return []

    def _get_client_ip(self) -> str:
        """Get client IP address from request"""
        # This should be implemented to get IP from the current request context
        return "0.0.0.0"  # Placeholder

    def _get_user_agent(self) -> str:
        """Get user agent from request"""
        # This should be implemented to get user agent from the current request context
        return "Unknown"  # Placeholder

# Global audit log service instance
audit_log_service = AuditLogService() 