from django.db import models
from django.contrib.auth.models import AbstractUser, Permission
from django.utils import timezone
from django.conf import settings
from cryptography.fernet import Fernet
import json
import uuid
from django.utils.translation import gettext_lazy as _
from datetime import timedelta
from django.contrib.contenttypes.models import ContentType

def get_notification_deadline():
    """Return the notification deadline (72 hours from now)"""
    return timezone.now() + timedelta(hours=72)

class EncryptedField(models.TextField):
    """Custom field for encrypting sensitive data"""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fernet = Fernet(settings.ENCRYPTION_KEY)

    def from_db_value(self, value, expression, connection):
        if value is None:
            return value
        try:
            decrypted = self.fernet.decrypt(value.encode()).decode()
            # Try to deserialize JSON if possible
            try:
                return json.loads(decrypted)
            except json.JSONDecodeError:
                return decrypted
        except Exception as e:
            return value

    def to_python(self, value):
        if value is None:
            return value
        return value

    def get_prep_value(self, value):
        if value is None:
            return value
        # Convert dict/list to JSON string if necessary
        if isinstance(value, (dict, list)):
            value = json.dumps(value)
        # Convert to string if not already
        if not isinstance(value, str):
            value = str(value)
        return self.fernet.encrypt(value.encode()).decode()

    def value_to_string(self, obj):
        value = self.value_from_object(obj)
        return self.get_prep_value(value)

class FileUpload(models.Model):
    """Model for handling file uploads"""
    
    file = models.FileField(upload_to='uploads/%Y/%m/%d/')
    filename = models.CharField(max_length=255)
    content_type = models.CharField(max_length=100)
    size = models.PositiveIntegerField()
    uploaded_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='uploaded_files'
    )
    uploaded_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-uploaded_at']
        verbose_name = _('File Upload')
        verbose_name_plural = _('File Uploads')
    
    def __str__(self):
        return self.filename
    
    def save(self, *args, **kwargs):
        if not self.filename:
            self.filename = self.file.name
        if not self.content_type:
            self.content_type = self.file.content_type
        if not self.size:
            self.size = self.file.size
        super().save(*args, **kwargs)

def ensure_dpo_permissions():
    """Ensure DPO role has all required permissions"""
    from django.contrib.contenttypes.models import ContentType
    from django.contrib.auth.models import Permission
    
    # Get or create required permissions
    processing_ct = ContentType.objects.get_for_model(ProcessingActivity)
    view_processing, _ = Permission.objects.get_or_create(
        codename='view_processing',
        name='Can view processing activities',
        content_type=processing_ct,
    )
    
    # Get DPO role
    dpo_role = Role.objects.filter(name=Role.DATA_PROTECTION_OFFICER).first()
    if dpo_role:
        # Add permission if not already present
        if not dpo_role.permissions.filter(id=view_processing.id).exists():
            dpo_role.permissions.add(view_processing)

class Role(models.Model):
    """Role model for RBAC"""
    name = models.CharField(max_length=100, unique=True)
    description = models.TextField(blank=True)
    permissions = models.ManyToManyField(Permission, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)
    
    # Define default roles
    ADMIN = 'admin'
    COMPLIANCE_OFFICER = 'compliance_officer'
    DATA_PROTECTION_OFFICER = 'dpo'
    REGULAR_USER = 'user'
    
    ROLE_CHOICES = [
        (ADMIN, _('Admin')),
        (COMPLIANCE_OFFICER, _('Compliance Officer')),
        (DATA_PROTECTION_OFFICER, _('Data Protection Officer')),
        (REGULAR_USER, _('Regular User')),
    ]
    
    def __str__(self):
        return self.name
    
    class Meta:
        verbose_name = _('Role')
        verbose_name_plural = _('Roles')

    def save(self, *args, **kwargs):
        is_new = self.pk is None
        super().save(*args, **kwargs)
        
        if is_new and self.name == self.DATA_PROTECTION_OFFICER:
            ensure_dpo_permissions()

class CustomUser(AbstractUser):
    """Extended User model with RBAC support and GDPR compliance"""
    # Basic identification
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    roles = models.ManyToManyField(Role, blank=True)
    
    # Personal Info (Retention: 7 years after account deletion)
    phone_number = models.CharField(max_length=20, blank=True, null=True)
    date_of_birth = models.DateField(blank=True, null=True)
    address = EncryptedField(blank=True, null=True)
    city = models.CharField(max_length=100, blank=True, null=True)
    country = models.CharField(max_length=100, blank=True, null=True)
    postal_code = models.CharField(max_length=20, blank=True, null=True)
    nationality = models.CharField(max_length=100, blank=True, null=True)

    # Sensitive Data (Retention: Immediately deleted upon account deletion)
    government_id = EncryptedField(blank=True, null=True)
    emergency_contact = EncryptedField(blank=True, null=True)

    # Professional Info (Retention: 7 years after account deletion)
    occupation = models.CharField(max_length=200, blank=True, null=True)
    company = models.CharField(max_length=200, blank=True, null=True)

    # Preferences & Media (Retention: 30 days after account deletion)
    preferred_language = models.CharField(max_length=50, blank=True, null=True)
    profile_photo = models.ImageField(upload_to='profile_photos/%Y/%m/%d/', blank=True, null=True)

    # Security & Status
    last_login_ip = models.GenericIPAddressField(blank=True, null=True)
    account_status = models.CharField(
        max_length=20,
        choices=[
            ('active', _('Active')),
            ('inactive', _('Inactive')),
            ('pending_deletion', _('Pending Deletion')),
            ('suspended', _('Suspended'))
        ],
        default='active'
    )
    two_factor_enabled = models.BooleanField(default=False)
    is_deleted = models.BooleanField(default=False)
    deletion_scheduled_date = models.DateTimeField(null=True, blank=True)

    # Preferences & Tracking (Retention: Immediately deleted upon account deletion)
    privacy_settings = models.JSONField(default=dict, blank=True)
    marketing_preferences = models.JSONField(default=dict, blank=True)
    social_profiles = EncryptedField(blank=True, null=True)
    device_info = models.JSONField(default=dict, blank=True)
    data_retention_policy = models.JSONField(default=dict, blank=True)
    last_privacy_acceptance = models.DateTimeField(null=True, blank=True)

    # Timestamps and Retention
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    scheduled_deletion_date = models.DateTimeField(null=True, blank=True)

    class Meta:
        verbose_name = _('User')
        verbose_name_plural = _('Users')
        permissions = [
            ("can_view_sensitive_data", "Can view sensitive user data"),
            ("can_export_user_data", "Can export user data"),
            ("can_delete_user_data", "Can delete user data"),
        ]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._ensure_default_policies()

    def _ensure_default_policies(self):
        """Ensure default policies are set"""
        if not self.data_retention_policy:
            self.data_retention_policy = {
                'personal_info': {'retention_period': 2555, 'unit': 'days'},  # 7 years
                'sensitive_data': {'retention_period': 0, 'unit': 'days'},    # Immediate deletion
                'professional_info': {'retention_period': 2555, 'unit': 'days'},  # 7 years
                'preferences': {'retention_period': 30, 'unit': 'days'},      # 30 days
                'security_logs': {'retention_period': 365, 'unit': 'days'},   # 1 year
            }
        
        if not self.marketing_preferences:
            self.marketing_preferences = {
                'email_marketing': False,
                'consent_date': None,
                'last_updated': None
            }
        
        if not self.device_info:
            self.device_info = {
                'last_login_device': None,
                'known_devices': []
            }

    def save(self, *args, **kwargs):
        self._ensure_default_policies()
        super().save(*args, **kwargs)

    def has_role(self, role_name):
        """Check if user has specific role"""
        return self.roles.filter(name=role_name, is_active=True).exists()
    
    def add_role(self, role_name):
        """Add role to user"""
        role, _ = Role.objects.get_or_create(name=role_name)
        self.roles.add(role)
    
    def remove_role(self, role_name):
        """Remove role from user"""
        role = Role.objects.filter(name=role_name).first()
        if role:
            self.roles.remove(role)
    
    def get_permissions(self):
        """Get all permissions from user's roles"""
        return Permission.objects.filter(role__in=self.roles.all()).distinct()
    
    def has_permission(self, permission_name):
        """Check if user has specific permission"""
        return self.get_permissions().filter(codename=permission_name).exists()

    def schedule_deletion(self):
        """Schedule user data for deletion"""
        self.account_status = 'pending_deletion'
        self.scheduled_deletion_date = timezone.now()
        self.save()

    def anonymize_data(self):
        """Anonymize user data while preserving necessary records"""
        self.username = f"anonymized_{self.id}"
        self.email = f"anonymized_{self.id}@deleted.local"
        self.first_name = "Anonymized"
        self.last_name = "User"
        self.phone_number = None
        self.date_of_birth = None
        self.address = None
        self.city = None
        self.country = None
        self.postal_code = None
        self.nationality = None
        self.government_id = None
        self.emergency_contact = None
        self.occupation = None
        self.company = None
        self.profile_photo = None
        self.social_profiles = None
        self.device_info = {'anonymized': True}
        self.save()

    def get_retention_period(self, data_category):
        """Get retention period for a specific data category"""
        return self.data_retention_policy.get(data_category, {}).get('retention_period', 0)

    @property
    def requires_deletion(self):
        """Check if user data requires deletion based on retention policy"""
        if self.scheduled_deletion_date:
            return timezone.now() >= self.scheduled_deletion_date
        return False

    def update_marketing_preferences(self, email_marketing=None):
        """Update marketing preferences"""
        if email_marketing is not None:
            self.marketing_preferences['email_marketing'] = email_marketing
            self.marketing_preferences['last_updated'] = str(timezone.now().date())
            self.save()

    def update_device_info(self, device_info):
        """Update device information"""
        current_device = {
            'user_agent': device_info.get('user_agent'),
            'ip_address': device_info.get('ip_address'),
            'last_seen': str(timezone.now())
        }
        
        if not self.device_info.get('known_devices'):
            self.device_info['known_devices'] = []
            
        self.device_info['last_login_device'] = current_device
        
        # Add to known devices if not already present
        device_exists = False
        for device in self.device_info['known_devices']:
            if device.get('user_agent') == current_device['user_agent'] and \
               device.get('ip_address') == current_device['ip_address']:
                device['last_seen'] = current_device['last_seen']
                device_exists = True
                break
                
        if not device_exists:
            self.device_info['known_devices'].append(current_device)
        
        self.save()

    def export_data(self):
        """Export user data in a GDPR-compliant format"""
        return {
            'personal_info': {
                'username': self.username,
                'email': self.email,
                'first_name': self.first_name,
                'last_name': self.last_name,
                'phone_number': self.phone_number,
                'date_of_birth': self.date_of_birth,
                'address': self.address,
                'city': self.city,
                'country': self.country,
                'postal_code': self.postal_code,
                'nationality': self.nationality
            },
            'professional_info': {
                'occupation': self.occupation,
                'company': self.company
            },
            'preferences': {
                'preferred_language': self.preferred_language,
                'marketing_preferences': self.marketing_preferences
            },
            'account_info': {
                'created_at': self.created_at,
                'last_login': self.last_login,
                'account_status': self.account_status
            }
        }

class SupportTicket(models.Model):
    """Model for handling user support tickets"""
    
    STATUS_CHOICES = [
        ('open', _('Open')),
        ('in_progress', _('In Progress')),
        ('resolved', _('Resolved')),
        ('closed', _('Closed')),
    ]
    
    PRIORITY_CHOICES = [
        ('low', _('Low')),
        ('medium', _('Medium')),
        ('high', _('High')),
        ('urgent', _('Urgent')),
    ]
    
    CATEGORY_CHOICES = [
        ('data_rights', _('Data Rights Request')),
        ('privacy', _('Privacy Concern')),
        ('security', _('Security Issue')),
        ('technical', _('Technical Issue')),
        ('other', _('Other')),
    ]
    
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='support_tickets'
    )
    
    ticket_id = models.CharField(
        max_length=20,
        unique=True,
        editable=False
    )
    
    category = models.CharField(
        max_length=20,
        choices=CATEGORY_CHOICES,
        default='other'
    )
    
    subject = models.CharField(max_length=200)
    description = models.TextField()
    
    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default='open'
    )
    
    priority = models.CharField(
        max_length=20,
        choices=PRIORITY_CHOICES,
        default='medium'
    )
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    resolved_at = models.DateTimeField(null=True, blank=True)
    
    assigned_to = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='assigned_tickets'
    )
    
    attachments = models.ManyToManyField(
        'FileUpload',
        blank=True,
        related_name='support_tickets'
    )
    
    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['ticket_id']),
            models.Index(fields=['status']),
            models.Index(fields=['user']),
            models.Index(fields=['created_at']),
        ]
        verbose_name = _('Support Ticket')
        verbose_name_plural = _('Support Tickets')
    
    def __str__(self):
        return f"{self.ticket_id} - {self.subject}"
    
    def save(self, *args, **kwargs):
        if not self.ticket_id:
            # Generate ticket ID: TICK-YYYYMMDD-XXXX
            date_str = timezone.now().strftime('%Y%m%d')
            last_ticket = SupportTicket.objects.filter(
                ticket_id__startswith=f'TICK-{date_str}'
            ).order_by('-ticket_id').first()
            
            if last_ticket:
                last_number = int(last_ticket.ticket_id.split('-')[-1])
                new_number = str(last_number + 1).zfill(4)
            else:
                new_number = '0001'
            
            self.ticket_id = f'TICK-{date_str}-{new_number}'
        
        if self.status == 'resolved' and not self.resolved_at:
            self.resolved_at = timezone.now()
        
        super().save(*args, **kwargs)

class SupportTicketComment(models.Model):
    """Model for comments on support tickets"""
    
    ticket = models.ForeignKey(
        SupportTicket,
        on_delete=models.CASCADE,
        related_name='comments'
    )
    
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='ticket_comments'
    )
    
    comment = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    attachments = models.ManyToManyField(
        'FileUpload',
        blank=True,
        related_name='ticket_comments'
    )
    
    class Meta:
        ordering = ['created_at']
        verbose_name = _('Support Ticket Comment')
        verbose_name_plural = _('Support Ticket Comments')
    
    def __str__(self):
        return f"Comment on {self.ticket.ticket_id} by {self.user.username}"

class SystemSettings(models.Model):
    """System-wide settings for GDPR compliance"""
    key = models.CharField(max_length=100, unique=True)
    value = models.JSONField()
    description = models.TextField(blank=True)
    category = models.CharField(max_length=50, choices=[
        ('security', _('Security Settings')),
        ('privacy', _('Privacy Settings')),
        ('retention', _('Data Retention')),
        ('notification', _('Notification Settings')),
        ('compliance', _('Compliance Settings'))
    ])
    is_encrypted = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_modified_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name='modified_settings'
    )

    class Meta:
        verbose_name = _('System Setting')
        verbose_name_plural = _('System Settings')
        ordering = ['category', 'key']

    def __str__(self):
        return f"{self.category} - {self.key}"

    def save(self, *args, **kwargs):
        if self.is_encrypted and not isinstance(self.value, str):
            # Encrypt the value if it's marked as encrypted
            fernet = Fernet(settings.ENCRYPTION_KEY)
            self.value = fernet.encrypt(json.dumps(self.value).encode()).decode()
        super().save(*args, **kwargs)

    def get_value(self):
        """Get the decrypted value if the setting is encrypted"""
        if not self.is_encrypted:
            return self.value
        
        try:
            fernet = Fernet(settings.ENCRYPTION_KEY)
            decrypted = fernet.decrypt(self.value.encode()).decode()
            return json.loads(decrypted)
        except Exception as e:
            return None

class DataBreach(models.Model):
    """Model for tracking data breaches and incidents"""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    title = models.CharField(max_length=200)
    description = EncryptedField()
    date_discovered = models.DateTimeField()
    date_reported = models.DateTimeField(auto_now_add=True)
    severity = models.CharField(max_length=20, choices=[
        ('low', _('Low Risk')),
        ('medium', _('Medium Risk')),
        ('high', _('High Risk')),
        ('critical', _('Critical Risk'))
    ])
    status = models.CharField(max_length=20, choices=[
        ('investigating', _('Investigating')),
        ('contained', _('Contained')),
        ('resolved', _('Resolved')),
        ('monitoring', _('Monitoring'))
    ], default='investigating')
    
    # Breach details
    affected_users = models.ManyToManyField(settings.AUTH_USER_MODEL, related_name='affected_by_breaches')
    affected_data_categories = models.JSONField()
    breach_type = models.CharField(max_length=50, choices=[
        ('unauthorized_access', _('Unauthorized Access')),
        ('data_leak', _('Data Leak')),
        ('system_breach', _('System Breach')),
        ('malware', _('Malware')),
        ('phishing', _('Phishing')),
        ('insider_threat', _('Insider Threat')),
        ('other', _('Other'))
    ])
    impact_assessment = models.TextField()
    
    # Response tracking
    response_team = models.ManyToManyField(
        settings.AUTH_USER_MODEL,
        related_name='breach_response_team',
        blank=True
    )
    containment_measures = models.JSONField(default=list)
    remediation_steps = models.TextField(blank=True)
    
    # Notification tracking
    authority_notified = models.BooleanField(default=False)
    authority_notification_date = models.DateTimeField(null=True, blank=True)
    users_notified = models.BooleanField(default=False)
    user_notification_date = models.DateTimeField(null=True, blank=True)
    notification_deadline = models.DateTimeField(
        help_text="72-hour deadline for notifying supervisory authority",
        default=get_notification_deadline
    )

    # Enhanced tracking
    ai_detected = models.BooleanField(default=False)
    risk_score = models.FloatField(default=0.0)
    anomaly_details = models.JSONField(null=True, blank=True)
    resolved = models.BooleanField(default=False)
    resolution_date = models.DateTimeField(null=True, blank=True)
    lessons_learned = models.TextField(
        null=True, blank=True,
        help_text="Post-incident analysis and lessons learned"
    )

    class Meta:
        ordering = ['-date_reported']

    def __str__(self):
        return f"{self.title} - {self.get_severity_display()}"

    def get_severity_class(self):
        return {
            'low': 'success',
            'medium': 'warning',
            'high': 'danger',
            'critical': 'dark'
        }.get(self.severity, 'secondary')

    def get_status_class(self):
        return {
            'investigating': 'warning',
            'contained': 'info',
            'resolved': 'success',
            'monitoring': 'primary'
        }.get(self.status, 'secondary')

    def calculate_response_time(self):
        """Calculate response time in hours"""
        if self.date_reported and self.date_discovered:
            delta = self.date_reported - self.date_discovered
            return round(delta.total_seconds() / 3600, 1)
        return None

class BreachTimeline(models.Model):
    """Model for tracking the timeline of events in a data breach"""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    breach = models.ForeignKey(DataBreach, on_delete=models.CASCADE, related_name='timeline_events')
    timestamp = models.DateTimeField()
    event_type = models.CharField(max_length=50, choices=[
        ('discovery', _('Breach Discovery')),
        ('investigation', _('Investigation Started')),
        ('containment', _('Containment Measures')),
        ('notification', _('Notification Sent')),
        ('remediation', _('Remediation Action')),
        ('resolution', _('Resolution')),
        ('review', _('Post-Incident Review')),
        ('other', _('Other'))
    ])
    description = models.TextField()
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name='breach_timeline_events'
    )
    evidence = models.JSONField(default=dict, blank=True)
    impact_assessment = models.TextField(blank=True)
    next_steps = models.TextField(blank=True)
    status = models.CharField(max_length=20, choices=[
        ('pending', _('Pending')),
        ('in_progress', _('In Progress')),
        ('completed', _('Completed')),
        ('blocked', _('Blocked'))
    ], default='pending')
    completion_date = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        verbose_name = _('Breach Timeline')
        verbose_name_plural = _('Breach Timelines')
        ordering = ['timestamp']
        indexes = [
            models.Index(fields=['breach', 'timestamp']),
            models.Index(fields=['event_type', 'status']),
        ]

    def __str__(self):
        return f"{self.breach.title} - {self.get_event_type_display()} ({self.timestamp})"

    def mark_completed(self, completion_date=None):
        """Mark the timeline event as completed"""
        self.status = 'completed'
        self.completion_date = completion_date or timezone.now()
        self.save()

    def add_evidence(self, evidence_type, content):
        """Add evidence to the timeline event"""
        if not self.evidence:
            self.evidence = {}
        if evidence_type not in self.evidence:
            self.evidence[evidence_type] = []
        self.evidence[evidence_type].append({
            'content': content,
            'added_at': timezone.now().isoformat(),
        })
        self.save()

    def get_duration(self):
        """Calculate the duration of the event"""
        if self.completion_date:
            return self.completion_date - self.timestamp
        return timezone.now() - self.timestamp

class CrossBorderTransfer(models.Model):
    """Track international data transfers"""
    TRANSFER_MECHANISMS = [
        ('scc', _('Standard Contractual Clauses')),
        ('bcr', _('Binding Corporate Rules')),
        ('adequacy', _('Adequacy Decision')),
        ('consent', _('Explicit Consent')),
        ('contract', _('Contract Performance')),
        ('public_interest', _('Public Interest')),
        ('legal_claims', _('Legal Claims')),
    ]
    
    # Alias for backward compatibility
    TRANSFER_MECHANISM_CHOICES = TRANSFER_MECHANISMS

    RISK_LEVELS = [
        ('low', _('Low Risk')),
        ('medium', _('Medium Risk')),
        ('high', _('High Risk')),
    ]

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    recipient_country = models.CharField(max_length=100)
    recipient_organization = models.CharField(max_length=200)
    data_categories = EncryptedField()
    transfer_mechanism = models.CharField(max_length=20, choices=TRANSFER_MECHANISMS)
    safeguards = EncryptedField()
    transfer_date = models.DateField()
    expiry_date = models.DateField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    status = models.CharField(max_length=20, default='active')
    risk_level = models.CharField(max_length=10, choices=RISK_LEVELS, default='low')

    # Enhanced GDPR fields
    adequacy_assessment = models.TextField(
        help_text="Assessment of adequacy of data protection in recipient country",
        null=True, blank=True
    )
    transfer_impact_assessment = models.TextField(
        help_text="Impact assessment of the data transfer",
        null=True, blank=True
    )
    periodic_review_date = models.DateTimeField(
        help_text="Date for next periodic review of transfer arrangement",
        default=timezone.now
    )
    supplementary_measures = models.TextField(
        help_text="Additional safeguards implemented for transfer",
        null=True, blank=True
    )
    data_minimization_measures = models.TextField(
        help_text="Measures to ensure only necessary data is transferred",
        null=True, blank=True
    )
    recipient_dpo_contact = models.JSONField(
        default=dict,
        help_text="Contact details of recipient's Data Protection Officer"
    )
    transfer_legal_basis = models.TextField(
        help_text="Detailed legal basis for international transfer",
        default="Standard Contractual Clauses (SCCs) as approved by the European Commission"
    )
    data_subject_rights = models.TextField(
        help_text="Description of data subject rights for this transfer",
        default="Data subjects maintain their GDPR rights including access, rectification, erasure, and data portability. These rights can be exercised by contacting the DPO."
    )

    class Meta:
        ordering = ['-transfer_date']
        indexes = [
            models.Index(fields=['recipient_country']),
            models.Index(fields=['transfer_mechanism']),
            models.Index(fields=['status']),
        ]

    def __str__(self):
        return f"Transfer to {self.recipient_organization} ({self.recipient_country})"

class CookieConsent(models.Model):
    """Store user cookie consent preferences"""
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    necessary_cookies = models.BooleanField(default=True)  # Always true as these are essential
    analytics_cookies = models.BooleanField(default=False)
    marketing_cookies = models.BooleanField(default=False)
    functional_cookies = models.BooleanField(default=False)
    timestamp = models.DateTimeField(auto_now=True)
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField()
    ai_analysis = models.JSONField(null=True, blank=True)

    class Meta:
        get_latest_by = 'timestamp'

class DataRequest(models.Model):
    """Track user data access and deletion requests"""
    REQUEST_TYPES = [
        ('access', _('Data Access Request')),
        ('deletion', _('Data Deletion Request')),
        ('rectification', _('Data Rectification Request')),
        ('portability', _('Data Portability Request')),
        ('restriction', _('Processing Restriction Request')),
        ('objection', _('Processing Objection')),
    ]
    
    STATUS_CHOICES = [
        ('pending', _('Pending')),
        ('processing', _('Processing')),
        ('completed', _('Completed')),
        ('rejected', _('Rejected')),
        ('extended', _('Extended')),
        ('withdrawn', _('Withdrawn')),
    ]

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    request_type = models.CharField(max_length=20, choices=REQUEST_TYPES)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    request_date = models.DateTimeField(auto_now_add=True)
    completion_date = models.DateTimeField(null=True, blank=True)
    notes = EncryptedField(null=True, blank=True)
    tracking_id = models.UUIDField(default=uuid.uuid4, editable=False)
    data_categories = models.JSONField(default=list)
    data_file = models.FileField(upload_to='data_requests/%Y/%m/%d/', null=True, blank=True)
    file_format = models.CharField(max_length=10, choices=[('json', 'JSON'), ('csv', 'CSV')], default='json')
    description = models.TextField(blank=True)
    due_date = models.DateTimeField(null=True, blank=True)
    extension_date = models.DateTimeField(null=True, blank=True)
    extension_reason = models.TextField(blank=True)
    assigned_to = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name='assigned_requests'
    )
    verification_method = models.CharField(max_length=50, blank=True)
    verification_status = models.BooleanField(default=False)

    class Meta:
        ordering = ['-request_date']
        permissions = [
            ('manage_data_requests', 'Can manage data requests'),
            ('review_data_requests', 'Can review data requests'),
        ]

    def __str__(self):
        return f"{self.get_request_type_display()} request by {self.user.username}"

    def get_file_path(self):
        if self.data_file:
            return self.data_file.path
        return None

    def is_overdue(self):
        if self.due_date and self.status == 'pending':
            return timezone.now() > self.due_date
        return False

class DataCategory(models.Model):
    """Model for categorizing types of personal data"""
    name = models.CharField(max_length=100, unique=True)
    description = models.TextField()
    sensitivity_level = models.CharField(max_length=20, choices=[
        ('low', _('Low')),
        ('medium', _('Medium')),
        ('high', _('High')),
        ('special', _('Special Category'))
    ])
    retention_period = models.IntegerField(help_text="Retention period in days")
    requires_consent = models.BooleanField(default=True)
    legal_basis = models.CharField(max_length=50, choices=[
        ('consent', _('Explicit Consent')),
        ('contract', _('Contract Performance')),
        ('legal_obligation', _('Legal Obligation')),
        ('vital_interests', _('Vital Interests')),
        ('public_task', _('Public Task')),
        ('legitimate_interests', _('Legitimate Interests'))
    ])
    examples = models.TextField(help_text="Examples of this type of data")
    special_handling_required = models.BooleanField(default=False)
    handling_instructions = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name='created_data_categories'
    )

    class Meta:
        verbose_name = _('Data Category')
        verbose_name_plural = _('Data Categories')
        ordering = ['name']

    def __str__(self):
        return self.name

    def requires_dpia(self):
        """Check if this category requires Data Protection Impact Assessment"""
        return self.sensitivity_level in ['high', 'special']

    def get_protection_measures(self):
        """Return required protection measures based on sensitivity"""
        base_measures = ['access_control', 'audit_logging']
        if self.sensitivity_level == 'medium':
            base_measures.extend(['encryption_at_rest', 'access_approval'])
        elif self.sensitivity_level in ['high', 'special']:
            base_measures.extend([
                'encryption_at_rest',
                'encryption_in_transit',
                'access_approval',
                'anonymization',
                'regular_audits'
            ])
        return base_measures

class DataTransfer(models.Model):
    """Model for tracking data transfers between systems or organizations"""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    title = models.CharField(max_length=200)
    description = models.TextField()
    source_system = models.CharField(max_length=200)
    destination_system = models.CharField(max_length=200)
    transfer_type = models.CharField(max_length=50, choices=[
        ('internal', _('Internal Transfer')),
        ('external', _('External Transfer')),
        ('cross_border', _('Cross-Border Transfer')),
        ('cloud', _('Cloud Service Transfer'))
    ])
    data_categories = models.ManyToManyField(DataCategory)
    transfer_method = models.CharField(max_length=50, choices=[
        ('api', _('API')),
        ('sftp', _('SFTP')),
        ('manual', _('Manual')),
        ('automated', _('Automated')),
        ('other', _('Other'))
    ])
    encryption_method = models.CharField(max_length=50, choices=[
        ('tls', _('TLS')),
        ('ssl', _('SSL')),
        ('pgp', _('PGP')),
        ('aes', _('AES')),
        ('none', _('None'))
    ])
    frequency = models.CharField(max_length=50, choices=[
        ('one_time', _('One-Time')),
        ('daily', _('Daily')),
        ('weekly', _('Weekly')),
        ('monthly', _('Monthly')),
        ('on_demand', _('On-Demand'))
    ])
    volume = models.IntegerField(help_text=_("Estimated number of records transferred"))
    start_date = models.DateTimeField()
    end_date = models.DateTimeField(null=True, blank=True)
    status = models.CharField(max_length=20, choices=[
        ('planned', _('Planned')),
        ('active', _('Active')),
        ('suspended', _('Suspended')),
        ('completed', _('Completed')),
        ('cancelled', _('Cancelled'))
    ])
    
    # Security and compliance
    risk_level = models.CharField(max_length=20, choices=[
        ('low', _('Low')),
        ('medium', _('Medium')),
        ('high', _('High'))
    ])
    security_measures = models.JSONField(help_text=_("Security measures in place"))
    dpia_required = models.BooleanField(default=False)
    dpia_completed = models.BooleanField(default=False)
    dpia_details = models.JSONField(null=True, blank=True)
    
    # Contractual details
    contract_reference = models.CharField(max_length=100, blank=True)
    data_sharing_agreement = models.FileField(upload_to='data_sharing_agreements/', null=True, blank=True)
    recipient_details = models.JSONField(help_text=_("Details of the recipient organization"))
    
    # Audit trail
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name='created_transfers'
    )
    last_reviewed = models.DateTimeField(null=True, blank=True)
    last_reviewed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name='reviewed_transfers'
    )

    class Meta:
        verbose_name = _('Data Transfer')
        verbose_name_plural = _('Data Transfers')
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['transfer_type', 'status']),
            models.Index(fields=['created_at']),
        ]

    def __str__(self):
        return f"{self.title} - {self.get_transfer_type_display()}"

    def mark_reviewed(self, user):
        """Mark the transfer as reviewed"""
        self.last_reviewed = timezone.now()
        self.last_reviewed_by = user
        self.save()

    def requires_dpia(self):
        """Determine if DPIA is required based on transfer characteristics"""
        high_risk_indicators = [
            self.risk_level == 'high',
            self.transfer_type == 'cross_border',
            any(cat.sensitivity_level in ['high', 'special'] for cat in self.data_categories.all()),
            self.volume > 10000,  # Large scale transfer
            self.encryption_method == 'none'
        ]
        return any(high_risk_indicators)

    def get_security_status(self):
        """Get the security status of the transfer"""
        security_score = 0
        max_score = 5
        
        # Check encryption
        if self.encryption_method != 'none':
            security_score += 1
        
        # Check if DPIA is completed when required
        if self.dpia_required and self.dpia_completed:
            security_score += 1
        elif not self.dpia_required:
            security_score += 1
        
        # Check contract and agreement
        if self.contract_reference and self.data_sharing_agreement:
            security_score += 1
        
        # Check security measures
        if len(self.security_measures) >= 3:  # At least 3 security measures
            security_score += 1
        
        # Check review status
        if self.last_reviewed and (timezone.now() - self.last_reviewed).days <= 90:  # Reviewed within 90 days
            security_score += 1
        
        return {
            'score': security_score,
            'max_score': max_score,
            'percentage': (security_score / max_score) * 100,
            'status': 'high' if security_score >= 4 else 'medium' if security_score >= 3 else 'low'
        }

class ProcessingActivity(models.Model):
    """Model for tracking data processing activities under GDPR Article 30"""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=200)
    description = models.TextField()
    purpose = models.TextField()
    legal_basis = models.CharField(max_length=50, choices=[
        ('consent', _('Explicit Consent')),
        ('contract', _('Contract Performance')),
        ('legal_obligation', _('Legal Obligation')),
        ('vital_interests', _('Vital Interests')),
        ('public_task', _('Public Task')),
        ('legitimate_interests', _('Legitimate Interests'))
    ])
    data_categories = models.ManyToManyField(DataCategory)
    data_subjects = models.JSONField(help_text=_("Categories of data subjects affected"))
    data_recipients = models.JSONField(help_text=_("Categories of recipients"))
    retention_period = models.IntegerField(help_text=_("Retention period in days"))
    security_measures = models.JSONField(help_text=_("Technical and organizational security measures"))
    cross_border_transfer = models.BooleanField(default=False)
    transfer_details = models.JSONField(null=True, blank=True)
    
    # Processing details
    processor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name='processing_activities'
    )
    department = models.CharField(max_length=100)
    start_date = models.DateTimeField()
    end_date = models.DateTimeField(null=True, blank=True)
    is_active = models.BooleanField(default=True)
    
    # Risk and compliance
    risk_level = models.CharField(max_length=10, choices=[
        ('low', _('Low Risk')),
        ('medium', _('Medium Risk')),
        ('high', _('High Risk'))
    ])
    dpia_required = models.BooleanField(default=False)
    dpia_completed = models.BooleanField(default=False)
    dpia_details = models.JSONField(null=True, blank=True)
    
    # Audit trail
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name='created_activities'
    )
    last_reviewed = models.DateTimeField(null=True, blank=True)
    last_reviewed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name='reviewed_activities'
    )

    class Meta:
        verbose_name = _('Processing Activity')
        verbose_name_plural = _('Processing Activities')
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['legal_basis', 'risk_level']),
            models.Index(fields=['created_at']),
        ]

    def __str__(self):
        return f"{self.name} - {self.get_legal_basis_display()}"

    def mark_reviewed(self, user):
        """Mark the activity as reviewed"""
        self.last_reviewed = timezone.now()
        self.last_reviewed_by = user
        self.save()

    def requires_dpia(self):
        """Determine if DPIA is required based on processing characteristics"""
        high_risk_indicators = [
            self.risk_level == 'high',
            self.cross_border_transfer,
            any(cat.sensitivity_level in ['high', 'special'] for cat in self.data_categories.all()),
            len(self.data_subjects) > 10000,  # Large scale processing
            'automated_decision_making' in self.purpose.lower(),
            'profiling' in self.purpose.lower(),
            'monitoring' in self.purpose.lower()
        ]
        return any(high_risk_indicators)

    def get_retention_status(self):
        """Check retention status of the processing activity"""
        if not self.end_date:
            return 'ongoing'
        
        retention_end = self.end_date + timedelta(days=self.retention_period)
        if timezone.now() > retention_end:
            return 'expired'
        return 'active'

    def get_affected_rights(self):
        """Determine which data subject rights are affected by this processing"""
        rights = ['access', 'rectification', 'erasure']
        if 'automated_decision_making' in self.purpose.lower():
            rights.append('object_to_automated_decision')
        if self.legal_basis == 'consent':
            rights.append('withdraw_consent')
        if 'profiling' in self.purpose.lower():
            rights.append('object_to_profiling')
        return rights

class DataProcessingActivity(models.Model):
    """Model for tracking data processing activities under GDPR Article 30"""
    PROCESSING_TYPES = [
        ('collection', 'Data Collection'),
        ('storage', 'Data Storage'),
        ('use', 'Data Use'),
        ('disclosure', 'Data Disclosure'),
        ('erasure', 'Data Erasure'),
    ]

    LEGAL_BASIS_CHOICES = [
        ('consent', 'Explicit Consent'),
        ('contract', 'Contract Performance'),
        ('legal_obligation', 'Legal Obligation'),
        ('vital_interests', 'Vital Interests'),
        ('public_task', 'Public Task'),
        ('legitimate_interests', 'Legitimate Interests'),
    ]

    activity_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=200)
    description = models.TextField()
    processing_type = models.CharField(max_length=20, choices=PROCESSING_TYPES)
    legal_basis = models.CharField(max_length=20, choices=LEGAL_BASIS_CHOICES)
    purpose = models.TextField()
    data_categories = models.ManyToManyField(DataCategory)
    data_subjects = models.JSONField(help_text="Categories of data subjects affected")
    recipients = models.JSONField(help_text="Categories of recipients")
    retention_period = models.IntegerField(help_text="Retention period in days")
    security_measures = models.JSONField()
    cross_border_transfer = models.BooleanField(default=False)
    transfer_details = models.JSONField(null=True, blank=True)
    
    # Processing details
    processor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name='data_processing_activities'
    )
    department = models.CharField(max_length=100)
    start_date = models.DateTimeField()
    end_date = models.DateTimeField(null=True, blank=True)
    is_active = models.BooleanField(default=True)
    
    # Risk and compliance
    risk_level = models.CharField(max_length=10, choices=[
        ('low', 'Low Risk'),
        ('medium', 'Medium Risk'),
        ('high', 'High Risk')
    ])
    dpia_required = models.BooleanField(default=False)
    dpia_completed = models.BooleanField(default=False)
    dpia_details = models.JSONField(null=True, blank=True)
    
    # Audit trail
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name='created_data_processing_activities'
    )
    last_reviewed = models.DateTimeField(null=True, blank=True)
    last_reviewed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name='reviewed_data_processing_activities'
    )

    class Meta:
        verbose_name = _('Data Processing Activity')
        verbose_name_plural = _('Data Processing Activities')
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['processing_type', 'risk_level']),
            models.Index(fields=['created_at']),
        ]

    def __str__(self):
        return f"{self.name} - {self.get_processing_type_display()}"

    def mark_reviewed(self, user):
        self.last_reviewed = timezone.now()
        self.last_reviewed_by = user
        self.save()

    def requires_dpia(self):
        """Determine if DPIA is required based on processing characteristics"""
        high_risk_indicators = [
            self.risk_level == 'high',
            self.cross_border_transfer,
            any(cat.sensitivity_level in ['high', 'special'] for cat in self.data_categories.all()),
            len(self.data_subjects) > 10000,  # Large scale processing
            'automated_decision_making' in self.purpose.lower(),
            'profiling' in self.purpose.lower(),
            'monitoring' in self.purpose.lower()
        ]
        return any(high_risk_indicators)

    def get_retention_status(self):
        """Check retention status of the processing activity"""
        if not self.end_date:
            return 'ongoing'
        
        retention_end = self.end_date + timedelta(days=self.retention_period)
        if timezone.now() > retention_end:
            return 'expired'
        return 'active'

    def get_affected_rights(self):
        """Determine which data subject rights are affected by this processing"""
        rights = ['access', 'rectification', 'erasure']
        if 'automated_decision_making' in self.purpose.lower():
            rights.append('object_to_automated_decision')
        if self.legal_basis == 'consent':
            rights.append('withdraw_consent')
        if 'profiling' in self.purpose.lower():
            rights.append('object_to_profiling')
        return rights

class ProcessingRequirement(models.Model):
    """Model for tracking requirements and compliance measures for data processing activities"""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    activity = models.ForeignKey(DataProcessingActivity, on_delete=models.CASCADE, related_name='requirements')
    name = models.CharField(max_length=200)
    description = models.TextField()
    requirement_type = models.CharField(max_length=50, choices=[
        ('legal', _('Legal Requirement')),
        ('technical', _('Technical Measure')),
        ('organizational', _('Organizational Measure')),
        ('security', _('Security Control')),
        ('privacy', _('Privacy Measure')),
        ('documentation', _('Documentation Requirement')),
        ('other', _('Other'))
    ])
    priority = models.CharField(max_length=20, choices=[
        ('low', _('Low')),
        ('medium', _('Medium')),
        ('high', _('High')),
        ('critical', _('Critical'))
    ])
    status = models.CharField(max_length=20, choices=[
        ('pending', _('Pending')),
        ('in_progress', _('In Progress')),
        ('completed', _('Completed')),
        ('blocked', _('Blocked')),
        ('deferred', _('Deferred'))
    ], default='pending')
    
    # Implementation details
    implementation_details = models.TextField(blank=True)
    responsible_party = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name='assigned_requirements'
    )
    deadline = models.DateTimeField(null=True, blank=True)
    completion_date = models.DateTimeField(null=True, blank=True)
    
    # Compliance tracking
    evidence = models.JSONField(default=dict, blank=True)
    verification_method = models.TextField(blank=True)
    verification_frequency = models.CharField(max_length=50, choices=[
        ('one_time', _('One-Time')),
        ('daily', _('Daily')),
        ('weekly', _('Weekly')),
        ('monthly', _('Monthly')),
        ('quarterly', _('Quarterly')),
        ('annually', _('Annually'))
    ])
    last_verified = models.DateTimeField(null=True, blank=True)
    next_verification = models.DateTimeField(null=True, blank=True)
    
    # Dependencies and risks
    dependencies = models.ManyToManyField('self', symmetrical=False, blank=True)
    risk_level = models.CharField(max_length=20, choices=[
        ('low', _('Low')),
        ('medium', _('Medium')),
        ('high', _('High'))
    ])
    risk_details = models.TextField(blank=True)
    mitigation_measures = models.TextField(blank=True)
    
    # Audit trail
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name='created_requirements'
    )
    last_updated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name='updated_requirements'
    )

    class Meta:
        verbose_name = _('Processing Requirement')
        verbose_name_plural = _('Processing Requirements')
        ordering = ['-priority', 'status', 'deadline']
        indexes = [
            models.Index(fields=['requirement_type', 'status']),
            models.Index(fields=['priority', 'deadline']),
        ]

    def __str__(self):
        return f"{self.name} - {self.get_requirement_type_display()}"

    def mark_completed(self, user, completion_date=None):
        """Mark the requirement as completed"""
        self.status = 'completed'
        self.completion_date = completion_date or timezone.now()
        self.last_updated_by = user
        self.save()

    def add_evidence(self, evidence_type, content, user):
        """Add evidence of requirement implementation"""
        if not self.evidence:
            self.evidence = {}
        if evidence_type not in self.evidence:
            self.evidence[evidence_type] = []
        self.evidence[evidence_type].append({
            'content': content,
            'added_by': str(user.id),
            'added_at': timezone.now().isoformat(),
        })
        self.save()

    def schedule_next_verification(self):
        """Schedule the next verification based on frequency"""
        if not self.last_verified:
            self.next_verification = timezone.now()
            return

        delta = None
        if self.verification_frequency == 'daily':
            delta = timedelta(days=1)
        elif self.verification_frequency == 'weekly':
            delta = timedelta(weeks=1)
        elif self.verification_frequency == 'monthly':
            delta = timedelta(days=30)
        elif self.verification_frequency == 'quarterly':
            delta = timedelta(days=90)
        elif self.verification_frequency == 'annually':
            delta = timedelta(days=365)

        if delta:
            self.next_verification = self.last_verified + delta
            self.save()

    def is_verification_due(self):
        """Check if verification is due"""
        if not self.next_verification:
            return True
        return timezone.now() >= self.next_verification

    def get_dependent_requirements(self):
        """Get all requirements that depend on this one"""
        return ProcessingRequirement.objects.filter(dependencies=self)

    def get_blocking_requirements(self):
        """Get incomplete requirements that this requirement depends on"""
        return self.dependencies.filter(status__in=['pending', 'in_progress', 'blocked'])

    def can_start(self):
        """Check if requirement can be started based on dependencies"""
        return not self.get_blocking_requirements().exists()

class UserSession(models.Model):
    """Track user sessions for security monitoring"""
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    session_key = models.CharField(max_length=40)
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField()
    login_time = models.DateTimeField(auto_now_add=True)
    last_activity = models.DateTimeField(auto_now=True)
    logout_time = models.DateTimeField(null=True, blank=True)
    is_active = models.BooleanField(default=True)
    mfa_verified = models.BooleanField(default=False, help_text="Whether this session was verified using MFA")
    end_reason = models.CharField(max_length=50, null=True, blank=True, choices=[
        ('user_logout', 'User Logout'),
        ('session_expired', 'Session Expired'),
        ('security_logout', 'Security Logout'),
        ('revoked', 'Manually Revoked'),
        ('revoked_all', 'All Sessions Revoked'),
        ('system_terminated', 'System Terminated')
    ])

    class Meta:
        verbose_name = "User Session"
        verbose_name_plural = "User Sessions"

    def __str__(self):
        return f"Session for {self.user.email} from {self.ip_address}"

    def end_session(self):
        self.is_active = False
        self.logout_time = timezone.now()
        self.end_reason = 'system_terminated'
        self.save()

class PrivacyPolicy(models.Model):
    """Manage privacy policy versions"""
    version = models.CharField(max_length=10)
    content = models.TextField()
    effective_date = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True)
    is_active = models.BooleanField(default=False)
    ai_compliance_score = models.FloatField(default=0.0)
    ai_recommendations = models.TextField(null=True, blank=True)
    last_ai_analysis = models.DateTimeField(null=True, blank=True)

    class Meta:
        get_latest_by = 'effective_date'

class UserPrivacyPolicyConsent(models.Model):
    """Track user consent to privacy policy versions"""
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    policy = models.ForeignKey(PrivacyPolicy, on_delete=models.PROTECT)
    consent_date = models.DateTimeField(auto_now_add=True)
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField()
    sentiment_analysis = models.JSONField(null=True, blank=True)
    ai_recommendations = models.TextField(null=True, blank=True)

class DataExport(models.Model):
    """Track user data exports for portability"""
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    request_date = models.DateTimeField(auto_now_add=True)
    completion_date = models.DateTimeField(null=True, blank=True)
    file_format = models.CharField(max_length=10, choices=[('json', 'JSON'), ('csv', 'CSV')])
    file_size = models.BigIntegerField(null=True)
    download_count = models.IntegerField(default=0)
    expires_at = models.DateTimeField()
    status = models.CharField(max_length=20, default='processing')

class AuditLog(models.Model):
    """Immutable audit log for compliance monitoring"""
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True)
    action = models.CharField(max_length=50)
    resource_type = models.CharField(max_length=50)
    resource_id = models.CharField(max_length=50)
    timestamp = models.DateTimeField(auto_now_add=True)
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField()
    details = EncryptedField()
    
    class Meta:
        indexes = [
            models.Index(fields=['timestamp', 'action']),
            models.Index(fields=['resource_type', 'resource_id']),
        ]

class TwoFactorAuth(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    secret_key = models.CharField(max_length=32)
    is_enabled = models.BooleanField(default=False)
    backup_codes = models.JSONField(default=list)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Two-Factor Authentication"
        verbose_name_plural = "Two-Factor Authentication"

    def __str__(self):
        return f"2FA for {self.user.email}"

class TrustedDevice(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    device_id = models.CharField(max_length=64, unique=True)
    user_agent = models.TextField()
    ip_address = models.GenericIPAddressField()
    last_used = models.DateTimeField(default=timezone.now)
    added_on = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()

    class Meta:
        verbose_name = "Trusted Device"
        verbose_name_plural = "Trusted Devices"

    def __str__(self):
        return f"Device {self.device_id} for {self.user.email}"

    def is_expired(self):
        return timezone.now() > self.expires_at

    def update_last_used(self):
        self.last_used = timezone.now()
        self.save()

class TrustSettings(models.Model):
    DURATION_CHOICES = [
        (30, '30 days'),
        (60, '60 days'),
        (90, '90 days'),
    ]

    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    trust_duration = models.IntegerField(choices=DURATION_CHOICES, default=30)
    require_2fa_new_ip = models.BooleanField(default=True)
    max_trusted_devices = models.IntegerField(default=5)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Trust Settings"
        verbose_name_plural = "Trust Settings"

    def __str__(self):
        return f"Trust settings for {self.user.email}"

class ActivityLog(models.Model):
    ACTION_TYPES = [
        ('login', 'Login'),
        ('password', 'Password Change'),
        ('2fa', '2FA Change'),
        ('security', 'Security Settings'),
    ]

    STATUS_CHOICES = [
        ('success', 'Success'),
        ('failed', 'Failed'),
        ('blocked', 'Blocked'),
    ]

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    timestamp = models.DateTimeField(auto_now_add=True)
    action_type = models.CharField(max_length=20, choices=ACTION_TYPES)
    action = models.CharField(max_length=255)
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField()
    status = models.CharField(max_length=20, choices=STATUS_CHOICES)
    details = models.JSONField(default=dict, blank=True)

    class Meta:
        verbose_name = "Activity Log"
        verbose_name_plural = "Activity Logs"
        ordering = ['-timestamp']

    def __str__(self):
        return f"{self.action_type} by {self.user.email} at {self.timestamp}"

class DeletionTask(models.Model):
    """Model for tracking data deletion tasks"""
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    request_id = models.UUIDField()
    task_type = models.CharField(max_length=50)
    description = models.TextField()
    scheduled_date = models.DateTimeField()
    completed_date = models.DateTimeField(null=True, blank=True)
    status = models.CharField(
        max_length=20,
        choices=[
            ('scheduled', _('Scheduled')),
            ('in_progress', _('In Progress')),
            ('completed', _('Completed')),
            ('failed', _('Failed')),
            ('cancelled', _('Cancelled'))
        ],
        default='scheduled'
    )
    error_message = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _('Deletion Task')
        verbose_name_plural = _('Deletion Tasks')
        ordering = ['scheduled_date', 'status']
        indexes = [
            models.Index(fields=['user', 'status']),
            models.Index(fields=['scheduled_date']),
            models.Index(fields=['request_id']),
        ]

    def __str__(self):
        return f"{self.task_type} - {self.status} ({self.user.username})"

    def mark_completed(self):
        self.status = 'completed'
        self.completed_date = timezone.now()
        self.save()

    def mark_failed(self, error_message):
        self.status = 'failed'
        self.error_message = error_message
        self.save()

class BreachNotification(models.Model):
    """Model for tracking breach notifications sent to users"""
    breach = models.ForeignKey(DataBreach, on_delete=models.CASCADE)
    recipient = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    status = models.CharField(max_length=20, choices=[
        ('pending', _('Pending')),
        ('sent', _('Sent')),
        ('acknowledged', _('Acknowledged')),
        ('failed', _('Failed'))
    ], default='pending')
    created_at = models.DateTimeField(auto_now_add=True)
    sent_at = models.DateTimeField(null=True, blank=True)
    acknowledged_at = models.DateTimeField(null=True, blank=True)
    notification_method = models.CharField(max_length=20, default='email')
    notification_data = models.JSONField(default=dict)
    
    class Meta:
        verbose_name = _('Breach Notification')
        verbose_name_plural = _('Breach Notifications')
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['status', 'created_at']),
            models.Index(fields=['recipient', 'breach']),
        ]

    def __str__(self):
        return f"Breach notification for {self.recipient} - {self.get_status_display()}"

class ConsentRecord(models.Model):
    """Model for tracking user consent records"""
    CONSENT_TYPES = [
        ('privacy_policy', _('Privacy Policy')),
        ('cookie_usage', _('Cookie Usage')),
        ('marketing', _('Marketing Communications')),
        ('data_processing', _('Data Processing')),
        ('data_sharing', _('Data Sharing')),
        ('special_category', _('Special Category Data')),
    ]
    
    STATUS_CHOICES = [
        ('active', _('Active')),
        ('withdrawn', _('Withdrawn')),
        ('expired', _('Expired')),
    ]
    
    # Consent details
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    consent_type = models.CharField(max_length=50, choices=CONSENT_TYPES)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='active')
    
    # Consent data
    purpose = models.TextField(help_text=_("Purpose of data processing"))
    data_categories = models.JSONField(help_text=_("Categories of data covered by consent"))
    processing_activities = models.JSONField(help_text=_("Specific processing activities consented to"))
    third_parties = models.JSONField(blank=True, null=True, help_text=_("Third parties data may be shared with"))
    
    # Timestamps
    granted_at = models.DateTimeField(auto_now_add=True)
    last_updated = models.DateTimeField(auto_now=True)
    valid_until = models.DateTimeField(null=True, blank=True)
    withdrawn_at = models.DateTimeField(null=True, blank=True)
    
    # Collection context
    collection_method = models.CharField(max_length=50, help_text=_("How consent was collected"))
    proof_of_consent = EncryptedField(help_text=_("Evidence of consent collection"))
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    
    # Version tracking
    policy_version = models.CharField(max_length=50, blank=True)
    form_version = models.CharField(max_length=50, blank=True)
    
    # Metadata
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name='created_consents'
    )
    notes = models.TextField(blank=True)
    
    class Meta:
        verbose_name = _('Consent Record')
        verbose_name_plural = _('Consent Records')
        ordering = ['-granted_at']
        indexes = [
            models.Index(fields=['user', 'consent_type']),
            models.Index(fields=['status', 'valid_until']),
        ]
        unique_together = ['user', 'consent_type', 'policy_version']

    def __str__(self):
        return f"{self.user.email} - {self.get_consent_type_display()} ({self.status})"

    def withdraw_consent(self):
        """Withdraw user consent"""
        self.status = 'withdrawn'
        self.withdrawn_at = timezone.now()
        self.save()

    def is_valid(self):
        """Check if consent is currently valid"""
        if self.status != 'active':
            return False
        if self.valid_until and timezone.now() > self.valid_until:
            self.status = 'expired'
            self.save()
            return False
        return True

    def extend_validity(self, days=365):
        """Extend the validity period of consent"""
        if self.status == 'active':
            self.valid_until = (self.valid_until or timezone.now()) + timedelta(days=days)
            self.save()

    def get_processing_history(self):
        """Get history of data processing under this consent"""
        return {
            'granted_at': self.granted_at,
            'last_updated': self.last_updated,
            'valid_until': self.valid_until,
            'status': self.status,
            'processing_activities': self.processing_activities,
            'collection_context': {
                'method': self.collection_method,
                'ip_address': self.ip_address,
                'user_agent': self.user_agent,
            }
        }

class Task(models.Model):
    """Model for tracking compliance tasks and to-dos"""
    description = models.CharField(max_length=255)
    due_date = models.DateTimeField()
    priority = models.CharField(max_length=20, choices=[
        ('low', _('Low')),
        ('medium', _('Medium')),
        ('high', _('High'))
    ])
    status = models.CharField(max_length=20, choices=[
        ('pending', _('Pending')),
        ('in_progress', _('In Progress')),
        ('completed', _('Completed')),
        ('blocked', _('Blocked'))
    ], default='pending')
    assigned_to = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name='assigned_tasks'
    )
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name='created_tasks'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    notes = models.TextField(blank=True)
    category = models.CharField(max_length=50, choices=[
        ('compliance', _('Compliance')),
        ('documentation', _('Documentation')),
        ('training', _('Training')),
        ('review', _('Review')),
        ('other', _('Other'))
    ])

    class Meta:
        verbose_name = _('Task')
        verbose_name_plural = _('Tasks')
        ordering = ['due_date', 'priority']
        indexes = [
            models.Index(fields=['status']),
            models.Index(fields=['due_date']),
            models.Index(fields=['priority']),
        ]

    def __str__(self):
        return f"{self.description} ({self.get_status_display()})"

    def is_overdue(self):
        return self.due_date < timezone.now() and self.status == 'pending'

class Report(models.Model):
    """Model for storing generated reports"""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    type = models.CharField(max_length=50, choices=[
        ('data_processing', _('Data Processing Activities')),
        ('data_breaches', _('Data Breaches')),
        ('user_requests', _('User Requests')),
        ('consent_management', _('Consent Management')),
        ('compliance_audit', _('Compliance Audit'))
    ])
    date_from = models.DateTimeField()
    date_to = models.DateTimeField()
    generated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name='generated_reports'
    )
    generated_at = models.DateTimeField(auto_now_add=True)
    data = models.JSONField()
    file = models.FileField(upload_to='reports/%Y/%m/%d/', null=True, blank=True)

    class Meta:
        verbose_name = _('Report')
        verbose_name_plural = _('Reports')
        ordering = ['-generated_at']

    def __str__(self):
        return f"{self.get_type_display()} ({self.generated_at})"

class ReportSchedule(models.Model):
    """Model for scheduling recurring reports"""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    report_type = models.CharField(max_length=50, choices=[
        ('data_processing', _('Data Processing Activities')),
        ('data_breaches', _('Data Breaches')),
        ('user_requests', _('User Requests')),
        ('consent_management', _('Consent Management')),
        ('compliance_audit', _('Compliance Audit'))
    ])
    frequency = models.CharField(max_length=20, choices=[
        ('daily', _('Daily')),
        ('weekly', _('Weekly')),
        ('monthly', _('Monthly')),
        ('quarterly', _('Quarterly'))
    ])
    recipients = models.ManyToManyField(
        settings.AUTH_USER_MODEL,
        related_name='report_subscriptions'
    )
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name='created_report_schedules'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    last_run = models.DateTimeField(null=True, blank=True)
    next_run = models.DateTimeField()
    is_active = models.BooleanField(default=True)

    class Meta:
        verbose_name = _('Report Schedule')
        verbose_name_plural = _('Report Schedules')
        ordering = ['next_run']

    def __str__(self):
        return f"{self.get_report_type_display()} - {self.get_frequency_display()}"

    def save(self, *args, **kwargs):
        if not self.next_run:
            self.next_run = self._calculate_next_run()
        super().save(*args, **kwargs)

    def _calculate_next_run(self):
        """Calculate the next run time based on frequency"""
        now = timezone.now()
        if self.frequency == 'daily':
            return now + timedelta(days=1)
        elif self.frequency == 'weekly':
            return now + timedelta(weeks=1)
        elif self.frequency == 'monthly':
            return now + timedelta(days=30)
        elif self.frequency == 'quarterly':
            return now + timedelta(days=90)
        return now

    def update_next_run(self):
        """Update the next run time after a report is generated"""
        self.last_run = timezone.now()
        self.next_run = self._calculate_next_run()
        self.save()
