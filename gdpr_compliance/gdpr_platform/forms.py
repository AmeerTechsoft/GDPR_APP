from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth import get_user_model
from django.core.validators import RegexValidator, EmailValidator, FileExtensionValidator
from django.utils.translation import gettext_lazy as _
from django.core.exceptions import ValidationError
from django.conf import settings
import re
import mimetypes
from datetime import date
from django.utils import timezone
import logging
import os
from PIL import Image
from django.utils.html import strip_tags
from bleach import clean as bleach_clean
from typing import Any, Dict, Optional
from django.forms import ValidationError as DjangoValidationError
from .models import DataRequest, CrossBorderTransfer

logger = logging.getLogger(__name__)

User = get_user_model()

def validate_file_type(value):
    """Validate file type using mimetypes"""
    mime_type, _ = mimetypes.guess_type(value.name)
    valid_types = ['image/jpeg', 'image/png', 'application/pdf', 
                  'application/msword',
                  'application/vnd.openxmlformats-officedocument.wordprocessingml.document']
    
    if mime_type not in valid_types:
        raise ValidationError(
            _('Unsupported file type. Allowed types: JPEG, PNG, PDF, DOC, DOCX')
        )
    
    # Additional size validation
    if value.size > 5 * 1024 * 1024:  # 5MB limit
        raise ValidationError(_('File size cannot exceed 5MB'))

class BaseFormMixin:
    """Base mixin class with CSRF protection and security features"""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Add CSRF token to all forms
        self.fields['csrfmiddlewaretoken'] = forms.CharField(
            widget=forms.HiddenInput(),
            required=False  # Django's middleware will handle the validation
        )
        
        # Add security headers to all forms
        for field in self.fields.values():
            if isinstance(field.widget, forms.TextInput):
                field.widget.attrs.update({
                    'autocomplete': 'off',
                    'autocorrect': 'off',
                    'autocapitalize': 'off',
                    'spellcheck': 'false'
                })
    
    def clean(self):
        """Sanitize all form data to prevent XSS and injection attacks"""
        cleaned_data = super().clean()
        
        for field_name, value in cleaned_data.items():
            if isinstance(value, str):
                # Strip HTML tags from all string fields
                cleaned_value = strip_tags(value)
                # Additional sanitization using bleach
                cleaned_value = bleach_clean(
                    cleaned_value,
                    tags=[],  # No HTML tags allowed
                    strip=True,
                    strip_comments=True
                )
                # Remove any null bytes
                cleaned_value = cleaned_value.replace('\x00', '')
                # Normalize whitespace
                cleaned_value = ' '.join(cleaned_value.split())
                
                cleaned_data[field_name] = cleaned_value
        
        return cleaned_data

class BaseForm(BaseFormMixin, forms.Form):
    """Base form class for regular forms"""
    pass

class BaseModelForm(BaseFormMixin, forms.ModelForm):
    """Base form class for model forms"""
    pass

class RegistrationForm(BaseModelForm, UserCreationForm):
    """User registration form with GDPR compliance"""
    
    email = forms.EmailField(
        required=True,
        validators=[EmailValidator()],
        widget=forms.EmailInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter your email',
            'autocomplete': 'email'
        })
    )
    
    phone_number = forms.CharField(
        max_length=20, 
        required=False,
        validators=[RegexValidator(
            regex=r'^\+?[1-9]\d{1,14}$',
            message=_("Phone number must be in E.164 format (e.g., +1234567890)")
        )],
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': '+1234567890',
            'autocomplete': 'tel'
        })
    )
    
    date_of_birth = forms.DateField(
        required=False,
        widget=forms.DateInput(attrs={
            'type': 'date',
            'class': 'form-control',
            'autocomplete': 'bday'
        }),
        help_text=_("You must be at least 16 years old to register.")
    )

    # Contact Information Fields
    address = forms.CharField(
        max_length=255,
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter your address',
            'autocomplete': 'street-address'
        })
    )

    city = forms.CharField(
        max_length=100,
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter your city',
            'autocomplete': 'address-level2'
        })
    )

    country = forms.CharField(
        max_length=100,
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter your country',
            'autocomplete': 'country-name'
        })
    )

    postal_code = forms.CharField(
        max_length=20,
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter your postal code',
            'autocomplete': 'postal-code'
        })
    )

    # Additional Information Fields
    nationality = forms.CharField(
        max_length=100,
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter your nationality'
        })
    )

    occupation = forms.CharField(
        max_length=200,
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter your occupation'
        })
    )

    company = forms.CharField(
        max_length=200,
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter your company name'
        })
    )

    preferred_language = forms.CharField(
        max_length=50,
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter your preferred language'
        })
    )
    
    profile_photo = forms.ImageField(
        required=False,
        validators=[
            FileExtensionValidator(allowed_extensions=['jpg', 'jpeg', 'png']),
        ],
        widget=forms.FileInput(attrs={
            'class': 'form-control',
            'accept': 'image/jpeg,image/png'
        }),
        help_text=_("Maximum file size: 5MB. Supported formats: JPEG, PNG")
    )
    
    privacy_policy_consent = forms.BooleanField(
        required=True,
        widget=forms.CheckboxInput(attrs={'class': 'form-check-input'}),
        label=_("I have read and agree to the Privacy Policy"),
        help_text=_("Required. We need your consent to process your personal data according to our privacy policy.")
    )
    
    data_processing_consent = forms.BooleanField(
        required=True,
        widget=forms.CheckboxInput(attrs={'class': 'form-check-input'}),
        label=_("I consent to the processing of my personal data"),
        help_text=_("Required. This allows us to provide our services to you in compliance with GDPR.")
    )
    
    marketing_consent = forms.BooleanField(
        required=False,
        widget=forms.CheckboxInput(attrs={'class': 'form-check-input'}),
        label=_("I would like to receive marketing communications"),
        help_text=_("Optional. You can change or withdraw this consent at any time in your privacy settings.")
    )
    
    class Meta(UserCreationForm.Meta):
        model = User
        fields = (
            'username', 'email', 'password1', 'password2',
            'first_name', 'last_name', 'phone_number',
            'date_of_birth', 'address', 'city', 'country',
            'postal_code', 'nationality', 'occupation',
            'company', 'preferred_language', 'profile_photo',
            'privacy_policy_consent', 'data_processing_consent',
            'marketing_consent'
        )
    
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        # Add security attributes to sensitive fields
        self.fields['username'].widget.attrs.update({
            'class': 'form-control',
            'placeholder': 'Choose a username',
            'autocomplete': 'username'
        })
        self.fields['password1'].widget.attrs.update({
            'class': 'form-control',
            'placeholder': 'Enter password',
            'autocomplete': 'new-password'
        })
        self.fields['password2'].widget.attrs.update({
            'class': 'form-control',
            'placeholder': 'Confirm password',
            'autocomplete': 'new-password'
        })
        self.fields['first_name'].widget.attrs.update({
            'class': 'form-control',
            'placeholder': 'First name',
            'autocomplete': 'given-name'
        })
        self.fields['last_name'].widget.attrs.update({
            'class': 'form-control',
            'placeholder': 'Last name',
            'autocomplete': 'family-name'
        })

    def clean_password1(self) -> str:
        password = self.cleaned_data.get('password1')
        if password:
            # Check password strength
            if len(password) < 12:
                raise DjangoValidationError(_("Password must be at least 12 characters long."))
            if not re.search(r'[A-Z]', password):
                raise DjangoValidationError(_("Password must contain at least one uppercase letter."))
            if not re.search(r'[a-z]', password):
                raise DjangoValidationError(_("Password must contain at least one lowercase letter."))
            if not re.search(r'\d', password):
                raise DjangoValidationError(_("Password must contain at least one number."))
            if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
                raise DjangoValidationError(_("Password must contain at least one special character."))
            
            # Check for common passwords
            common_passwords = getattr(settings, 'COMMON_PASSWORDS', [])
            if password.lower() in common_passwords:
                raise DjangoValidationError(_("This password is too common. Please choose a different one."))
        
        return password

    def clean_email(self) -> str:
        email = self.cleaned_data.get('email')
        if email:
            email = email.lower()
        if User.objects.filter(email__iexact=email).exists():
                raise DjangoValidationError(_("This email address is already registered."))
            
            # Check for disposable email providers
        domain = email.split('@')[1]
        disposable_domains = getattr(settings, 'DISPOSABLE_EMAIL_DOMAINS', [])
        if domain in disposable_domains:
            raise DjangoValidationError(_("Please use a valid email address. Disposable email providers are not allowed."))
        
        return email

    def clean_profile_photo(self) -> Optional[Any]:
        photo = self.cleaned_data.get('profile_photo')
        if photo:
            # Check file size
            max_size = getattr(settings, 'MAX_UPLOAD_SIZE', 5 * 1024 * 1024)  # Default 5MB
            if photo.size > max_size:
                raise DjangoValidationError(_("Image file too large (> %(size)s MB)") % {'size': max_size / (1024 * 1024)})
            
            try:
                # Use mimetypes for file type detection
                mime_type, _ = mimetypes.guess_type(photo.name)
                if not mime_type:
                    raise DjangoValidationError(_("Could not determine file type. Please upload a valid JPEG or PNG file."))
                
                allowed_types = ['image/jpeg', 'image/png']
                if mime_type not in allowed_types:
                    raise DjangoValidationError(_("Invalid file type. Only JPEG and PNG images are allowed."))
                
                # Additional security check for file extension
                file_extension = os.path.splitext(photo.name)[1].lower()
                allowed_extensions = ['.jpg', '.jpeg', '.png']
                if file_extension not in allowed_extensions:
                    raise DjangoValidationError(_("Invalid file extension. Only .jpg, .jpeg, and .png files are allowed."))
                
                # Verify image dimensions
                try:
                    with Image.open(photo) as img:
                        # Check maximum dimensions
                        max_dimension = getattr(settings, 'MAX_IMAGE_DIMENSION', 2000)
                        if img.width > max_dimension or img.height > max_dimension:
                            raise DjangoValidationError(_(
                                "Image dimensions too large. Maximum allowed dimension is %(max_dim)s pixels"
                            ) % {'max_dim': max_dimension})
                        
                        # Check minimum dimensions
                        min_dimension = getattr(settings, 'MIN_IMAGE_DIMENSION', 100)
                        if img.width < min_dimension or img.height < min_dimension:
                            raise DjangoValidationError(_(
                                "Image dimensions too small. Minimum allowed dimension is %(min_dim)s pixels"
                            ) % {'min_dim': min_dimension})
                        
                        # Verify it's actually an image
                        img.verify()
                        
                except Exception as e:
                    raise DjangoValidationError(_("Invalid image file. Please upload a valid JPEG or PNG file."))
                
            except Exception as e:
                logger.error(f"Error validating profile photo: {str(e)}")
                raise DjangoValidationError(_("Error verifying file type. Please try again."))
        
        return photo

    def clean_date_of_birth(self) -> Optional[date]:
        dob = self.cleaned_data.get('date_of_birth')
        if dob:
            today = date.today()
            age = today.year - dob.year - ((today.month, today.day) < (dob.month, dob.day))
            if age < 16:
                raise DjangoValidationError(_("You must be at least 16 years old to register."))
            if age > 120:
                raise DjangoValidationError(_("Please enter a valid date of birth."))
        return dob

    def clean(self) -> Dict[str, Any]:
        cleaned_data = super().clean()
        
        # Validate required consents
        if not cleaned_data.get('privacy_policy_consent'):
            self.add_error('privacy_policy_consent', _('You must accept the privacy policy to continue.'))
        
        if not cleaned_data.get('data_processing_consent'):
            self.add_error('data_processing_consent', _('You must consent to data processing to continue.'))
        
        # Additional username validation
        username = cleaned_data.get('username')
        if username:
            if len(username) < 3:
                self.add_error('username', _('Username must be at least 3 characters long.'))
            if not re.match(r'^[\w.@+-]+$', username):
                self.add_error('username', _('Username can only contain letters, numbers, and @/./+/-/_ characters.'))
        
        return cleaned_data

    def save(self, commit: bool = True) -> Any:
        try:
            user = super().save(commit=False)
            user.email = self.cleaned_data['email'].lower()
            
            # Set marketing preferences
            user.marketing_preferences = {
                'email_marketing': self.cleaned_data.get('marketing_consent', False),
                'consent_date': str(timezone.now().date()),
                'last_updated': str(timezone.now()),
                'consent_version': settings.COOKIE_POLICY_VERSION
            }
            
            # Set data retention preferences from settings
            user.data_retention_policy = getattr(settings, 'GDPR_RETENTION_PERIODS', {
                'personal_info': {'retention_period': 2555, 'unit': 'days'},  # 7 years
                'sensitive_data': {'retention_period': 0, 'unit': 'days'},
                'professional_info': {'retention_period': 2555, 'unit': 'days'},
                'preferences': {'retention_period': 30, 'unit': 'days'},
                'security_logs': {'retention_period': 365, 'unit': 'days'},
            })
            
            if commit:
                user.save()
            
            return user
            
        except Exception as e:
            logger.error(f"Error creating user: {str(e)}")
            raise DjangoValidationError(_('Error creating user account. Please try again.')) from e

class DataRequestForm(BaseModelForm):
    class Meta:
        model = DataRequest
        fields = ('request_type', 'notes')
        widgets = {
            'notes': forms.Textarea(attrs={
                'rows': 4,
                'class': 'form-control',
                'maxlength': 1000  # Limit text length
            }),
        }
    
    def clean_notes(self) -> str:
        """Sanitize notes field"""
        notes = self.cleaned_data.get('notes', '')
        if notes:
            # Strip HTML and sanitize
            notes = strip_tags(notes)
            notes = bleach_clean(
                notes,
                tags=[],
                strip=True,
                strip_comments=True
            )
            # Remove any null bytes and normalize whitespace
            notes = notes.replace('\x00', '')
            notes = ' '.join(notes.split())
            
            # Check length after sanitization
            if len(notes) > 1000:
                raise DjangoValidationError(_("Notes field cannot exceed 1000 characters."))
        
        return notes

class CookiePreferencesForm(BaseForm):
    analytics_cookies = forms.BooleanField(
        required=False,
        widget=forms.CheckboxInput(attrs={'class': 'form-check-input'}),
        label=_("Analytics Cookies"),
        help_text=_("Allow us to analyze website usage to improve user experience.")
    )
    
    marketing_cookies = forms.BooleanField(
        required=False,
        widget=forms.CheckboxInput(attrs={'class': 'form-check-input'}),
        label=_("Marketing Cookies"),
        help_text=_("Allow us to personalize your experience and send relevant offers.")
    )
    
    functional_cookies = forms.BooleanField(
        required=False,
        widget=forms.CheckboxInput(attrs={'class': 'form-check-input'}),
        label=_("Functional Cookies"),
        help_text=_("Enable advanced features and personalization.")
    )
    
    def clean(self) -> Dict[str, Any]:
        cleaned_data = super().clean()
        
        # Ensure at least necessary cookies are accepted (they're always required)
        cleaned_data['necessary_cookies'] = True
        
        # Log consent for audit
        self.consent_timestamp = timezone.now()
        
        return cleaned_data

class CrossBorderTransferForm(BaseModelForm):
    class Meta:
        model = CrossBorderTransfer
        fields = ('recipient_country', 'recipient_organization', 'data_categories', 
                 'transfer_mechanism', 'safeguards', 'transfer_date', 'expiry_date',
                 'risk_level')
        widgets = {
            'data_categories': forms.Textarea(attrs={
                'rows': 3,
                'class': 'form-control',
                'maxlength': 1000
            }),
            'safeguards': forms.Textarea(attrs={
                'rows': 3,
                'class': 'form-control',
                'maxlength': 1000
            }),
            'transfer_date': forms.DateInput(attrs={
                'type': 'date',
                'class': 'form-control'
            }),
            'expiry_date': forms.DateInput(attrs={
                'type': 'date',
                'class': 'form-control'
            }),
        }
    
    def clean(self) -> Dict[str, Any]:
        cleaned_data = super().clean()
        transfer_date = cleaned_data.get('transfer_date')
        expiry_date = cleaned_data.get('expiry_date')
        
        if transfer_date and expiry_date and transfer_date > expiry_date:
            raise DjangoValidationError(_("Transfer date must be before expiry date."))
        
        return cleaned_data

class TwoFactorSetupForm(BaseForm):
    verification_code = forms.CharField(
        max_length=6,
        min_length=6,
        validators=[RegexValidator(r'^[0-9]{6}$', _('Enter a valid 6-digit code.'))],
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': _('Enter 6-digit code'),
            'autocomplete': 'off',
            'pattern': '[0-9]{6}',
            'inputmode': 'numeric'
        })
    )

    def clean_verification_code(self) -> str:
        code = self.cleaned_data.get('verification_code')
        if code:
            # Remove any whitespace
            code = ''.join(code.split())
            # Ensure it's exactly 6 digits
            if not code.isdigit() or len(code) != 6:
                raise DjangoValidationError(_("Please enter a valid 6-digit code."))
        return code

class TrustSettingsForm(BaseForm):
    trust_duration = forms.ChoiceField(
        choices=[
            (30, _('30 days')),
            (60, _('60 days')),
            (90, _('90 days')),
        ],
        widget=forms.Select(attrs={'class': 'form-select'})
    )
    require_2fa_new_ip = forms.BooleanField(
        required=False,
        widget=forms.CheckboxInput(attrs={'class': 'form-check-input'})
    )
    max_trusted_devices = forms.IntegerField(
        min_value=1,
        max_value=10,
        initial=5,
        widget=forms.NumberInput(attrs={
            'class': 'form-control',
            'min': '1',
            'max': '10'
        })
    )

    def clean_max_trusted_devices(self) -> int:
        devices = self.cleaned_data.get('max_trusted_devices')
        if devices is not None:
            if devices < 1:
                raise DjangoValidationError(_("Must allow at least one trusted device."))
            if devices > 10:
                raise DjangoValidationError(_("Cannot allow more than 10 trusted devices."))
        return devices

class ActivityFilterForm(BaseForm):
    ACTION_TYPES = [
        ('', _('All Activities')),
        ('login', _('Login Attempts')),
        ('password', _('Password Changes')),
        ('2fa', _('2FA Changes')),
        ('security', _('Security Settings')),
    ]

    activity_type = forms.ChoiceField(
        choices=ACTION_TYPES,
        required=False,
        widget=forms.Select(attrs={'class': 'form-select'})
    )
    date_from = forms.DateField(
        required=False,
        widget=forms.DateInput(attrs={
            'class': 'form-control',
            'type': 'date'
        })
    )
    date_to = forms.DateField(
        required=False,
        widget=forms.DateInput(attrs={
            'class': 'form-control',
            'type': 'date'
        })
    )
    
    def clean(self) -> Dict[str, Any]:
        cleaned_data = super().clean()
        date_from = cleaned_data.get('date_from')
        date_to = cleaned_data.get('date_to')
        
        if date_from and date_to and date_from > date_to:
            raise DjangoValidationError(_("Start date must be before end date."))
        
        return cleaned_data