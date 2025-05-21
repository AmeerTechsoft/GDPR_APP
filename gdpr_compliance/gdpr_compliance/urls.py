"""
URL configuration for gdpr_compliance project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from django.views.generic import RedirectView
from gdpr_platform import api


# Configure admin site
admin.site.site_header = 'GDPR Compliance Platform'
admin.site.site_title = 'GDPR Admin'
admin.site.index_title = 'Administration'
admin.site.login_template = settings.ADMIN_LOGIN_TEMPLATE
admin.site.login_url = settings.ADMIN_LOGIN_URL

urlpatterns = [
    path('admin/', admin.site.urls),
    path('gdpr/', include('gdpr_platform.urls')),
    path('', RedirectView.as_view(url='/gdpr/', permanent=False)),
    
    # Redirect all auth-related URLs to our custom implementation
    path('accounts/login/', RedirectView.as_view(url='/gdpr/login/', permanent=True)),
    path('accounts/logout/', RedirectView.as_view(url='/gdpr/logout/', permanent=True)),
    path('accounts/password_reset/', RedirectView.as_view(url='/gdpr/reset-password/', permanent=True)),
    path('accounts/password_reset/done/', RedirectView.as_view(url='/gdpr/reset-password/done/', permanent=True)),
    path('accounts/reset/<uidb64>/<token>/', 
         RedirectView.as_view(
             url='/gdpr/reset-password/confirm/%(uidb64)s/%(token)s/',
             permanent=True,
             query_string=True
         )),
    path('accounts/reset/done/', RedirectView.as_view(url='/gdpr/reset-password/complete/', permanent=True)),
    
    # API endpoints
    path('api/v1/', api.api_root, name='api_root'),
    path('api/v1/breaches/', api.data_breaches, name='api_breaches'),
    path('api/v1/breaches/<uuid:breach_id>/', api.data_breach_detail, name='api_breach_detail'),
    path('api/v1/requests/', api.data_requests, name='api_requests'),
    path('api/v1/webhooks/<str:webhook_type>/', api.webhook_receiver, name='webhook_receiver'),
]

# Serve media files in development
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
