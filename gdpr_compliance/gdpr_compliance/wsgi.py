"""
WSGI config for gdpr_compliance project.
"""

import os
from django.core.wsgi import get_wsgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'gdpr_compliance.settings')

application = get_wsgi_application()
