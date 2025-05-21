"""
ASGI config for gdpr_compliance project.
"""

import os
from django.core.asgi import get_asgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'gdpr_compliance.settings')

application = get_asgi_application()
