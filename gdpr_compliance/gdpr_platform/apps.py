from django.apps import AppConfig


class GdprPlatformConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'gdpr_platform'

    def ready(self):
        # Import and start the breach monitoring system
        from .monitoring import breach_monitor
        breach_monitor.start_monitoring()
