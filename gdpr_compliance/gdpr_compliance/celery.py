import os
from celery import Celery
from celery.schedules import crontab

# Set the default Django settings module for the 'celery' program
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'gdpr_compliance.settings')

# Create the Celery app
app = Celery('gdpr_compliance')

# Using a string here means the worker doesn't have to serialize
# the configuration object to child processes
app.config_from_object('django.conf:settings', namespace='CELERY')

# Load task modules from all registered Django app configs
app.autodiscover_tasks()

# Configure periodic tasks
app.conf.beat_schedule = {
    # Data retention tasks
    'cleanup-expired-data': {
        'task': 'gdpr_platform.tasks.cleanup_expired_data',
        'schedule': crontab(hour=2, minute=0),  # Run daily at 2:00 AM
        'options': {'expires': 3600}  # Task expires after 1 hour
    },
    
    # Monitoring tasks
    'monitor-data-breaches': {
        'task': 'gdpr_platform.tasks.monitor_data_breaches',
        'schedule': crontab(minute=0, hour='*/1'),  # Run every hour
        'options': {'expires': 3600}
    },
    'monitor-data-requests': {
        'task': 'gdpr_platform.tasks.monitor_data_requests',
        'schedule': crontab(hour=9, minute=0),  # Run daily at 9:00 AM
        'options': {'expires': 3600}
    },
    
    # Reporting tasks
    'generate-scheduled-reports': {
        'task': 'gdpr_platform.tasks.generate_scheduled_reports',
        'schedule': crontab(hour=5, minute=0),  # Run daily at 5:00 AM
        'options': {'expires': 7200}  # Task expires after 2 hours
    },
}

# Task routing
app.conf.task_routes = {
    'gdpr_platform.tasks.cleanup_expired_data': {'queue': 'maintenance'},
    'gdpr_platform.tasks.monitor_data_breaches': {'queue': 'monitoring'},
    'gdpr_platform.tasks.monitor_data_requests': {'queue': 'monitoring'},
    'gdpr_platform.tasks.generate_scheduled_reports': {'queue': 'reporting'},
}

# Task settings
app.conf.task_time_limit = 1800  # 30 minutes
app.conf.task_soft_time_limit = 1500  # 25 minutes
app.conf.worker_prefetch_multiplier = 1  # Disable prefetching
app.conf.task_acks_late = True  # Tasks are acknowledged after execution

@app.task(bind=True)
def debug_task(self):
    print(f'Request: {self.request!r}') 