# Generated by Django 4.2.19 on 2025-03-04 13:21

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('gdpr_platform', '0004_deletiontask'),
    ]

    operations = [
        migrations.AddField(
            model_name='usersession',
            name='end_reason',
            field=models.CharField(blank=True, choices=[('user_logout', 'User Logout'), ('session_expired', 'Session Expired'), ('security_logout', 'Security Logout'), ('revoked', 'Manually Revoked'), ('revoked_all', 'All Sessions Revoked'), ('system_terminated', 'System Terminated')], max_length=50, null=True),
        ),
    ]
