# Generated by Django 4.2.19 on 2025-03-06 01:06

from django.db import migrations, models
import uuid


class Migration(migrations.Migration):

    dependencies = [
        ('gdpr_platform', '0009_remove_userbreachnotification_breach_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='breachnotification',
            name='id',
            field=models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False),
        ),
    ]
