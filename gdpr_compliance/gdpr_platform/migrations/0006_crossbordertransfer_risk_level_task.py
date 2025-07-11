# Generated by Django 4.2.19 on 2025-03-05 17:48

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('gdpr_platform', '0005_usersession_end_reason'),
    ]

    operations = [
        migrations.AddField(
            model_name='crossbordertransfer',
            name='risk_level',
            field=models.CharField(choices=[('low', 'Low Risk'), ('medium', 'Medium Risk'), ('high', 'High Risk')], default='low', max_length=10),
        ),
        migrations.CreateModel(
            name='Task',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('description', models.CharField(max_length=255)),
                ('due_date', models.DateTimeField()),
                ('priority', models.CharField(choices=[('low', 'Low'), ('medium', 'Medium'), ('high', 'High')], max_length=20)),
                ('status', models.CharField(choices=[('pending', 'Pending'), ('in_progress', 'In Progress'), ('completed', 'Completed'), ('blocked', 'Blocked')], default='pending', max_length=20)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('notes', models.TextField(blank=True)),
                ('category', models.CharField(choices=[('compliance', 'Compliance'), ('documentation', 'Documentation'), ('training', 'Training'), ('review', 'Review'), ('other', 'Other')], max_length=50)),
                ('assigned_to', models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='assigned_tasks', to=settings.AUTH_USER_MODEL)),
                ('created_by', models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='created_tasks', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'verbose_name': 'Task',
                'verbose_name_plural': 'Tasks',
                'ordering': ['due_date', 'priority'],
                'indexes': [models.Index(fields=['status'], name='gdpr_platfo_status_edbcbd_idx'), models.Index(fields=['due_date'], name='gdpr_platfo_due_dat_ffb924_idx'), models.Index(fields=['priority'], name='gdpr_platfo_priorit_1986a1_idx')],
            },
        ),
    ]
