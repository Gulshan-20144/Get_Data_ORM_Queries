# Generated by Django 5.0.2 on 2024-03-16 13:44

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('ORM_API', '0004_remove_user1_detail_user1_detail'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='user1',
            name='detail',
        ),
        migrations.AddField(
            model_name='user1',
            name='detail',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, related_name='User', to=settings.AUTH_USER_MODEL, to_field='username'),
        ),
    ]