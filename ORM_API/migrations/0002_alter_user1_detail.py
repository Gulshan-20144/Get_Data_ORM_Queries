# Generated by Django 5.0.2 on 2024-03-15 13:07

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('ORM_API', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='user1',
            name='detail',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL, to_field='username'),
        ),
    ]
