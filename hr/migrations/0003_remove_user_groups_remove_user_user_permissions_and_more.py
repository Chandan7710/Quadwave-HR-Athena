# Generated by Django 5.0.4 on 2024-06-21 09:08

from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [
        ("hr", "0002_user_registration"),
    ]

    operations = [
        migrations.RemoveField(
            model_name="user",
            name="groups",
        ),
        migrations.RemoveField(
            model_name="user",
            name="user_permissions",
        ),
        migrations.DeleteModel(
            name="Registration",
        ),
        migrations.DeleteModel(
            name="User",
        ),
    ]