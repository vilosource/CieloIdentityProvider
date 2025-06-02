from django.contrib.auth.models import User
from django.db.models.signals import post_migrate
from django.dispatch import receiver
from django.conf import settings

@receiver(post_migrate)
def create_default_admin(sender, **kwargs):
    """Create a default admin user on first migrate."""
    
    if not settings.DEBUG:
        return  # Only do this in development

    if not User.objects.filter(username="admin").exists():
        print("Creating default admin user...")
        User.objects.create_superuser(
            username="admin", 
            password="admin", 
            email="admin@example.com"
        )
