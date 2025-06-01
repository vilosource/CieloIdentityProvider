from django.contrib.auth.models import User

def create_default_admin(sender, **kwargs):
    """Create a default admin user on first migrate."""
    if not User.objects.filter(username="admin").exists():
        User.objects.create_superuser("admin", password="admin", email="")

