from django.apps import AppConfig


class IdentityConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.identity"

    def ready(self):
        from django.db.models.signals import post_migrate
        from .signals import create_default_admin
        post_migrate.connect(create_default_admin, sender=self)

