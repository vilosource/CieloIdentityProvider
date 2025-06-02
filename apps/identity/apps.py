from django.apps import AppConfig


class IdentityConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.identity"
    
    def ready(self):
        # Import signals to register them
        import apps.identity.signals

