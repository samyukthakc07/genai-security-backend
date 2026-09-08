from django.apps import AppConfig


class SecurityEngineConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.security_engine'
    verbose_name = 'GenAI Security Platform - Security Engine'

    def ready(self):
        """Discover and register all detection plugins on startup."""
        from apps.security_engine.registry import plugin_registry
        plugin_registry.discover_plugins()
