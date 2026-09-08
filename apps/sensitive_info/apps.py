from django.apps import AppConfig


class SensitiveInfoConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.sensitive_info'
    label = 'sensitive_info'
    verbose_name = 'LLM02 - Sensitive Information Disclosure'
