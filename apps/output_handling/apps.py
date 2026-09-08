from django.apps import AppConfig


class OutputHandlingConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.output_handling'
    label = 'output_handling'
    verbose_name = 'LLM05 - Improper Output Handling'
