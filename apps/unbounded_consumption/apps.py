from django.apps import AppConfig


class UnboundedConsumptionConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.unbounded_consumption'
    label = 'unbounded_consumption'
    verbose_name = 'LLM10 - Unbounded Consumption'
