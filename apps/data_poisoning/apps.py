from django.apps import AppConfig


class DataPoisoningConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.data_poisoning'
    label = 'data_poisoning'
    verbose_name = 'LLM04 - Data and Model Poisoning'
