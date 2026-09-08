from django.apps import AppConfig


class PromptLeakageConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.prompt_leakage'
    label = 'prompt_leakage'
    verbose_name = 'LLM07 - System Prompt Leakage'
