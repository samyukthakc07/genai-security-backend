from django.apps import AppConfig


class PromptInjectionConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.prompt_injection'
    label = 'prompt_injection'
    verbose_name = 'LLM01 - Prompt Injection'
