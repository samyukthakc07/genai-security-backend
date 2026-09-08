from django.contrib import admin
from .models import PromptLeakageScan, PromptExposureTest, SecretInPrompt


@admin.register(PromptLeakageScan)
class PromptLeakageScanAdmin(admin.ModelAdmin):
    list_display = ('id', 'leakage_found', 'exposure_type', 'risk_score', 'prompt_hardening_score')
    list_filter = ('leakage_found', 'exposure_type')


@admin.register(PromptExposureTest)
class PromptExposureTestAdmin(admin.ModelAdmin):
    list_display = ('test_type', 'is_successful', 'confidence')
    list_filter = ('test_type', 'is_successful')


@admin.register(SecretInPrompt)
class SecretInPromptAdmin(admin.ModelAdmin):
    list_display = ('secret_type', 'location', 'risk_level')
    list_filter = ('secret_type', 'risk_level')
