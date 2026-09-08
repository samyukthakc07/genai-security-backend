from django.contrib import admin
from .models import PromptScan, PromptScanBatch


@admin.register(PromptScan)
class PromptScanAdmin(admin.ModelAdmin):
    list_display = ('id', 'is_malicious', 'risk_score', 'injection_type', 'created_at')
    list_filter = ('is_malicious', 'injection_type')
    search_fields = ('prompt_text',)


@admin.register(PromptScanBatch)
class PromptScanBatchAdmin(admin.ModelAdmin):
    list_display = ('name', 'total_prompts', 'malicious_count', 'avg_risk_score')
