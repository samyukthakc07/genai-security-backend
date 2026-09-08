from django.contrib import admin
from .models import HallucinationFinding, CitationValidation, ResponseValidation


@admin.register(HallucinationFinding)
class HallucinationFindingAdmin(admin.ModelAdmin):
    list_display = ('hallucination_type', 'severity', 'hallucination_score', 'confidence_score', 'created_at')
    list_filter = ('hallucination_type', 'severity')
    date_hierarchy = 'created_at'


@admin.register(CitationValidation)
class CitationValidationAdmin(admin.ModelAdmin):
    list_display = ('citation_text', 'source_title', 'status')
    list_filter = ('status',)


@admin.register(ResponseValidation)
class ResponseValidationAdmin(admin.ModelAdmin):
    list_display = ('overall_validity_score', 'trust_score', 'status')
    list_filter = ('status',)
