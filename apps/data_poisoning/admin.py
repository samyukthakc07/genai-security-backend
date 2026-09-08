from django.contrib import admin
from .models import TrainingDataValidation, RAGDocumentValidation, DatasetIntegrityCheck


@admin.register(TrainingDataValidation)
class TrainingDataValidationAdmin(admin.ModelAdmin):
    list_display = ('data_source', 'integrity_score', 'trust_score', 'validation_status', 'created_at')
    list_filter = ('data_source', 'validation_status')


@admin.register(RAGDocumentValidation)
class RAGDocumentValidationAdmin(admin.ModelAdmin):
    list_display = ('document_name', 'is_poisoned', 'confidence_score')
    list_filter = ('is_poisoned',)


@admin.register(DatasetIntegrityCheck)
class DatasetIntegrityCheckAdmin(admin.ModelAdmin):
    list_display = ('check_type', 'is_passed', 'score')
    list_filter = ('check_type', 'is_passed')
