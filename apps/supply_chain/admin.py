from django.contrib import admin
from .models import AISBOM, DependencyScan, SDKRiskAssessment


@admin.register(AISBOM)
class AISBOMAdmin(admin.ModelAdmin):
    list_display = ('model', 'sbom_version', 'format', 'risk_score', 'generated_at')


@admin.register(DependencyScan)
class DependencyScanAdmin(admin.ModelAdmin):
    list_display = ('dependency_name', 'dependency_version', 'risk_level', 'is_outdated')
    list_filter = ('risk_level', 'is_outdated')
    search_fields = ('dependency_name',)


@admin.register(SDKRiskAssessment)
class SDKRiskAssessmentAdmin(admin.ModelAdmin):
    list_display = ('sdk_name', 'sdk_version', 'provider', 'risk_score', 'security_score')
    search_fields = ('sdk_name', 'provider')
