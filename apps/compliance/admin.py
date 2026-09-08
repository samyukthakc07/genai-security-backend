from django.contrib import admin
from .models import (
    ComplianceFramework, ComplianceControl, ComplianceMapping,
    ComplianceCheckResult, ComplianceReport
)


@admin.register(ComplianceFramework)
class ComplianceFrameworkAdmin(admin.ModelAdmin):
    list_display = ('name', 'short_name', 'version', 'is_active', 'total_controls')
    list_filter = ('is_active',)


@admin.register(ComplianceControl)
class ComplianceControlAdmin(admin.ModelAdmin):
    list_display = ('control_id', 'framework', 'title', 'category')
    list_filter = ('framework', 'category')
    search_fields = ('control_id', 'title')


@admin.register(ComplianceMapping)
class ComplianceMappingAdmin(admin.ModelAdmin):
    list_display = ('finding', 'control', 'framework', 'mapping_type', 'confidence_score')
    list_filter = ('mapping_type', 'framework')


@admin.register(ComplianceCheckResult)
class ComplianceCheckResultAdmin(admin.ModelAdmin):
    list_display = ('control', 'status', 'scan', 'checked_at')
    list_filter = ('status', 'checked_at')


@admin.register(ComplianceReport)
class ComplianceReportAdmin(admin.ModelAdmin):
    list_display = ('name', 'framework', 'report_type', 'overall_score', 'generated_at')
    list_filter = ('report_type', 'framework')
