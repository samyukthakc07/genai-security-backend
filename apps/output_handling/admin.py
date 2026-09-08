from django.contrib import admin
from .models import OutputSanitization, XSSFinding, UnsafeCodeFinding


@admin.register(OutputSanitization)
class OutputSanitizationAdmin(admin.ModelAdmin):
    list_display = ('output_type', 'is_sanitized', 'severity', 'risk_score', 'created_at')
    list_filter = ('output_type', 'severity')


@admin.register(XSSFinding)
class XSSFindingAdmin(admin.ModelAdmin):
    list_display = ('xss_type', 'risk_level')
    list_filter = ('xss_type', 'risk_level')


@admin.register(UnsafeCodeFinding)
class UnsafeCodeFindingAdmin(admin.ModelAdmin):
    list_display = ('code_language', 'vulnerability_type', 'risk_level', 'line_number')
    list_filter = ('code_language', 'vulnerability_type', 'risk_level')
