from django.contrib import admin
from .models import Finding, FindingNote, FindingTrend


@admin.register(Finding)
class FindingAdmin(admin.ModelAdmin):
    list_display = ('title', 'module_type', 'severity', 'status', 'risk_score', 'discovered_at')
    list_filter = ('module_type', 'severity', 'status', 'discovered_at')
    search_fields = ('title', 'description')
    readonly_fields = ('discovered_at', 'created_at', 'updated_at')
    date_hierarchy = 'discovered_at'


@admin.register(FindingNote)
class FindingNoteAdmin(admin.ModelAdmin):
    list_display = ('finding', 'user', 'created_at')
    list_filter = ('created_at',)


@admin.register(FindingTrend)
class FindingTrendAdmin(admin.ModelAdmin):
    list_display = ('date', 'organization', 'module_type', 'total_count', 'critical_count', 'avg_risk_score')
    list_filter = ('module_type', 'date')
