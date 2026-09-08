from django.contrib import admin
from .models import TokenUsageRecord, CostMonitor, DoSEvent, RateLimitAssessment


@admin.register(TokenUsageRecord)
class TokenUsageRecordAdmin(admin.ModelAdmin):
    list_display = ('organization', 'model', 'usage_type', 'tokens_used', 'cost', 'is_anomalous', 'recorded_at')
    list_filter = ('usage_type', 'is_anomalous', 'recorded_at')
    date_hierarchy = 'recorded_at'


@admin.register(CostMonitor)
class CostMonitorAdmin(admin.ModelAdmin):
    list_display = ('organization', 'model', 'period_type', 'total_cost', 'budget_exceeded')
    list_filter = ('period_type', 'budget_exceeded')


@admin.register(DoSEvent)
class DoSEventAdmin(admin.ModelAdmin):
    list_display = ('event_type', 'severity', 'status', 'model', 'detected_at')
    list_filter = ('event_type', 'severity', 'status')
    date_hierarchy = 'detected_at'


@admin.register(RateLimitAssessment)
class RateLimitAssessmentAdmin(admin.ModelAdmin):
    list_display = ('model', 'rate_limiting_active', 'effectiveness_score', 'current_rpm_limit')
    list_filter = ('rate_limiting_active',)
