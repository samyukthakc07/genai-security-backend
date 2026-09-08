from django.contrib import admin
from .models import AgentPermission, ActionApproval, ToolAccessLog


@admin.register(AgentPermission)
class AgentPermissionAdmin(admin.ModelAdmin):
    list_display = ('permission_name', 'agent', 'resource_type', 'action', 'is_granted', 'risk_score')
    list_filter = ('resource_type', 'action', 'is_granted')
    search_fields = ('permission_name',)


@admin.register(ActionApproval)
class ActionApprovalAdmin(admin.ModelAdmin):
    list_display = ('agent', 'status', 'action_description', 'created_at')
    list_filter = ('status',)


@admin.register(ToolAccessLog)
class ToolAccessLogAdmin(admin.ModelAdmin):
    list_display = ('id', 'agent', 'tool_name', 'action_performed', 'status', 'risk_level', 'executed_at')
    list_filter = ('status', 'risk_level')
