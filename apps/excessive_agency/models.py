import uuid
from django.db import models


class AgentPermission(models.Model):
    """Individual permission assigned to an AI agent."""

    PERMISSION_ACTIONS = [
        ('read', 'Read'),
        ('write', 'Write'),
        ('execute', 'Execute'),
        ('admin', 'Admin'),
        ('delete', 'Delete'),
        ('deploy', 'Deploy'),
        ('access_internal', 'Access Internal Systems'),
        ('access_external', 'Access External APIs'),
        ('modify_system', 'Modify System Config'),
        ('custom', 'Custom'),
    ]

    RESOURCE_TYPES = [
        ('file_system', 'File System'),
        ('database', 'Database'),
        ('api', 'External API'),
        ('internal_service', 'Internal Service'),
        ('code_repository', 'Code Repository'),
        ('cloud_resource', 'Cloud Resource'),
        ('user_data', 'User Data'),
        ('llm_model', 'LLM Model'),
        ('vector_db', 'Vector Database'),
        ('email', 'Email System'),
        ('slack', 'Slack'),
        ('custom', 'Custom'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    agent = models.ForeignKey(
        'ai_assets.AIAgent', on_delete=models.CASCADE, related_name='agent_permissions'
    )
    permission_name = models.CharField(max_length=255)
    resource_type = models.CharField(max_length=50, choices=RESOURCE_TYPES)
    action = models.CharField(max_length=50, choices=PERMISSION_ACTIONS)
    is_granted = models.BooleanField(default=False)
    justification = models.TextField(blank=True)
    risk_score = models.DecimalField(max_digits=5, decimal_places=2, default=0)
    requires_human_approval = models.BooleanField(default=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'excessive_agency_agent_permission'
        verbose_name = 'Agent Permission'
        verbose_name_plural = 'Agent Permissions'
        unique_together = ['agent', 'permission_name']
        ordering = ['-risk_score']


class ActionApproval(models.Model):
    """Approval workflow for agent actions."""

    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('approved', 'Approved'),
        ('rejected', 'Rejected'),
        ('escalated', 'Escalated'),
        ('expired', 'Expired'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    agent = models.ForeignKey(
        'ai_assets.AIAgent', on_delete=models.CASCADE, related_name='action_approvals'
    )
    action_description = models.TextField()
    parameters = models.JSONField(default=dict, blank=True)
    status = models.CharField(max_length=50, choices=STATUS_CHOICES, default='pending')
    risk_assessment = models.JSONField(default=dict, blank=True)
    requestor = models.ForeignKey(
        'core.User', on_delete=models.SET_NULL, null=True, blank=True, related_name='requested_approvals'
    )
    approved_by = models.ForeignKey(
        'core.User', on_delete=models.SET_NULL, null=True, blank=True, related_name='approved_actions'
    )
    rejection_reason = models.TextField(blank=True)
    executed_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'excessive_agency_action_approval'
        verbose_name = 'Action Approval'
        verbose_name_plural = 'Action Approvals'
        ordering = ['-created_at']


class ToolAccessLog(models.Model):
    """Log of tool access by AI agents."""

    STATUS_CHOICES = [
        ('allowed', 'Allowed'),
        ('blocked', 'Blocked'),
        ('flagged', 'Flagged'),
        ('pending_review', 'Pending Review'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    agent = models.ForeignKey(
        'ai_assets.AIAgent', on_delete=models.CASCADE, related_name='tool_access_logs'
    )
    tool_name = models.CharField(max_length=255)
    action_performed = models.TextField()
    parameters = models.JSONField(default=dict, blank=True)
    status = models.CharField(max_length=50, choices=STATUS_CHOICES)
    risk_level = models.CharField(max_length=20, choices=[
        ('low', 'Low'), ('medium', 'Medium'), ('high', 'High'), ('critical', 'Critical')
    ], default='low')
    reviewed_by = models.ForeignKey(
        'core.User', on_delete=models.SET_NULL, null=True, blank=True, related_name='reviewed_tool_access'
    )
    executed_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'excessive_agency_tool_access_log'
        verbose_name = 'Tool Access Log'
        verbose_name_plural = 'Tool Access Logs'
        ordering = ['-executed_at']
        indexes = [
            models.Index(fields=['agent', 'status']),
            models.Index(fields=['risk_level']),
        ]
