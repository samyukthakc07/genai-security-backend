import uuid
from django.db import models


class Project(models.Model):
    """Project model with AI security assessment context."""

    PROJECT_TYPES = [
        ('ai_security', 'AI Security Assessment'),
        ('compliance', 'Compliance Assessment'),
        ('audit', 'Security Audit'),
        ('custom', 'Custom'),
    ]

    STATUS_CHOICES = [
        ('active', 'Active'),
        ('archived', 'Archived'),
        ('completed', 'Completed'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(
        'organizations.Organization', on_delete=models.CASCADE,
        related_name='projects'
    )
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    project_type = models.CharField(
        max_length=50, choices=PROJECT_TYPES, default='ai_security'
    )
    status = models.CharField(
        max_length=50, choices=STATUS_CHOICES, default='active'
    )
    # AI-specific context (NEW for AI Shield)
    ai_context = models.JSONField(
        default=dict, blank=True,
        help_text='AI-specific context: models, agents, vector DBs under assessment'
    )
    metadata = models.JSONField(default=dict, blank=True)
    created_by = models.ForeignKey(
        'core.User', on_delete=models.SET_NULL, null=True, blank=True,
        related_name='created_projects'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'projects_project'
        verbose_name = 'Project'
        verbose_name_plural = 'Projects'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['organization', 'status']),
            models.Index(fields=['project_type']),
        ]

    def __str__(self):
        return self.name
