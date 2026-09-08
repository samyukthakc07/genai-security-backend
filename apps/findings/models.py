import uuid
from django.db import models


class Finding(models.Model):
    """Base finding model - all module findings feed into this consolidated table."""

    MODULE_TYPES = [
        ('llm01', 'LLM01 - Prompt Injection'),
        ('llm02', 'LLM02 - Sensitive Information Disclosure'),
        ('llm03', 'LLM03 - Supply Chain Security'),
        ('llm04', 'LLM04 - Data and Model Poisoning'),
        ('llm05', 'LLM05 - Improper Output Handling'),
        ('llm06', 'LLM06 - Excessive Agency'),
        ('llm07', 'LLM07 - System Prompt Leakage'),
        ('llm08', 'LLM08 - Vector and Embedding Security'),
        ('llm09', 'LLM09 - Misinformation and Hallucination'),
        ('llm10', 'LLM10 - Unbounded Consumption'),
    ]

    SEVERITY_CHOICES = [
        ('critical', 'Critical'),
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low'),
        ('info', 'Info'),
    ]

    STATUS_CHOICES = [
        ('open', 'Open'),
        ('in_progress', 'In Progress'),
        ('resolved', 'Resolved'),
        ('false_positive', 'False Positive'),
        ('accepted_risk', 'Accepted Risk'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(
        'organizations.Organization', on_delete=models.CASCADE, related_name='findings'
    )
    project = models.ForeignKey(
        'projects.Project', on_delete=models.SET_NULL, null=True, blank=True, related_name='findings'
    )
    scan = models.ForeignKey(
        'scans.AIScan', on_delete=models.SET_NULL, null=True, blank=True, related_name='findings'
    )
    module_type = models.CharField(max_length=50, choices=MODULE_TYPES)
    finding_type = models.CharField(max_length=100, help_text='Specific finding type within the module')
    title = models.CharField(max_length=500)
    description = models.TextField(blank=True)
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES)
    cvss_score = models.DecimalField(max_digits=3, decimal_places=1, null=True, blank=True)
    owasp_category = models.CharField(max_length=100, blank=True)
    status = models.CharField(max_length=50, choices=STATUS_CHOICES, default='open')
    evidence = models.JSONField(default=dict, blank=True, help_text='Module-specific evidence/context')
    remediation = models.TextField(blank=True, help_text='Remediation steps')
    references = models.JSONField(default=list, blank=True, help_text='External references/links')
    risk_score = models.DecimalField(max_digits=5, decimal_places=2, default=0)
    assigned_to = models.ForeignKey(
        'core.User', on_delete=models.SET_NULL, null=True, blank=True, related_name='assigned_findings'
    )
    discovered_at = models.DateTimeField(auto_now_add=True)
    resolved_at = models.DateTimeField(null=True, blank=True)
    resolved_by = models.ForeignKey(
        'core.User', on_delete=models.SET_NULL, null=True, blank=True, related_name='resolved_findings'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'findings_finding'
        verbose_name = 'Finding'
        verbose_name_plural = 'Findings'
        ordering = ['-discovered_at']
        indexes = [
            models.Index(fields=['organization', 'module_type', 'severity']),
            models.Index(fields=['organization', 'status']),
            models.Index(fields=['scan']),
            models.Index(fields=['risk_score']),
        ]

    def __str__(self):
        return f'[{self.get_module_type_display()}] {self.title}'


class FindingNote(models.Model):
    """Notes/comments on findings."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    finding = models.ForeignKey(Finding, on_delete=models.CASCADE, related_name='notes')
    user = models.ForeignKey('core.User', on_delete=models.CASCADE)
    content = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'findings_finding_note'
        verbose_name = 'Finding Note'
        verbose_name_plural = 'Finding Notes'
        ordering = ['-created_at']


class FindingTrend(models.Model):
    """Aggregated trend data for findings over time."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey('organizations.Organization', on_delete=models.CASCADE, related_name='finding_trends')
    date = models.DateField()
    module_type = models.CharField(max_length=50, choices=Finding.MODULE_TYPES)
    total_count = models.IntegerField(default=0)
    critical_count = models.IntegerField(default=0)
    high_count = models.IntegerField(default=0)
    medium_count = models.IntegerField(default=0)
    low_count = models.IntegerField(default=0)
    avg_risk_score = models.DecimalField(max_digits=5, decimal_places=2, default=0)

    class Meta:
        db_table = 'findings_finding_trend'
        verbose_name = 'Finding Trend'
        verbose_name_plural = 'Finding Trends'
        unique_together = ['organization', 'date', 'module_type']
        ordering = ['-date']
