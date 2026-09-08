import uuid
from django.db import models


class AIScan(models.Model):
    """Generic AI security scan - foundation for all OWASP module scans."""

    SCAN_TYPES = [
        ('prompt_injection', 'LLM01 - Prompt Injection'),
        ('sensitive_info', 'LLM02 - Sensitive Information Disclosure'),
        ('supply_chain', 'LLM03 - Supply Chain Security'),
        ('data_poisoning', 'LLM04 - Data and Model Poisoning'),
        ('output_handling', 'LLM05 - Improper Output Handling'),
        ('excessive_agency', 'LLM06 - Excessive Agency'),
        ('prompt_leakage', 'LLM07 - System Prompt Leakage'),
        ('vector_security', 'LLM08 - Vector and Embedding Security'),
        ('hallucination', 'LLM09 - Misinformation and Hallucination'),
        ('unbounded_consumption', 'LLM10 - Unbounded Consumption'),
        ('full_assessment', 'Full Security Assessment'),
    ]

    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('queued', 'Queued'),
        ('running', 'Running'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
        ('cancelled', 'Cancelled'),
    ]

    TARGET_TYPES = [
        ('model', 'AI Model'),
        ('agent', 'AI Agent'),
        ('prompt', 'Prompt Text'),
        ('rag', 'RAG System'),
        ('vector_db', 'Vector Database'),
        ('dataset', 'Dataset'),
        ('application', 'Application'),
        ('custom', 'Custom'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(
        'organizations.Organization', on_delete=models.CASCADE, related_name='scans'
    )
    project = models.ForeignKey(
        'projects.Project', on_delete=models.CASCADE, related_name='scans',
        null=True, blank=True,
    )
    name = models.CharField(max_length=255)
    scan_type = models.CharField(max_length=50, choices=SCAN_TYPES)
    status = models.CharField(max_length=50, choices=STATUS_CHOICES, default='pending')
    target_type = models.CharField(max_length=50, choices=TARGET_TYPES, blank=True)
    target_id = models.UUIDField(null=True, blank=True, help_text='Polymorphic target reference')
    config = models.JSONField(default=dict, blank=True, help_text='Scan configuration parameters')
    progress = models.DecimalField(max_digits=5, decimal_places=2, default=0)
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    error_message = models.TextField(blank=True)
    created_by = models.ForeignKey(
        'core.User', on_delete=models.CASCADE, related_name='created_scans'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'scans_ai_scan'
        verbose_name = 'AI Scan'
        verbose_name_plural = 'AI Scans'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['organization', 'status']),
            models.Index(fields=['organization', 'scan_type']),
            models.Index(fields=['project']),
        ]

    def __str__(self):
        return f'{self.name} ({self.get_scan_type_display()})'
