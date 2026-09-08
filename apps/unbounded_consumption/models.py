import uuid
from django.db import models


class TokenUsageRecord(models.Model):
    """Token usage monitoring for LLM calls."""

    USAGE_TYPES = [
        ('prompt', 'Prompt Tokens'),
        ('completion', 'Completion Tokens'),
        ('total', 'Total Tokens'),
        ('embedding', 'Embedding Tokens'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(
        'organizations.Organization', on_delete=models.CASCADE, related_name='token_usage'
    )
    model = models.ForeignKey(
        'ai_assets.AIModel', on_delete=models.SET_NULL, null=True, blank=True, related_name='token_usage'
    )
    agent = models.ForeignKey(
        'ai_assets.AIAgent', on_delete=models.SET_NULL, null=True, blank=True, related_name='token_usage'
    )
    usage_type = models.CharField(max_length=50, choices=USAGE_TYPES)
    tokens_used = models.IntegerField(default=0)
    cost = models.DecimalField(max_digits=12, decimal_places=6, default=0)
    requests_count = models.IntegerField(default=1)
    avg_response_time_ms = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    endpoint = models.CharField(max_length=500, blank=True)
    is_anomalous = models.BooleanField(default=False)
    recorded_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'unbounded_consumption_token_usage'
        verbose_name = 'Token Usage Record'
        verbose_name_plural = 'Token Usage Records'
        ordering = ['-recorded_at']
        indexes = [
            models.Index(fields=['organization', '-recorded_at']),
            models.Index(fields=['model']),
            models.Index(fields=['is_anomalous']),
        ]


class CostMonitor(models.Model):
    """Aggregated cost monitoring data."""

    PERIOD_TYPES = [
        ('hourly', 'Hourly'),
        ('daily', 'Daily'),
        ('weekly', 'Weekly'),
        ('monthly', 'Monthly'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(
        'organizations.Organization', on_delete=models.CASCADE, related_name='cost_monitors'
    )
    model = models.ForeignKey(
        'ai_assets.AIModel', on_delete=models.SET_NULL, null=True, blank=True, related_name='cost_monitors'
    )
    period_type = models.CharField(max_length=50, choices=PERIOD_TYPES)
    period_start = models.DateTimeField()
    period_end = models.DateTimeField()
    total_cost = models.DecimalField(max_digits=12, decimal_places=6, default=0)
    total_tokens = models.IntegerField(default=0)
    total_requests = models.IntegerField(default=0)
    avg_cost_per_request = models.DecimalField(max_digits=10, decimal_places=6, default=0)
    budget_limit = models.DecimalField(max_digits=12, decimal_places=6, null=True, blank=True)
    budget_exceeded = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'unbounded_consumption_cost_monitor'
        verbose_name = 'Cost Monitor'
        verbose_name_plural = 'Cost Monitors'
        unique_together = ['organization', 'model', 'period_type', 'period_start']


class DoSEvent(models.Model):
    """Denial of Service event detection."""

    EVENT_TYPES = [
        ('token_exhaustion', 'Token Exhaustion'),
        ('rate_limit_breach', 'Rate Limit Breach'),
        ('concurrent_burst', 'Concurrent Request Burst'),
        ('cost_spike', 'Cost Spike'),
        ('resource_exhaustion', 'Resource Exhaustion'),
        ('api_abuse', 'API Abuse'),
        ('scraping', 'Scraping Detection'),
    ]

    SEVERITY_CHOICES = [
        ('critical', 'Critical'),
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low'),
    ]

    STATUS_CHOICES = [
        ('detected', 'Detected'),
        ('mitigated', 'Mitigated'),
        ('investigating', 'Investigating'),
        ('false_positive', 'False Positive'),
        ('resolved', 'Resolved'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(
        'organizations.Organization', on_delete=models.CASCADE, related_name='dos_events'
    )
    event_type = models.CharField(max_length=50, choices=EVENT_TYPES)
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES)
    status = models.CharField(max_length=50, choices=STATUS_CHOICES, default='detected')
    model = models.ForeignKey(
        'ai_assets.AIModel', on_delete=models.SET_NULL, null=True, blank=True, related_name='dos_events'
    )
    metrics = models.JSONField(default=dict, blank=True, help_text='Relevant metrics at time of event')
    description = models.TextField(blank=True)
    detected_at = models.DateTimeField(auto_now_add=True)
    resolved_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = 'unbounded_consumption_dos_event'
        verbose_name = 'DoS Event'
        verbose_name_plural = 'DoS Events'
        ordering = ['-detected_at']
        indexes = [
            models.Index(fields=['organization', 'severity']),
            models.Index(fields=['status']),
        ]


class RateLimitAssessment(models.Model):
    """Assessment of rate limiting configuration and effectiveness."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan = models.ForeignKey('scans.AIScan', on_delete=models.CASCADE, related_name='rate_limit_assessments')
    model = models.ForeignKey(
        'ai_assets.AIModel', on_delete=models.SET_NULL, null=True, blank=True, related_name='rate_limit_assessments'
    )
    current_rpm_limit = models.IntegerField(null=True, blank=True, help_text='Requests per minute limit')
    current_tpm_limit = models.IntegerField(null=True, blank=True, help_text='Tokens per minute limit')
    peak_rpm_observed = models.IntegerField(null=True, blank=True)
    peak_tpm_observed = models.IntegerField(null=True, blank=True)
    rate_limiting_active = models.BooleanField(default=False)
    effectiveness_score = models.DecimalField(max_digits=5, decimal_places=2, default=0)
    recommendations = models.JSONField(default=list, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'unbounded_consumption_rate_limit'
        verbose_name = 'Rate Limit Assessment'
        verbose_name_plural = 'Rate Limit Assessments'
