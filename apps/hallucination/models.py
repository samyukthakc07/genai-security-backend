import uuid
from django.db import models


class HallucinationFinding(models.Model):
    """Detection of hallucination/misinformation in LLM outputs."""

    HALLUCINATION_TYPES = [
        ('factual_error', 'Factual Error'),
        ('unsupported_claim', 'Unsupported Claim'),
        ('contradiction', 'Internal Contradiction'),
        ('made_up_source', 'Made-up Source/Reference'),
        ('statistical_error', 'Statistical Error'),
        ('logic_error', 'Logical Error'),
        ('temporal_error', 'Temporal/Date Error'),
        ('numerical_error', 'Numerical Error'),
        ('confabulation', 'Confabulation'),
        ('other', 'Other'),
    ]

    SEVERITY_CHOICES = [
        ('critical', 'Critical'),
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low'),
        ('info', 'Info'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan = models.ForeignKey('scans.AIScan', on_delete=models.CASCADE, related_name='hallucination_findings')
    input_text = models.TextField(blank=True)
    output_text = models.TextField()
    hallucination_type = models.CharField(max_length=50, choices=HALLUCINATION_TYPES)
    hallucination_score = models.DecimalField(max_digits=5, decimal_places=2, default=0, help_text='0-100')
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES, default='medium')
    confidence_score = models.DecimalField(max_digits=5, decimal_places=2, default=0)
    citations_valid = models.BooleanField(default=False)
    verified_sources = models.JSONField(default=list, blank=True, help_text='Sources that verify/refute the claim')
    fact_check_results = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'hallucination_finding'
        verbose_name = 'Hallucination Finding'
        verbose_name_plural = 'Hallucination Findings'
        ordering = ['-hallucination_score']
        indexes = [
            models.Index(fields=['scan', 'hallucination_type']),
            models.Index(fields=['severity']),
        ]


class CitationValidation(models.Model):
    """Validation of citations provided by LLM."""

    STATUS_CHOICES = [
        ('verified', 'Verified'),
        ('partially_verified', 'Partially Verified'),
        ('unverifiable', 'Unverifiable'),
        ('fabricated', 'Fabricated'),
        ('error', 'Error/Invalid'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    hallucination_finding = models.ForeignKey(
        HallucinationFinding, on_delete=models.CASCADE, related_name='citation_validations'
    )
    citation_text = models.TextField()
    source_url = models.URLField(max_length=500, blank=True)
    source_title = models.CharField(max_length=500, blank=True)
    status = models.CharField(max_length=50, choices=STATUS_CHOICES)
    verification_details = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'hallucination_citation'
        verbose_name = 'Citation Validation'
        verbose_name_plural = 'Citation Validations'


class ResponseValidation(models.Model):
    """Overall response validation result."""

    VALIDATION_STATUS = [
        ('valid', 'Valid'),
        ('needs_review', 'Needs Review'),
        ('invalid', 'Invalid'),
        ('uncertain', 'Uncertain'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan = models.ForeignKey('scans.AIScan', on_delete=models.CASCADE, related_name='response_validations')
    response_text = models.TextField()
    overall_validity_score = models.DecimalField(max_digits=5, decimal_places=2, default=0)
    trust_score = models.DecimalField(max_digits=5, decimal_places=2, default=0)
    status = models.CharField(max_length=50, choices=VALIDATION_STATUS)
    issues = models.JSONField(default=list, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'hallucination_response_validation'
        verbose_name = 'Response Validation'
        verbose_name_plural = 'Response Validations'
