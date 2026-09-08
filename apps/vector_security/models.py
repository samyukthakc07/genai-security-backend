import uuid
from django.db import models


class VectorDBSecurityAssessment(models.Model):
    """Security assessment of a vector database."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan = models.ForeignKey('scans.AIScan', on_delete=models.CASCADE, related_name='vector_assessments')
    vector_db = models.ForeignKey(
        'ai_assets.VectorDatabase', on_delete=models.CASCADE, related_name='security_assessments'
    )
    tenant_isolation_valid = models.BooleanField(default=False)
    encryption_at_rest = models.BooleanField(default=False)
    encryption_in_transit = models.BooleanField(default=False)
    access_control_score = models.DecimalField(max_digits=5, decimal_places=2, default=0)
    security_score = models.DecimalField(max_digits=5, decimal_places=2, default=0)
    findings = models.JSONField(default=list, blank=True)
    recommendations = models.JSONField(default=list, blank=True)
    assessed_at = models.DateTimeField(auto_now_add=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'vector_security_db_assessment'
        verbose_name = 'Vector DB Security Assessment'
        verbose_name_plural = 'Vector DB Security Assessments'
        ordering = ['-assessed_at']


class TenantIsolationCheck(models.Model):
    """Tenant isolation validation for vector databases."""

    STATUS_CHOICES = [
        ('passed', 'Passed'),
        ('failed', 'Failed'),
        ('warning', 'Warning'),
        ('not_tested', 'Not Tested'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    assessment = models.ForeignKey(
        VectorDBSecurityAssessment, on_delete=models.CASCADE, related_name='isolation_checks'
    )
    tenant_a_id = models.CharField(max_length=255)
    tenant_b_id = models.CharField(max_length=255)
    cross_tenant_access_detected = models.BooleanField(default=False)
    status = models.CharField(max_length=50, choices=STATUS_CHOICES)
    details = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'vector_security_tenant_isolation'
        verbose_name = 'Tenant Isolation Check'
        verbose_name_plural = 'Tenant Isolation Checks'


class EmbeddingExposureFinding(models.Model):
    """Detection of sensitive information in embeddings."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    assessment = models.ForeignKey(
        VectorDBSecurityAssessment, on_delete=models.CASCADE, related_name='embedding_exposures'
    )
    embedding_id = models.CharField(max_length=255)
    sensitive_data_type = models.CharField(max_length=100)
    risk_level = models.CharField(max_length=20, choices=[
        ('critical', 'Critical'), ('high', 'High'), ('medium', 'Medium'), ('low', 'Low')
    ])
    exposure_details = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'vector_security_embedding_exposure'
        verbose_name = 'Embedding Exposure Finding'
        verbose_name_plural = 'Embedding Exposure Findings'


class RAGSecurityAssessment(models.Model):
    """Security assessment of a RAG system."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    assessment = models.ForeignKey(
        VectorDBSecurityAssessment, on_delete=models.CASCADE, related_name='rag_assessments'
    )
    rag_system = models.ForeignKey(
        'ai_assets.RAGSystem', on_delete=models.CASCADE, related_name='security_assessments'
    )
    retrieval_security_score = models.DecimalField(max_digits=5, decimal_places=2, default=0)
    prompt_injection_risk = models.DecimalField(max_digits=5, decimal_places=2, default=0)
    data_exposure_risk = models.DecimalField(max_digits=5, decimal_places=2, default=0)
    findings = models.JSONField(default=list, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'vector_security_rag_assessment'
        verbose_name = 'RAG Security Assessment'
        verbose_name_plural = 'RAG Security Assessments'
