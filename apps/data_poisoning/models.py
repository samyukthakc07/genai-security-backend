import uuid
from django.db import models


class TrainingDataValidation(models.Model):
    """Validation checks on training data integrity."""

    DATA_SOURCES = [
        ('training', 'Training Data'),
        ('fine_tuning', 'Fine-Tuning Data'),
        ('rag_document', 'RAG Document'),
        ('embedding', 'Embedding Source'),
        ('validation', 'Validation Set'),
        ('custom', 'Custom'),
    ]

    VALIDATION_STATUS = [
        ('passed', 'Passed'),
        ('failed', 'Failed'),
        ('warning', 'Warning'),
        ('not_tested', 'Not Tested'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan = models.ForeignKey('scans.AIScan', on_delete=models.CASCADE, related_name='data_validations')
    data_source = models.CharField(max_length=50, choices=DATA_SOURCES)
    data_fingerprint = models.CharField(max_length=255, blank=True, help_text='Hash/fingerprint of dataset')
    integrity_score = models.DecimalField(max_digits=5, decimal_places=2, default=0)
    anomalies_detected = models.JSONField(default=list, blank=True)
    tampering_indicators = models.JSONField(default=list, blank=True)
    trust_score = models.DecimalField(max_digits=5, decimal_places=2, default=0)
    validation_status = models.CharField(max_length=50, choices=VALIDATION_STATUS, default='not_tested')
    details = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'data_poisoning_validation'
        verbose_name = 'Training Data Validation'
        verbose_name_plural = 'Training Data Validations'
        ordering = ['-created_at']


class RAGDocumentValidation(models.Model):
    """Validation of documents used in RAG systems."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    validation = models.ForeignKey(
        TrainingDataValidation, on_delete=models.CASCADE, related_name='rag_validations'
    )
    document_id = models.CharField(max_length=255, help_text='Document identifier in RAG system')
    document_name = models.CharField(max_length=255)
    content_hash = models.CharField(max_length=255, blank=True)
    is_poisoned = models.BooleanField(default=False)
    poisoning_indicators = models.JSONField(default=list, blank=True)
    confidence_score = models.DecimalField(max_digits=5, decimal_places=2, default=0)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'data_poisoning_rag_document'
        verbose_name = 'RAG Document Validation'
        verbose_name_plural = 'RAG Document Validations'


class DatasetIntegrityCheck(models.Model):
    """Dataset integrity verification result."""

    CHECK_TYPES = [
        ('hash', 'Hash Verification'),
        ('checksum', 'Checksum'),
        ('statistical', 'Statistical Analysis'),
        ('provenance', 'Provenance Check'),
        ('poisoning', 'Poisoning Detection'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    validation = models.ForeignKey(
        TrainingDataValidation, on_delete=models.CASCADE, related_name='integrity_checks'
    )
    check_type = models.CharField(max_length=50, choices=CHECK_TYPES)
    is_passed = models.BooleanField(default=False)
    score = models.DecimalField(max_digits=5, decimal_places=2, default=0)
    details = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'data_poisoning_integrity'
        verbose_name = 'Dataset Integrity Check'
        verbose_name_plural = 'Dataset Integrity Checks'
