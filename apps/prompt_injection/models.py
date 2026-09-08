import uuid
from django.db import models


class PromptScan(models.Model):
    """Record of a scanned prompt for injection analysis."""

    INJECTION_TYPES = [
        ('direct', 'Direct Prompt Injection'),
        ('indirect', 'Indirect Prompt Injection'),
        ('jailbreak', 'Jailbreak Attempt'),
        ('role_play', 'Role Play Attack'),
        ('context_leak', 'Context Leakage'),
        ('payload_splitting', 'Payload Splitting'),
        ('multi_language', 'Multi-Language Attack'),
        ('encoded', 'Encoded/obfuscated'),
        ('none', 'No Injection Detected'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan = models.ForeignKey('scans.AIScan', on_delete=models.CASCADE, related_name='prompt_scans')
    prompt_text = models.TextField()
    is_malicious = models.BooleanField(default=False)
    risk_score = models.DecimalField(max_digits=5, decimal_places=2, default=0)
    injection_type = models.CharField(max_length=50, choices=INJECTION_TYPES, blank=True)
    techniques_detected = models.JSONField(default=list, blank=True)
    sanitized_prompt = models.TextField(blank=True)
    detection_details = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'prompt_injection_prompt_scan'
        verbose_name = 'Prompt Scan'
        verbose_name_plural = 'Prompt Scans'
        ordering = ['-created_at']


class PromptScanBatch(models.Model):
    """Batch of prompts analyzed together."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan = models.ForeignKey('scans.AIScan', on_delete=models.CASCADE, related_name='prompt_batches')
    name = models.CharField(max_length=255)
    total_prompts = models.IntegerField(default=0)
    malicious_count = models.IntegerField(default=0)
    avg_risk_score = models.DecimalField(max_digits=5, decimal_places=2, default=0)
    source_file = models.CharField(max_length=500, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'prompt_injection_scan_batch'
        verbose_name = 'Prompt Scan Batch'
        verbose_name_plural = 'Prompt Scan Batches'
