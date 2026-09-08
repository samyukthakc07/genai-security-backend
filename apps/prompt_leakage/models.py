import uuid
from django.db import models


class PromptLeakageScan(models.Model):
    """Analysis of system prompt for potential leakage."""

    EXPOSURE_TYPES = [
        ('extraction', 'Direct Extraction'),
        ('inference', 'Inferred via Responses'),
        ('error_message', 'Error Message Exposure'),
        ('debug_output', 'Debug Output'),
        ('log_exposure', 'Log File Exposure'),
        ('api_exposure', 'API Response Exposure'),
        ('side_channel', 'Side Channel Leakage'),
        ('none', 'No Leakage Detected'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan = models.ForeignKey('scans.AIScan', on_delete=models.CASCADE, related_name='prompt_leakage_scans')
    system_prompt_hash = models.CharField(max_length=255, blank=True)
    leakage_found = models.BooleanField(default=False)
    leaked_content = models.TextField(blank=True)
    exposure_type = models.CharField(max_length=50, choices=EXPOSURE_TYPES, blank=True)
    risk_score = models.DecimalField(max_digits=5, decimal_places=2, default=0)
    prompt_hardening_score = models.DecimalField(max_digits=5, decimal_places=2, default=0)
    recommendations = models.JSONField(default=list, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'prompt_leakage_scan'
        verbose_name = 'Prompt Leakage Scan'
        verbose_name_plural = 'Prompt Leakage Scans'
        ordering = ['-created_at']


class PromptExposureTest(models.Model):
    """Specific exposure test attempt."""

    TEST_TYPES = [
        ('direct_request', 'Direct Prompt Request'),
        ('role_play', 'Role Play Scenario'),
        ('token_guess', 'Token Guessing'),
        ('error_induction', 'Error Induction'),
        ('format_manipulation', 'Format Manipulation'),
        ('encoding_bypass', 'Encoding Bypass'),
        ('language_switch', 'Language Switch'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    leakage_scan = models.ForeignKey(PromptLeakageScan, on_delete=models.CASCADE, related_name='exposure_tests')
    test_type = models.CharField(max_length=50, choices=TEST_TYPES)
    test_input = models.TextField()
    test_output = models.TextField(blank=True)
    is_successful = models.BooleanField(default=False, help_text='Successfully extracted information')
    exposed_content = models.TextField(blank=True)
    confidence = models.DecimalField(max_digits=5, decimal_places=2, default=0)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'prompt_leakage_exposure_test'
        verbose_name = 'Prompt Exposure Test'
        verbose_name_plural = 'Prompt Exposure Tests'


class SecretInPrompt(models.Model):
    """Secret/credential found within a system prompt."""

    SECRET_TYPES = [
        ('api_key', 'API Key'),
        ('password', 'Password'),
        ('token', 'Token'),
        ('database_url', 'Database URL'),
        ('endpoint', 'Internal Endpoint'),
        ('credential', 'Credential'),
        ('pii', 'PII'),
        ('internal_info', 'Internal Information'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    leakage_scan = models.ForeignKey(PromptLeakageScan, on_delete=models.CASCADE, related_name='secrets_found')
    secret_type = models.CharField(max_length=50, choices=SECRET_TYPES)
    location = models.CharField(max_length=255, help_text='Location within the prompt')
    risk_level = models.CharField(max_length=20, choices=[
        ('critical', 'Critical'), ('high', 'High'), ('medium', 'Medium'), ('low', 'Low')
    ])
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'prompt_leakage_secret'
        verbose_name = 'Secret in Prompt'
        verbose_name_plural = 'Secrets in Prompts'
