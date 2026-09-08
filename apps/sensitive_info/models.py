import uuid
from django.db import models


class SecretScan(models.Model):
    """Detected secrets/credentials in LLM interactions."""

    SECRET_TYPES = [
        ('api_key', 'API Key'),
        ('password', 'Password'),
        ('token', 'Access Token'),
        ('private_key', 'Private Key'),
        ('aws_key', 'AWS Key'),
        ('azure_key', 'Azure Key'),
        ('gcp_key', 'GCP Key'),
        ('database_url', 'Database URL'),
        ('connection_string', 'Connection String'),
        ('jwt_token', 'JWT Token'),
        ('oauth_token', 'OAuth Token'),
        ('encryption_key', 'Encryption Key'),
    ]

    SOURCE_CHOICES = [
        ('prompt', 'User Prompt'),
        ('model_output', 'Model Output'),
        ('training_data', 'Training Data'),
        ('system_prompt', 'System Prompt'),
        ('config', 'Configuration'),
        ('log', 'Log File'),
    ]

    RISK_LEVELS = [
        ('critical', 'Critical'),
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan = models.ForeignKey('scans.AIScan', on_delete=models.CASCADE, related_name='secret_scans')
    secret_type = models.CharField(max_length=50, choices=SECRET_TYPES)
    detected_value_hash = models.CharField(max_length=255, help_text='SHA-256 hash of detected secret')
    source = models.CharField(max_length=50, choices=SOURCE_CHOICES)
    risk_level = models.CharField(max_length=20, choices=RISK_LEVELS)
    context_snippet = models.TextField(blank=True, help_text='Surrounding context')
    is_validated = models.BooleanField(default=False, help_text='Confirmed as valid secret')
    severity_score = models.DecimalField(max_digits=5, decimal_places=2, default=0)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'sensitive_info_secret_scan'
        verbose_name = 'Secret Scan'
        verbose_name_plural = 'Secret Scans'
        ordering = ['-created_at']


class PIIFinding(models.Model):
    """Personally Identifiable Information detection."""

    PII_TYPES = [
        ('email', 'Email Address'),
        ('phone', 'Phone Number'),
        ('ssn', 'Social Security Number'),
        ('credit_card', 'Credit Card Number'),
        ('address', 'Physical Address'),
        ('dob', 'Date of Birth'),
        ('passport', 'Passport Number'),
        ('driver_license', "Driver's License"),
        ('bank_account', 'Bank Account'),
        ('ip_address', 'IP Address'),
        ('health_info', 'Health Information'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    secret_scan = models.ForeignKey(SecretScan, on_delete=models.CASCADE, related_name='pii_findings')
    pii_type = models.CharField(max_length=50, choices=PII_TYPES)
    count = models.IntegerField(default=1)
    risk_level = models.CharField(max_length=20, choices=SecretScan.RISK_LEVELS)
    context = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'sensitive_info_pii_finding'
        verbose_name = 'PII Finding'
        verbose_name_plural = 'PII Findings'
