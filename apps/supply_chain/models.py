import uuid
from django.db import models


class AISBOM(models.Model):
    """AI Software Bill of Materials for model supply chain."""

    FORMAT_CHOICES = [
        ('cyclonedx', 'CycloneDX'),
        ('spdx', 'SPDX'),
        ('custom', 'Custom'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(
        'organizations.Organization', on_delete=models.CASCADE, related_name='ai_sboms'
    )
    model = models.ForeignKey(
        'ai_assets.AIModel', on_delete=models.CASCADE, related_name='sboms'
    )
    sbom_version = models.CharField(max_length=50, blank=True)
    format = models.CharField(max_length=50, choices=FORMAT_CHOICES, default='cyclonedx')
    components = models.JSONField(default=list, blank=True, help_text='List of dependencies/components')
    vulnerabilities = models.JSONField(default=list, blank=True, help_text='Known vulnerabilities')
    risk_score = models.DecimalField(max_digits=5, decimal_places=2, default=0)
    sbom_data = models.JSONField(default=dict, blank=True, help_text='Full SBOM document')
    generated_at = models.DateTimeField(auto_now_add=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'supply_chain_ai_sbom'
        verbose_name = 'AI SBOM'
        verbose_name_plural = 'AI SBOMs'
        ordering = ['-generated_at']


class DependencyScan(models.Model):
    """Third-party dependency analysis."""

    RISK_LEVELS = [
        ('critical', 'Critical'),
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low'),
        ('none', 'None'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan = models.ForeignKey('scans.AIScan', on_delete=models.CASCADE, related_name='dependency_scans')
    dependency_name = models.CharField(max_length=255)
    dependency_version = models.CharField(max_length=100)
    dependency_type = models.CharField(max_length=100, help_text='e.g., python-package, npm, docker-image')
    known_vulnerabilities = models.JSONField(default=list, blank=True, help_text='CVE entries')
    risk_level = models.CharField(max_length=20, choices=RISK_LEVELS, default='none')
    latest_version = models.CharField(max_length=100, blank=True)
    is_outdated = models.BooleanField(default=False)
    license_info = models.CharField(max_length=255, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'supply_chain_dependency'
        verbose_name = 'Dependency Scan'
        verbose_name_plural = 'Dependency Scans'
        indexes = [
            models.Index(fields=['risk_level']),
            models.Index(fields=['dependency_name']),
        ]


class SDKRiskAssessment(models.Model):
    """SDK/Plugin risk assessment."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan = models.ForeignKey('scans.AIScan', on_delete=models.CASCADE, related_name='sdk_assessments')
    sdk_name = models.CharField(max_length=255)
    sdk_version = models.CharField(max_length=100)
    provider = models.CharField(max_length=255, blank=True)
    permissions_required = models.JSONField(default=list, blank=True)
    data_access = models.JSONField(default=list, blank=True, help_text='Data the SDK can access')
    risk_score = models.DecimalField(max_digits=5, decimal_places=2, default=0)
    security_score = models.DecimalField(max_digits=5, decimal_places=2, default=0)
    findings = models.JSONField(default=list, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'supply_chain_sdk_risk'
        verbose_name = 'SDK Risk Assessment'
        verbose_name_plural = 'SDK Risk Assessments'
