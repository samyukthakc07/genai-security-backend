import uuid
from django.db import models


class ComplianceFramework(models.Model):
    """Security compliance framework (e.g., OWASP GenAI, NIST AI RMF, ISO 42001)."""

    FRAMEWORK_CHOICES = [
        ('owasp_genai', 'OWASP GenAI Security'),
        ('nist_ai_rmf', 'NIST AI RMF'),
        ('iso_42001', 'ISO/IEC 42001'),
        ('iso_27001', 'ISO 27001'),
        ('mitre_atlas', 'MITRE ATLAS'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=255)
    short_name = models.CharField(max_length=50, unique=True, choices=FRAMEWORK_CHOICES)
    version = models.CharField(max_length=50, blank=True)
    description = models.TextField(blank=True)
    icon_url = models.URLField(max_length=500, blank=True)
    total_controls = models.IntegerField(default=0)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'compliance_framework'
        verbose_name = 'Compliance Framework'
        verbose_name_plural = 'Compliance Frameworks'
        ordering = ['short_name']

    def __str__(self):
        return f'{self.name} ({self.short_name})'


class ComplianceControl(models.Model):
    """Individual control within a compliance framework."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    framework = models.ForeignKey(
        ComplianceFramework, on_delete=models.CASCADE, related_name='controls'
    )
    control_id = models.CharField(max_length=100, help_text='e.g., OWASP-GENAI-LLM01-01')
    title = models.CharField(max_length=500)
    description = models.TextField(blank=True)
    category = models.CharField(max_length=255, blank=True)
    risk_category = models.CharField(max_length=100, blank=True, help_text='Maps to OWASP LLM category')
    implementation_guidance = models.TextField(blank=True)
    verification_method = models.CharField(max_length=100, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'compliance_control'
        verbose_name = 'Compliance Control'
        verbose_name_plural = 'Compliance Controls'
        unique_together = ['framework', 'control_id']
        ordering = ['framework', 'control_id']

    def __str__(self):
        return f'{self.framework.short_name}: {self.control_id}'


class ComplianceMapping(models.Model):
    """Maps findings to compliance controls across frameworks."""

    MAPPING_TYPES = [
        ('automated', 'Automated'),
        ('manual', 'Manual'),
        ('ai_suggested', 'AI Suggested'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(
        'organizations.Organization', on_delete=models.CASCADE, related_name='compliance_mappings'
    )
    finding = models.ForeignKey(
        'findings.Finding', on_delete=models.CASCADE, related_name='compliance_mappings'
    )
    control = models.ForeignKey(
        ComplianceControl, on_delete=models.CASCADE, related_name='compliance_mappings'
    )
    framework = models.ForeignKey(
        ComplianceFramework, on_delete=models.CASCADE, related_name='mappings'
    )
    mapping_type = models.CharField(max_length=50, choices=MAPPING_TYPES, default='automated')
    confidence_score = models.DecimalField(max_digits=5, decimal_places=2, default=1.0)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'compliance_mapping'
        verbose_name = 'Compliance Mapping'
        verbose_name_plural = 'Compliance Mappings'
        unique_together = ['finding', 'control']

    def __str__(self):
        return f'{self.finding} → {self.control}'


class ComplianceCheckResult(models.Model):
    """Result of a compliance check against a specific control."""

    STATUS_CHOICES = [
        ('compliant', 'Compliant'),
        ('non_compliant', 'Non-Compliant'),
        ('not_applicable', 'Not Applicable'),
        ('not_tested', 'Not Tested'),
        ('partial', 'Partially Compliant'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(
        'organizations.Organization', on_delete=models.CASCADE, related_name='compliance_results'
    )
    project = models.ForeignKey(
        'projects.Project', on_delete=models.SET_NULL, null=True, blank=True, related_name='compliance_results'
    )
    scan = models.ForeignKey(
        'scans.AIScan', on_delete=models.SET_NULL, null=True, blank=True, related_name='compliance_results'
    )
    framework = models.ForeignKey(
        ComplianceFramework, on_delete=models.CASCADE, related_name='check_results'
    )
    control = models.ForeignKey(
        ComplianceControl, on_delete=models.CASCADE, related_name='check_results'
    )
    status = models.CharField(max_length=50, choices=STATUS_CHOICES, default='not_tested')
    evidence = models.JSONField(default=dict, blank=True)
    notes = models.TextField(blank=True)
    checked_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'compliance_check_result'
        verbose_name = 'Compliance Check Result'
        verbose_name_plural = 'Compliance Check Results'
        unique_together = ['scan', 'control']

    def __str__(self):
        return f'{self.control.control_id}: {self.get_status_display()}'


class ComplianceReport(models.Model):
    """Generated compliance report."""

    REPORT_TYPES = [
        ('full', 'Full Report'),
        ('summary', 'Executive Summary'),
        ('gap_analysis', 'Gap Analysis'),
        ('certification', 'Certification Readiness'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(
        'organizations.Organization', on_delete=models.CASCADE, related_name='compliance_reports'
    )
    project = models.ForeignKey(
        'projects.Project', on_delete=models.SET_NULL, null=True, blank=True, related_name='compliance_reports'
    )
    framework = models.ForeignKey(
        ComplianceFramework, on_delete=models.CASCADE, related_name='reports'
    )
    name = models.CharField(max_length=255)
    report_type = models.CharField(max_length=50, choices=REPORT_TYPES, default='full')
    overall_score = models.DecimalField(max_digits=5, decimal_places=2, null=True, blank=True)
    control_summary = models.JSONField(default=dict, blank=True)
    findings_summary = models.JSONField(default=dict, blank=True)
    file_url = models.URLField(max_length=500, blank=True)
    generated_at = models.DateTimeField(auto_now_add=True)
    created_by = models.ForeignKey(
        'core.User', on_delete=models.SET_NULL, null=True, blank=True, related_name='compliance_reports'
    )

    class Meta:
        db_table = 'compliance_report'
        verbose_name = 'Compliance Report'
        verbose_name_plural = 'Compliance Reports'
        ordering = ['-generated_at']

    def __str__(self):
        return f'{self.name} ({self.framework.short_name})'
