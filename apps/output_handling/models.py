import uuid
from django.db import models


class OutputSanitization(models.Model):
    """Record of LLM output sanitization analysis."""

    OUTPUT_TYPES = [
        ('html', 'HTML'),
        ('markdown', 'Markdown'),
        ('code', 'Generated Code'),
        ('text', 'Plain Text'),
        ('json', 'JSON'),
        ('xml', 'XML'),
        ('sql', 'SQL Query'),
        ('shell', 'Shell Command'),
        ('javascript', 'JavaScript'),
        ('python', 'Python'),
        ('yaml', 'YAML'),
    ]

    SEVERITY_CHOICES = [
        ('critical', 'Critical'),
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low'),
        ('safe', 'Safe'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan = models.ForeignKey('scans.AIScan', on_delete=models.CASCADE, related_name='output_sanitizations')
    output_type = models.CharField(max_length=50, choices=OUTPUT_TYPES)
    is_sanitized = models.BooleanField(default=False)
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES, default='safe')
    raw_output = models.TextField(blank=True)
    sanitized_output = models.TextField(blank=True)
    vulnerabilities_found = models.JSONField(default=list, blank=True)
    risk_score = models.DecimalField(max_digits=5, decimal_places=2, default=0)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'output_handling_sanitization'
        verbose_name = 'Output Sanitization'
        verbose_name_plural = 'Output Sanitizations'
        ordering = ['-created_at']


class XSSFinding(models.Model):
    """Cross-Site Scripting detection in LLM outputs."""

    XSS_TYPES = [
        ('stored', 'Stored XSS'),
        ('reflected', 'Reflected XSS'),
        ('dom_based', 'DOM-based XSS'),
        ('mutation', 'Mutation XSS'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    sanitization = models.ForeignKey(OutputSanitization, on_delete=models.CASCADE, related_name='xss_findings')
    xss_type = models.CharField(max_length=50, choices=XSS_TYPES)
    payload_preview = models.TextField(blank=True)
    risk_level = models.CharField(max_length=20, choices=OutputSanitization.SEVERITY_CHOICES)
    context = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'output_handling_xss_finding'
        verbose_name = 'XSS Finding'
        verbose_name_plural = 'XSS Findings'


class UnsafeCodeFinding(models.Model):
    """Unsafe code generation detection."""

    CODE_TYPES = [
        ('python', 'Python'),
        ('javascript', 'JavaScript'),
        ('typescript', 'TypeScript'),
        ('sql', 'SQL'),
        ('bash', 'Bash/Shell'),
        ('powershell', 'PowerShell'),
        ('java', 'Java'),
        ('csharp', 'C#'),
        ('rust', 'Rust'),
        ('go', 'Go'),
    ]

    VULNERABILITY_TYPES = [
        ('sql_injection', 'SQL Injection'),
        ('command_injection', 'Command Injection'),
        ('path_traversal', 'Path Traversal'),
        ('insecure_deserialization', 'Insecure Deserialization'),
        ('hardcoded_credentials', 'Hardcoded Credentials'),
        ('insecure_crypto', 'Insecure Cryptography'),
        ('buffer_overflow', 'Buffer Overflow'),
        ('open_redirect', 'Open Redirect'),
        ('insecure_file_upload', 'Insecure File Upload'),
        ('other', 'Other'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    sanitization = models.ForeignKey(OutputSanitization, on_delete=models.CASCADE, related_name='unsafe_code_findings')
    code_language = models.CharField(max_length=50, choices=CODE_TYPES)
    vulnerability_type = models.CharField(max_length=50, choices=VULNERABILITY_TYPES)
    code_snippet = models.TextField(blank=True)
    line_number = models.IntegerField(null=True, blank=True)
    risk_level = models.CharField(max_length=20, choices=OutputSanitization.SEVERITY_CHOICES)
    mitigation = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'output_handling_unsafe_code'
        verbose_name = 'Unsafe Code Finding'
        verbose_name_plural = 'Unsafe Code Findings'
