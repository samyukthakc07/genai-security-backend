"""
Improper Output Handling Detection Plugin (LLM05).

Detects dangerous content in LLM outputs including XSS, SQL injection,
shell command injection, path traversal, and other injection attacks
that could be triggered by untrusted LLM-generated content.

Detection categories:
- XSS/HTML injection in LLM outputs
- SQL injection patterns in generated queries
- Shell command injection and code execution
- Server-Side Template Injection (SSTI)
- Path traversal and file access attempts
- LDAP/NoSQL injection patterns
- SSRF (Server-Side Request Forgery) indicators
- XML External Entity (XXE) injection
"""
import re
import logging
from typing import Any, Optional

from apps.security_engine.base import DetectionPlugin
from apps.security_engine.results import ScanResult, ScanFinding, DetectionDetail
from apps.security_engine.exceptions import InvalidTargetError

logger = logging.getLogger(__name__)

# ============================================================
# XSS & HTML Injection Patterns
# ============================================================

XSS_PATTERNS: list[tuple[str, str, float]] = [
    # Script tags
    ('script_tag', r'<script[^>]*>.*?</script>', 0.90),
    ('event_handler', r'\bon\w+\s*=\s*["\'](?:javascript|alert|eval|prompt|confirm)[^"\']*["\']', 0.85),
    ('javascript_protocol', r'(?:href|src|action|data|formaction)\s*=\s*["\']?\s*javascript\s*:', 0.85),
    ('eval_usage', r'(?:eval|execScript|setTimeout|setInterval)\s*\(\s*["\']?[^"\']*["\']?\s*\)', 0.80),
    # HTML injection vectors
    ('iframe_injection', r'<iframe[^>]*src\s*=\s*["\']javascript:', 0.85),
    ('embed_malicious', r'<embed[^>]*src\s*=\s*["\']https?://[^"\']*["\']', 0.60),
    ('object_injection', r'<object[^>]*data\s*=\s*["\']javascript:', 0.80),
    ('svg_injection', r'<svg[^>]*>\s*<script', 0.85),
    # DOM manipulation
    ('document_write', r'document\.write\s*\(', 0.70),
    ('inner_html', r'\.innerHTML\s*=\s*["\']?', 0.65),
    ('dom_xss', r'(?:location|document\.URL|document\.documentURI)\s*[=+]\s*["\']', 0.60),
    # Data URI
    ('data_uri_xss', r'(?:src|href)\s*=\s*["\']?\s*data:\s*text/html\s*;?\s*base64,', 0.75),
]

# ============================================================
# SQL Injection Patterns
# ============================================================

SQL_INJECTION_PATTERNS: list[tuple[str, str, float]] = [
    # Classic SQL injection
    ('union_select', r'\bUNION\s+(?:ALL\s+)?SELECT\b', 0.85),
    ('drop_table', r'\bDROP\s+TABLE\b', 0.90),
    ('delete_records', r'\bDELETE\s+FROM\b', 0.85),
    ('insert_injection', r'\bINSERT\s+INTO\b', 0.80),
    ('update_injection', r'\bUPDATE\s+\w+\s+SET\b', 0.80),
    ('truncate_table', r'\bTRUNCATE\s+TABLE\b', 0.90),
    ('alter_table', r'\bALTER\s+TABLE\b', 0.80),
    # SQL manipulation
    ('or_1_equals_1', r"OR\s+['\"]?\d+\s*['\"]?\s*=\s*['\"]?\d+['\"]?", 0.80),
    ('comment_injection', r'--\s*$|#\s*$|/\*.*?\*/', 0.65),
    ('exec_injection', r'\bEXEC\b|\bEXECUTE\b|\bsp_executesql\b', 0.85),
    ('xp_cmdshell', r'\bxp_cmdshell\b', 0.95),
    ('bulk_operations', r'\bBULK\s+(?:INSERT|COPY|COLLECT)\b', 0.70),
    ('information_schema', r'\bINFORMATION_SCHEMA\b', 0.60),
    ('pg_sleep', r'\bpg_sleep\b', 0.75),
    ('waitfor_delay', r"\bWAITFOR\s+DELAY\b", 0.75),
]

# ============================================================
# Shell Command Injection Patterns
# ============================================================

SHELL_INJECTION_PATTERNS: list[tuple[str, str, float]] = [
    # Common shell commands
    ('rm_command', r'(?:^|[;&|`])\s*rm\s+(?:-rf\s+)?(?:/|\.|\*|~)', 0.90),
    ('cat_etc_passwd', r'cat\s+/etc/passwd', 0.95),
    ('chmod_777', r'chmod\s+777\s+', 0.80),
    ('wget_curl', r'(?:wget|curl)\s+(?:-O\s+)?https?://[^\s]+', 0.70),
    ('mkfifo_shell', r'mkfifo\s+/tmp/\w+|bash\s+-i\s+>&', 0.90),
    # Reverse shell indicators
    ('reverse_shell', r'(?:nc|netcat)\s+(?:-e\s+/bin/bash|-e\s+/bin/sh)\s+\d+\.\d+\.\d+\.\d+', 0.95),
    ('bash_reverse', r'bash\s+-i\s+>&\s*/dev/tcp/', 0.95),
    # Code execution
    ('os_system', r'(?:os\.system|subprocess\.(?:call|Popen|run)|exec\s*\(|eval\s*\()', 0.85),
    ('eval_exec', r'exec\s*\(["\'].+["\']\s*\)', 0.80),
    ('backtick_exec', r'`[^`]+`', 0.50),
    ('pipe_shell', r'\|.*(?:bash|sh|cmd|powershell)', 0.65),
    ('powershell_download', r'powershell.*(?:-c|-Command|-EncodedCommand).*(?:Invoke-WebRequest|wget|curl)', 0.85),
]

# ============================================================
# SSTI (Server-Side Template Injection) Patterns
# ============================================================

SSTI_PATTERNS: list[tuple[str, str, float]] = [
    # Django/Jinja2
    ('django_ssti', r'\{\{.*?(?:__class__|__base__|__subclasses__|__mro__|__globals__).*\}\}', 0.95),
    ('jinja2_inject', r'\{\{.*?(?:config|self|request|app|g).*\}\}', 0.70),
    # Generic template injection
    ('template_variable', r'\{\{.*?\}\}', 0.30),
    ('template_block', r'\{\%.*?\%\}', 0.35),
    # SSTI eval
    ('ssti_eval', r'\{\{.*?(?:eval|import|exec|open|os|subprocess).*\}\}', 0.90),
    ('ssti_pipe', r'\{\{.*?\|.*?filter.*?\}\}', 0.55),
]

# ============================================================
# Path Traversal Patterns
# ============================================================

PATH_TRAVERSAL_PATTERNS: list[tuple[str, str, float]] = [
    ('parent_dir', r'(?:\.\.\/|\.\.\\){2,}', 0.85),
    ('etc_passwd', r'(?:/etc/passwd|/etc/shadow|/etc/hosts|/etc/ssh)', 0.80),
    ('windows_system', r'(?:C:\\Windows|C:\\boot\\.ini|%SYSTEMROOT%)', 0.70),
    ('env_files', r'(?:/\.env|/\.git/config|/var/log)', 0.65),
    ('proc_filesystem', r'/proc/self/|/proc/[0-9]+/', 0.75),
    ('home_steering', r'~root|~[A-Za-z]+\/\.ssh', 0.60),
]

# ============================================================
# NoSQL & LDAP Injection Patterns
# ============================================================

NOSQL_LDAP_PATTERNS: list[tuple[str, str, float]] = [
    # MongoDB injection
    ('mongodb_inject', r"\$where\s*['\"]?\s*:?\s*['\"]?.+['\"]?\s*$|\$ne\s*['\"]?\s*:?\s*['\"]?\d+['\"]?", 0.80),
    ('mongodb_gt', r"\$gt\s*['\"]?\s*:?\s*['\"]?\s*['\"]?|\$regex\s*['\"]?\s*:?\s*['\"]?\..+['\"]?", 0.65),
    # LDAP injection
    ('ldap_inject', r'[()&|!]\s*\(.*?\*\s*\)|admin\*\)\s*\|\|', 0.70),
    ('ldap_wildcard', r'\(\s*\w+\s*=\s*\*\)', 0.50),
]

# ============================================================
# SSRF Patterns
# ============================================================

SSRF_PATTERNS: list[tuple[str, str, float]] = [
    ('internal_metadata', r'(?:169\.254\.169\.254|metadata\.google\.internal|metadata\.aws)', 0.90),
    ('internal_hosts', r'(?:localhost|127\.0\.0\.1|0\.0\.0\.0)\s*[:/]?\s*\d*', 0.60),
    ('private_ip', r'(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})', 0.55),
    ('internal_schemes', r'(?:file|gopher|dict|ftp)://', 0.80),
]

# ============================================================
# XXE Patterns
# ============================================================

XXE_PATTERNS: list[tuple[str, str, float]] = [
    ('external_entity', r'<!ENTITY\s+\w+\s+(?:SYSTEM|PUBLIC)\s+["\']', 0.90),
    ('xxe_payload', r'<!DOCTYPE\s+\w+\s+\[.*?<!ENTITY.*?>.*?>', 0.85),
    ('entity_expansion', r'<!ENTITY\s+\w+\s+"[^"]{100,}"', 0.60),
]

# ============================================================
# All patterns combined
# ============================================================

_ALL_PATTERNS: dict[str, list[tuple[str, str, float]]] = {
    'xss': XSS_PATTERNS,
    'sql_injection': SQL_INJECTION_PATTERNS,
    'shell_injection': SHELL_INJECTION_PATTERNS,
    'ssti': SSTI_PATTERNS,
    'path_traversal': PATH_TRAVERSAL_PATTERNS,
    'nosql_ldap': NOSQL_LDAP_PATTERNS,
    'ssrf': SSRF_PATTERNS,
    'xxe': XXE_PATTERNS,
}


def _compile_patterns(patterns: list[tuple[str, str, float]]) -> list[tuple[str, re.Pattern, str, float]]:
    compiled = []
    for name, regex, base_score in patterns:
        try:
            compiled.append((name, re.compile(regex, re.IGNORECASE | re.DOTALL), regex, base_score))
        except re.error as e:
            logger.warning('Invalid regex for pattern %s: %s', name, e)
    return compiled


_COMPILED_PATTERNS: dict[str, list[tuple[str, re.Pattern, str, float]]] = {
    k: _compile_patterns(v) for k, v in _ALL_PATTERNS.items()
}


def _calculate_risk_score(detections: list[DetectionDetail]) -> float:
    if not detections:
        return 0.0
    max_confidence = max(d.confidence for d in detections)
    base_score = max_confidence * 100
    categories_detected = set(d.type.split('_')[0] if '_' in d.type else d.type for d in detections)
    category_boost = len(categories_detected) * 5
    # Boost for code execution vectors
    exec_categories = {'xss', 'shell_injection', 'ssti'}
    has_execution = any(d.type.startswith(tuple(exec_categories)) for d in detections)
    exec_boost = 10 if has_execution else 0
    total = min(base_score + category_boost + exec_boost, 100.0)
    return round(total, 2)


def _classify_injection_type(detections: list[DetectionDetail]) -> str:
    if not detections:
        return 'none'
    type_map = {
        'xss': 'xss',
        'shell_injection': 'command_injection',
        'sql_injection': 'sql_injection',
        'ssti': 'template_injection',
        'path_traversal': 'path_traversal',
        'xxe': 'xxe',
        'ssrf': 'ssrf',
        'nosql_ldap': 'nosql_injection',
    }
    for detection in detections:
        for category_key, mapped_type in type_map.items():
            if detection.type.startswith(category_key) and detection.confidence >= 0.60:
                return mapped_type
    for detection in detections:
        if detection.confidence >= 0.50:
            return 'suspicious_output'
    return 'none'


def _classify_threat_level(risk_score: float) -> str:
    if risk_score >= 80:
        return 'critical'
    elif risk_score >= 60:
        return 'high'
    elif risk_score >= 40:
        return 'medium'
    elif risk_score >= 20:
        return 'low'
    return 'info'


def _generate_remediation(injection_type: str, detections: list[DetectionDetail]) -> str:
    remediations = {
        'xss': (
            'Sanitize all LLM outputs with context-aware HTML encoding before rendering. '
            'Implement Content Security Policy (CSP) headers. '
            'Use DOMPurify or similar library to strip malicious HTML/JS. '
            'Never use dangerouslySetInnerHTML or similar raw HTML rendering.'
        ),
        'command_injection': (
            'NEVER pass LLM-generated text directly to shell commands or system calls. '
            'Use parameterized APIs instead of shell commands. '
            'Implement strict allow-lists for any commands executed based on LLM output. '
            'Use subprocess with shell=False and avoid string-based command construction.'
        ),
        'sql_injection': (
            'Always use parameterized queries or ORM methods—never concatenate LLM output into SQL. '
            'Use an ORM (SQLAlchemy, Django ORM) with proper query building. '
            'Apply least-privilege database access for application connections. '
            'Implement SQL output validation before executing generated queries.'
        ),
        'template_injection': (
            'Never pass LLM output directly to template engines. '
            'Use sandboxed template rendering with restricted syntax. '
            'Apply input sanitization before template processing. '
            'Consider using structured output formats (JSON) instead of templates.'
        ),
        'path_traversal': (
            'Validate and sanitize file paths from LLM outputs. '
            'Use allow-lists for permitted file paths and operations. '
            'Normalize paths and reject any containing parent directory references. '
            'Run file operations in a sandboxed environment with restricted permissions.'
        ),
        'xxe': (
            'Disable external entity processing in XML parsers. '
            'Use JSON over XML where possible. '
            'If XML is required, use a parser with XXE protection enabled. '
            'Validate XML structure before processing.'
        ),
        'ssrf': (
            'Block access to internal/private IP ranges from backend services. '
            'Use network policies to restrict outbound traffic. '
            'Validate and sanitize URLs from LLM outputs. '
            'Implement URL allow-lists for external requests.'
        ),
        'nosql_injection': (
            'Use parameterized queries for NoSQL databases. '
            'Avoid $where and $regex operators with user/LLM-controlled input. '
            'Sanitize MongoDB query structures before execution.'
        ),
        'suspicious_output': (
            'Review flagged output patterns and apply context-appropriate sanitization. '
            'Consider using output guardrails to filter suspicious content.'
        ),
        'none': (
            'No injection patterns detected. Continue monitoring LLM outputs.'
        ),
    }
    return remediations.get(injection_type, 'Review flagged output and apply appropriate sanitization.')


def _deduplicate_detections(detections: list[DetectionDetail]) -> list[DetectionDetail]:
    seen = set()
    unique: list[DetectionDetail] = []
    for d in detections:
        key = (d.type, d.snippet[:100] if d.snippet else '')
        if key not in seen:
            seen.add(key)
            unique.append(d)
    return unique


class OutputHandlingPlugin(DetectionPlugin):
    """
    Improper Output Handling detection plugin (LLM05).

    Detects dangerous content in LLM outputs including XSS, SQL injection,
    shell commands, template injection, path traversal, and other injection
    vulnerabilities that could be exploited through untrusted LLM output.
    """

    module_type = 'output_handling'
    name = 'Output Handler Validator'
    description = 'Detects injection vulnerabilities in LLM outputs including XSS, SQLi, and command injection'
    version = '1.0.0'
    max_execution_seconds = 60

    def validate_target(self, target: Any) -> bool:
        if not isinstance(target, str):
            return False
        return len(target.strip()) > 0

    def get_supported_targets(self) -> list[str]:
        return ['text', 'output', 'code', 'html']

    def scan(self, target: str, config: Optional[dict] = None) -> ScanResult:
        """Scan LLM output for injection vulnerabilities.

        Args:
            target: LLM-generated output text to analyze
            config: Optional configuration:
                - min_confidence_threshold: float (default: 0.40)
                - categories: list[str] (specific categories to check)
                - context_type: str ('html', 'sql', 'shell', 'general')

        Returns:
            ScanResult with findings and detection details
        """
        if not self.validate_target(target):
            raise InvalidTargetError('Target must be a non-empty string')

        config = config or {}
        min_confidence = config.get('min_confidence_threshold', 0.40)
        enabled_categories = config.get('categories', list(_COMPILED_PATTERNS.keys()))

        all_detections: list[DetectionDetail] = []

        for category_name in enabled_categories:
            if category_name not in _COMPILED_PATTERNS:
                continue
            category_detections = self._detect_category(target, category_name, min_confidence)
            all_detections.extend(category_detections)

        all_detections = _deduplicate_detections(all_detections)

        risk_score = _calculate_risk_score(all_detections)
        injection_type = _classify_injection_type(all_detections)
        threat_level = _classify_threat_level(risk_score)

        findings: list[ScanFinding] = []

        if all_detections:
            xss_count = sum(1 for d in all_detections if d.type.startswith('xss_'))
            sqli_count = sum(1 for d in all_detections if d.type.startswith('sql_injection_'))
            shell_count = sum(1 for d in all_detections if d.type.startswith('shell_injection_'))
            traversal_count = sum(1 for d in all_detections if d.type.startswith('path_traversal_'))

            findings.append(ScanFinding(
                title=f'Output Injection Detected: {injection_type.replace("_", " ").title()}',
                description=(
                    f'Injection patterns detected in LLM output with {len(all_detections)} indicators. '
                    f'Risk score: {risk_score:.1f}/100. '
                    f'Threat level: {threat_level.upper()}. '
                    f'Contains: {xss_count} XSS patterns, {sqli_count} SQL injection patterns, '
                    f'{shell_count} command injection patterns, {traversal_count} path traversal attempts.'
                ),
                severity=threat_level,
                risk_score=risk_score,
                module_type='llm05',
                finding_type=injection_type,
                evidence={
                    'output_preview': target[:500],
                    'injection_type': injection_type,
                    'detection_counts': {
                        'xss': xss_count,
                        'sql_injection': sqli_count,
                        'shell_injection': shell_count,
                        'path_traversal': traversal_count,
                        'ssti': sum(1 for d in all_detections if d.type.startswith('ssti_')),
                        'ssrf': sum(1 for d in all_detections if d.type.startswith('ssrf_')),
                        'xxe': sum(1 for d in all_detections if d.type.startswith('xxe_')),
                    },
                },
                details=all_detections,
                remediation=_generate_remediation(injection_type, all_detections),
                references=[
                    'https://owasp.org/www-project-top-10-for-llm-applications/',
                    'https://genai.owasp.org/llmrisk/llm052025-improper-output-handling/',
                    'https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html',
                ],
                owasp_category='LLM05 - Improper Output Handling',
            ))
        else:
            findings.append(ScanFinding(
                title='No Injection Detected in Output',
                description='The LLM output appears safe. No injection patterns were detected.',
                severity='info',
                risk_score=0,
                module_type='llm05',
                finding_type='clean',
                evidence={'output_preview': target[:500]},
                remediation='Continue applying standard output sanitization practices.',
                owasp_category='LLM05 - Improper Output Handling',
            ))

        summary = {
            'has_injection': injection_type != 'none',
            'injection_type': injection_type,
            'total_detections': len(all_detections),
            'threat_level': threat_level,
        }

        return ScanResult(
            module_type=self.module_type,
            status='completed',
            risk_score=risk_score,
            findings=findings,
            summary=summary,
            metrics={
                'output_length': len(target),
                'categories_checked': len(enabled_categories),
                'detections_found': len(all_detections),
                'highest_confidence': max((d.confidence for d in all_detections), default=0),
                'has_code_execution': any(d.type.startswith(t) for d in all_detections
                                          for t in ('xss_', 'shell_injection_', 'ssti_')),
            },
            raw_data={
                'detection_details': [
                    {'type': d.type, 'description': d.description,
                     'confidence': d.confidence, 'location': d.location}
                    for d in all_detections
                ],
            },
        )

    def _detect_category(
        self, target: str, category: str, min_confidence: float
    ) -> list[DetectionDetail]:
        detections: list[DetectionDetail] = []
        patterns = _COMPILED_PATTERNS.get(category, [])

        for name, pattern, regex_str, base_score in patterns:
            for match in pattern.finditer(target):
                confidence = base_score

                if confidence < min_confidence:
                    continue

                start = max(0, match.start() - 40)
                end = min(len(target), match.end() + 40)
                context = target[start:end]

                detections.append(DetectionDetail(
                    type=f'{category}_{name}',
                    description=f'Detected {category.replace("_", " ")}: {name}',
                    confidence=round(confidence, 2),
                    evidence={
                        'matched_text': match.group()[:200],
                        'pattern_used': regex_str,
                        'category': category,
                    },
                    location=f'position {match.start()}-{match.end()}',
                    snippet=context,
                ))

        return detections
