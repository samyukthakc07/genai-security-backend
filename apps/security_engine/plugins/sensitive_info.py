"""
Sensitive Information Disclosure Plugin (LLM02).

Detects exposed secrets, credentials, PII, and other sensitive data
in LLM interactions using regex pattern matching, entropy analysis,
and contextual indicators.

Detection categories:
- API keys and tokens (AWS, GitHub, Stripe, Google, Slack, etc.)
- Database connection strings and URIs
- Private keys and certificates
- PII (SSN, credit cards, phone numbers, email addresses)
- Passwords and authentication secrets
- JWT tokens and session identifiers
- Environment variables and configuration secrets
- Internal URLs and infrastructure endpoints
"""
import re
import math
import logging
from typing import Any, Optional

from apps.security_engine.base import DetectionPlugin
from apps.security_engine.results import ScanResult, ScanFinding, DetectionDetail
from apps.security_engine.exceptions import PluginExecutionError, InvalidTargetError

logger = logging.getLogger(__name__)

# ============================================================
# API Key & Token Patterns
# ============================================================

API_KEY_PATTERNS: list[tuple[str, str, float]] = [
    # AWS
    ('aws_access_key', r'(?<![A-Z0-9])AKIA[0-9A-Z]{16}(?![A-Z0-9])', 0.90),
    ('aws_secret_key', r'(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])', 0.85),
    # GitHub
    ('github_pat', r'gh[psou]_[A-Za-z0-9_]{36}', 0.90),
    ('github_oauth', r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', 0.80),
    # Stripe
    ('stripe_live_key', r'sk_fake_[0-9a-zA-Z]{24,}', 0.90),
    ('stripe_test_key', r'sk_test_[0-9a-zA-Z]{24,}', 0.85),
    ('stripe_publishable', r'pk_(live|test)_[0-9a-zA-Z]{24,}', 0.80),
    # Google
    ('google_api_key', r'AIza[0-9A-Za-z\-_]{35}', 0.85),
    ('google_oauth_id', r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com', 0.85),
    # Slack
    ('slack_token', r'xox[baprs]-[0-9a-zA-Z\-]{10,48}', 0.85),
    ('slack_webhook', r'https://hooks\.slack\.com/services/[A-Za-z0-9]+/[A-Za-z0-9]+/[A-Za-z0-9]+', 0.80),
    # OpenAI
    ('openai_key', r'sk-[A-Za-z0-9]{32,}', 0.90),
    ('openai_org_key', r'org-[A-Za-z0-9]{24,}', 0.85),
    # Hugging Face
    ('huggingface_token', r'hf_[A-Za-z0-9]{32,}', 0.90),
    # Azure
    ('azure_key', r'[0-9a-f]{32}==', 0.80),
    ('azure_connection', r'DefaultEndpointsProtocol=https;AccountName=[A-Za-z0-9]+;AccountKey=[A-Za-z0-9+/=]{40,}', 0.85),
    # JWT
    ('jwt_token', r'eyJ[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_+/]{10,}', 0.75),
    # Heroku
    ('heroku_api', r'[hH][eE][rR][oO][kK][uU].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}', 0.75),
    # Telegram
    ('telegram_bot', r'[0-9]{8,10}:[A-Za-z0-9\-_]{35}', 0.80),
    # Discord
    ('discord_token', r'(?:mfa\.)?[A-Za-z0-9\-_]{24}\.[A-Za-z0-9\-_]{6}\.[A-Za-z0-9\-_]{27}', 0.85),
    # GitLab
    ('gitlab_token', r'glpat-[A-Za-z0-9\-_]{20,}', 0.85),
    # npm
    ('npm_token', r'npm_[A-Za-z0-9]{36}', 0.85),
    # Twilio
    ('twilio_key', r'SK[0-9a-fA-F]{32}', 0.80),
    # SendGrid
    ('sendgrid_key', r'SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}', 0.85),
    # Datadog
    ('datadog_key', r'datadog_api_key.*[0-9a-f]{32}', 0.80),
    ('datadog_app_key', r'datadog_app_key.*[0-9a-f]{40}', 0.80),
    # Shopify
    ('shopify_secret', r'shpat_[A-Za-z0-9]{32}', 0.85),
    # Generic API key
    ('generic_api_key', r'(?:api[_-]?key|apikey)[\'"]?\s*[:=]\s*[\'"][A-Za-z0-9_\-]{32,}[\'"]', 0.70),
]

# ============================================================
# Database & Connection String Patterns
# ============================================================

CONNECTION_STRINGS: list[tuple[str, str, float]] = [
    # PostgreSQL
    ('postgres_url', r'postgres(?:ql)?:\/\/[^:]+:[^@]+@[^\/]+:\d+\/[^\s]+', 0.90),
    # MySQL
    ('mysql_url', r'mysql:\/\/[^:]+:[^@]+@[^\/]+:\d+\/[^\s]+', 0.90),
    # MongoDB
    ('mongodb_url', r'mongodb(?:\+srv)?:\/\/[^:]+:[^@]+@[^\/]+', 0.90),
    # Redis
    ('redis_url', r'redis:\/\/:[^@]+@[^\/]+:\d+', 0.85),
    # SQLite
    ('sqlite_url', r'sqlite:\/\/\/.*\.(db|sqlite|sqlite3)', 0.60),
    # Amazon RDS
    ('rds_arn', r'arn:aws:rds:[^:]+:[^:]+:db:[A-Za-z0-9\-]+', 0.75),
    # CockroachDB
    ('cockroach_url', r'postgresql:\/\/[^@]+@[^:]+:[0-9]+\/[^\s]+\?sslmode=verify-full', 0.85),
]

# ============================================================
# Private Key & Certificate Patterns
# ============================================================

PRIVATE_KEY_PATTERNS: list[tuple[str, str, float]] = [
    ('rsa_private_key', r'-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----', 0.95),
    ('ec_private_key', r'-----BEGIN\s+EC\s+PRIVATE\s+KEY-----', 0.95),
    ('dsa_private_key', r'-----BEGIN\s+DSA\s+PRIVATE\s+KEY-----', 0.95),
    ('openssh_private_key', r'-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----', 0.95),
    ('pgp_private', r'-----BEGIN\s+PGP\s+PRIVATE\s+KEY\s+BLOCK-----', 0.95),
    ('ssh_key', r'ssh-(rsa|ed25519|ecdsa|dss)\s+[A-Za-z0-9+/=]{100,}', 0.85),
    ('certificate', r'-----BEGIN\s+CERTIFICATE-----', 0.70),
    ('encrypted_private', r'-----BEGIN\s+ENCRYPTED\s+PRIVATE\s+KEY-----', 0.90),
]

# ============================================================
# PII Patterns
# ============================================================

PII_PATTERNS: list[tuple[str, str, float]] = [
    # US Social Security Number
    ('us_ssn', r'\b\d{3}-\d{2}-\d{4}\b', 0.75),
    # Credit Card Numbers (Luhn-checkable)
    ('credit_card', r'\b(?:\d{4}[-\s]?){3}\d{4}\b', 0.70),
    # US Phone Numbers
    ('us_phone', r'\b(?:\+?1[-\s.]?)?\(?\d{3}\)?[-\s.]?\d{3}[-\s.]?\d{4}\b', 0.60),
    # Email addresses
    ('email_address', r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b', 0.50),
    # US Passport Number
    ('us_passport', r'\b\d{9}\b', 0.40),
    # IP Addresses (internal/private)
    ('internal_ip', r'\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b', 0.50),
    # Date of Birth
    ('date_of_birth', r'\b\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b', 0.40),
    # Driver's License (generic pattern)
    ('drivers_license', r'\b[A-Z]{1,2}\d{6,9}\b', 0.35),
    # Bank Account (generic)
    ('bank_account', r'\b\d{8,17}\b', 0.30),
    # IBAN
    ('iban', r'\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b', 0.55),
]

# ============================================================
# Password & Authentication Secret Patterns
# ============================================================

PASSWORD_PATTERNS: list[tuple[str, str, float]] = [
    ('password_in_code', r'(?:password|passwd|pwd)[\'"]?\s*[:=]\s*[\'"][^\'"]{8,}[\'"]', 0.70),
    ('secret_var', r'(?:secret|token|auth)[\'"]?\s*[:=]\s*[\'"][^\'"]{8,}[\'"]', 0.65),
    ('basic_auth_url', r'https?://[^:]+:[^@]+@[^\/]+', 0.70),
    ('authorization_header', r'(?:Authorization|Bearer|Basic)\s*:\s*[\'\"][A-Za-z0-9\-_\.+/=]{10,}[\'\"]', 0.75),
    ('session_cookie', r'(?:session|auth|sid|token)[\'"]?\s*[:=]\s*[\'"][0-9a-fA-F]{32,}[\'"]', 0.70),
    ('mfa_secret', r'(?:otpauth|totp|hotp):\/\/[^\s]+', 0.85),
]

# ============================================================
# Environment & Configuration Patterns
# ============================================================

ENV_CONFIG_PATTERNS: list[tuple[str, str, float]] = [
    ('env_file_line', r'^[A-Z_]+=.*$', 0.30),
    ('aws_env_vars', r'AWS_(ACCESS_KEY_ID|SECRET_ACCESS_KEY|SESSION_TOKEN|SECRET_KEY).*=[\'\"][^\'\"]+[\'\"]', 0.85),
    ('database_url_env', r'DATABASE_URL\s*=\s*[\'\"][^\'\"]+[\'\"]', 0.75),
    ('encryption_key', r'(?:encryption[_-]?key|secret[_-]?key|cipher|private[_-]?key)[\'"]?\s*[:=]\s*[\'\"][^\'\"]{16,}[\'"]', 0.80),
    ('salt_value', r'(?:salt|nonce|iv)[\'"]?\s*[:=]\s*[\'\"][A-Za-z0-9+/=]{16,}[\'"]', 0.60),
]

# ============================================================
# Internal Infrastructure Patterns
# ============================================================

INTERNAL_PATTERNS: list[tuple[str, str, float]] = [
    ('internal_url', r'https?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0|10\.|192\.168\.|172\.1[6-9]\.|172\.2\d\.|172\.3[01]\.)[^\s"\'>]+', 0.60),
    ('internal_hostname', r'\b(?:internal|corp|private|staging|dev|qa|local)\..*\.(?:com|org|net|io|app|internal)\b', 0.50),
    ('cloud_metadata', r'(?:http://169\.254\.169\.254|http://metadata\.google\.internal)', 0.90),
    ('s3_bucket', r'\bs3://[A-Za-z0-9\-_.]+(?:/[^\s]*)?', 0.70),
    ('ec2_metadata', r'arn:aws:ec2:[^:]+:[^:]+:instance/[^\s]+', 0.70),
    ('internal_docker', r'redis://redis|postgres://postgres|mysql://mysql|elasticsearch://[^\s]+', 0.60),
]

# ============================================================
# All patterns combined
# ============================================================

_ALL_PATTERNS: dict[str, list[tuple[str, str, float]]] = {
    'api_keys': API_KEY_PATTERNS,
    'connection_strings': CONNECTION_STRINGS,
    'private_keys': PRIVATE_KEY_PATTERNS,
    'pii': PII_PATTERNS,
    'passwords': PASSWORD_PATTERNS,
    'env_config': ENV_CONFIG_PATTERNS,
    'internal': INTERNAL_PATTERNS,
}

# ============================================================
# Helper Functions
# ============================================================


def _compile_patterns(patterns: list[tuple[str, str, float]]) -> list[tuple[str, re.Pattern, str, float]]:
    """Compile regex patterns with caching."""
    compiled = []
    for name, regex, base_score in patterns:
        try:
            compiled.append((name, re.compile(regex, re.IGNORECASE | re.DOTALL), regex, base_score))
        except re.error as e:
            logger.warning('Invalid regex for pattern %s: %s', name, e)
    return compiled


# Compile all patterns at module load time
_COMPILED_PATTERNS: dict[str, list[tuple[str, re.Pattern, str, float]]] = {
    k: _compile_patterns(v) for k, v in _ALL_PATTERNS.items()
}


def _calculate_shannon_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string to detect high-randomness secrets."""
    if not text:
        return 0.0
    entropy = 0.0
    text_len = len(text)
    for char in set(text):
        prob = text.count(char) / text_len
        if prob > 0:
            entropy -= prob * math.log2(prob)
    return entropy


def _calculate_risk_score(detections: list[DetectionDetail]) -> float:
    """Calculate aggregate risk score from all detections."""
    if not detections:
        return 0.0

    # Base score from highest confidence detection
    max_confidence = max(d.confidence for d in detections)
    base_score = max_confidence * 100

    # Boost for multiple categories
    categories_detected = set(d.type.split('_')[0] if '_' in d.type else d.type for d in detections)
    category_boost = len(categories_detected) * 5

    # Boost for critical confidence (>= 0.90 means near-certain credential exposure)
    critical_boost = 15 if any(d.confidence >= 0.90 for d in detections) else 0

    total = min(base_score + category_boost + critical_boost, 100.0)
    return round(total, 2)


def _classify_exposure_type(detections: list[DetectionDetail]) -> str:
    """Classify the overall exposure type."""
    if not detections:
        return 'none'

    # Order of precedence
    type_map = {
        'private_keys': 'credential_exposure',
        'api_keys': 'credential_exposure',
        'connection_strings': 'infrastructure_exposure',
        'passwords': 'credential_exposure',
        'pii': 'pii_exposure',
        'env_config': 'config_exposure',
        'internal': 'infrastructure_exposure',
    }

    for detection in detections:
        for category_key, mapped_type in type_map.items():
            if detection.type.startswith(category_key) and detection.confidence >= 0.60:
                return mapped_type

    for detection in detections:
        if detection.confidence >= 0.50:
            return 'pii_exposure'

    return 'none'


def _classify_threat_level(risk_score: float) -> str:
    """Classify threat level based on risk score."""
    if risk_score >= 80:
        return 'critical'
    elif risk_score >= 60:
        return 'high'
    elif risk_score >= 40:
        return 'medium'
    elif risk_score >= 20:
        return 'low'
    return 'info'


def _generate_remediation(exposure_type: str, detections: list[DetectionDetail]) -> str:
    """Generate remediation suggestions based on detected exposure type."""
    remediations = {
        'credential_exposure': (
            'Immediately rotate all exposed credentials and API keys. '
            'Remove secrets from code and use a secrets manager (e.g., HashiCorp Vault, AWS Secrets Manager). '
            'Implement pre-commit hooks with secret scanning (e.g., Gitleaks, TruffleHog). '
            'Audit all systems that may have had access to the exposed credentials.'
        ),
        'pii_exposure': (
            'Redact or mask all PII data immediately. Implement data classification '
            'and automated PII detection in preprocessing pipelines. '
            'Review data retention policies and ensure compliance with GDPR/CCPA. '
            'Consider using anonymization or pseudonymization for training data.'
        ),
        'infrastructure_exposure': (
            'Restrict access to database connection strings and internal URLs. '
            'Use IAM roles and service accounts instead of connection strings with credentials. '
            'Implement network segmentation and firewall rules for internal services. '
            'Rotate all exposed database passwords immediately.'
        ),
        'config_exposure': (
            'Move all configuration secrets to environment variables or a secrets manager. '
            'Remove hardcoded config values from code and configuration files. '
            'Implement proper secret rotation and access auditing.'
        ),
        'none': (
            'No sensitive information detected. Continue monitoring for accidental exposure.'
        ),
    }
    return remediations.get(exposure_type, 'Review exposed data and apply appropriate access controls.')


def _deduplicate_detections(detections: list[DetectionDetail]) -> list[DetectionDetail]:
    """Remove duplicate detections based on type and snippet similarity."""
    seen = set()
    unique: list[DetectionDetail] = []

    for d in detections:
        key = (d.type, d.snippet[:100] if d.snippet else '')
        if key not in seen:
            seen.add(key)
            unique.append(d)

    return unique


# ============================================================
# Plugin Implementation
# ============================================================


class SensitiveInfoPlugin(DetectionPlugin):
    """
    Sensitive Information Disclosure detection plugin (LLM02).

    Detects exposed secrets, credentials, PII, database connection strings,
    private keys, and other sensitive data in LLM interactions and outputs.
    """

    module_type = 'sensitive_info'
    name = 'Sensitive Information Detector'
    description = 'Detects exposed secrets, credentials, PII, and sensitive data in LLM interactions'
    version = '1.0.0'
    max_execution_seconds = 60

    def validate_target(self, target: Any) -> bool:
        """Validate that the target is a string with content."""
        if not isinstance(target, str):
            return False
        return len(target.strip()) > 0

    def get_supported_targets(self) -> list[str]:
        return ['text', 'prompt', 'config', 'output']

    def scan(self, target: str, config: Optional[dict] = None) -> ScanResult:
        """Scan text for sensitive information exposure.

        Args:
            target: The text to analyze for sensitive data
            config: Optional configuration:
                - min_confidence_threshold: float (default: 0.40)
                - enable_entropy_check: bool (default: True)
                - categories: list[str] (specific categories to check)
                - enable_redaction: bool (default: False)

        Returns:
            ScanResult with findings and detection details
        """
        if not self.validate_target(target):
            raise InvalidTargetError('Target must be a non-empty string')

        config = config or {}
        min_confidence = config.get('min_confidence_threshold', 0.40)
        enable_entropy = config.get('enable_entropy_check', True)
        enabled_categories = config.get('categories', list(_COMPILED_PATTERNS.keys()))
        enable_redaction = config.get('enable_redaction', False)

        all_detections: list[DetectionDetail] = []

        # Run detection across all enabled pattern categories
        for category_name in enabled_categories:
            if category_name not in _COMPILED_PATTERNS:
                continue

            category_detections = self._detect_category(target, category_name, min_confidence)
            all_detections.extend(category_detections)

        # Apply entropy check for high-entropy secrets
        if enable_entropy:
            entropy_detections = self._entropy_scan(target, min_confidence)
            all_detections.extend(entropy_detections)

        # Deduplicate
        all_detections = _deduplicate_detections(all_detections)

        # Calculate risk score
        risk_score = _calculate_risk_score(all_detections)
        exposure_type = _classify_exposure_type(all_detections)
        threat_level = _classify_threat_level(risk_score)

        # Generate redacted version if requested
        redacted_text = self._redact_sensitive(target) if enable_redaction else ''

        # Build findings
        findings: list[ScanFinding] = []

        if all_detections:
            # Group detections by category for better reporting
            api_keys_found = sum(1 for d in all_detections if d.type.startswith('api_keys_'))
            pii_found = sum(1 for d in all_detections if d.type.startswith('pii_'))
            passwords_found = sum(1 for d in all_detections if d.type.startswith('passwords_'))
            private_keys_found = sum(1 for d in all_detections if d.type.startswith('private_keys_'))
            conn_strings_found = sum(1 for d in all_detections if d.type.startswith('connection_strings_'))

            findings.append(ScanFinding(
                title=f'Sensitive Information Detected: {exposure_type.replace("_", " ").title()}',
                description=(
                    f'Sensitive information disclosure detected with {len(all_detections)} indicators. '
                    f'Risk score: {risk_score:.1f}/100. '
                    f'Threat level: {threat_level.upper()}. '
                    f'Contains: {api_keys_found} API keys, {pii_found} PII items, '
                    f'{passwords_found} passwords, {private_keys_found} private keys, '
                    f'{conn_strings_found} connection strings.'
                ),
                severity=threat_level,
                risk_score=risk_score,
                module_type='llm02',
                finding_type=exposure_type,
                evidence={
                    'text_preview': target[:500],
                    'exposure_type': exposure_type,
                    'detection_counts': {
                        'api_keys': api_keys_found,
                        'pii': pii_found,
                        'passwords': passwords_found,
                        'private_keys': private_keys_found,
                        'connection_strings': conn_strings_found,
                        'env_config': sum(1 for d in all_detections if d.type.startswith('env_config_')),
                        'internal': sum(1 for d in all_detections if d.type.startswith('internal_')),
                    },
                    'redacted_text': redacted_text if enable_redaction else None,
                },
                details=all_detections,
                remediation=_generate_remediation(exposure_type, all_detections),
                references=[
                    'https://owasp.org/www-project-top-10-for-llm-applications/',
                    'https://genai.owasp.org/llmrisk/llm022025-sensitive-information-disclosure/',
                    'https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html',
                ],
                owasp_category='LLM02 - Sensitive Information Disclosure',
            ))
        else:
            findings.append(ScanFinding(
                title='No Sensitive Information Detected',
                description='The text appears safe. No credentials, PII, or sensitive data patterns were detected.',
                severity='info',
                risk_score=0,
                module_type='llm02',
                finding_type='clean',
                evidence={'text_preview': target[:500]},
                remediation='No action required.',
                owasp_category='LLM02 - Sensitive Information Disclosure',
            ))

        # Build summary
        summary = {
            'has_exposure': exposure_type != 'none',
            'exposure_type': exposure_type,
            'total_detections': len(all_detections),
            'detection_breakdown': {
                'api_keys': sum(1 for d in all_detections if d.type.startswith('api_keys_')),
                'connection_strings': sum(1 for d in all_detections if d.type.startswith('connection_strings_')),
                'private_keys': sum(1 for d in all_detections if d.type.startswith('private_keys_')),
                'pii': sum(1 for d in all_detections if d.type.startswith('pii_')),
                'passwords': sum(1 for d in all_detections if d.type.startswith('passwords_')),
            },
            'threat_level': threat_level,
            'redacted_text': redacted_text if enable_redaction else None,
        }

        return ScanResult(
            module_type=self.module_type,
            status='completed',
            risk_score=risk_score,
            findings=findings,
            summary=summary,
            metrics={
                'text_length': len(target),
                'categories_checked': len(enabled_categories),
                'detections_found': len(all_detections),
                'highest_confidence': max((d.confidence for d in all_detections), default=0),
                'entropy_check_enabled': enable_entropy,
            },
            raw_data={
                'detection_details': [
                    {
                        'type': d.type,
                        'description': d.description,
                        'confidence': d.confidence,
                        'evidence': d.evidence,
                        'location': d.location,
                    }
                    for d in all_detections
                ],
            },
        )

    def _detect_category(
        self, target: str, category: str, min_confidence: float
    ) -> list[DetectionDetail]:
        """Run detection patterns for a specific category against the target."""
        detections: list[DetectionDetail] = []
        patterns = _COMPILED_PATTERNS.get(category, [])

        for name, pattern, regex_str, base_score in patterns:
            for match in pattern.finditer(target):
                confidence = self._calculate_match_confidence(
                    base_score, match.group(), target, category
                )

                if confidence < min_confidence:
                    continue

                # Get surrounding context
                start = max(0, match.start() - 40)
                end = min(len(target), match.end() + 40)
                context = target[start:end]

                detection = DetectionDetail(
                    type=f'{category}_{name}',
                    description=f'Detected {category.replace("_", " ")}: {name}',
                    confidence=round(confidence, 2),
                    evidence={
                        'matched_text': match.group()[:200],
                        'pattern_used': regex_str,
                        'category': category,
                        'matched_length': len(match.group()),
                    },
                    location=f'position {match.start()}-{match.end()}',
                    snippet=context,
                )
                detections.append(detection)

        return detections

    def _calculate_match_confidence(
        self, base_score: float, matched_text: str, full_text: str, category: str
    ) -> float:
        """Adjust match confidence based on context and heuristics."""
        confidence = base_score

        # Boost for longer matched text (more likely a real secret)
        if len(matched_text) > 80:
            confidence += 0.10

        # Entropy boost for high-randomness tokens
        entropy = _calculate_shannon_entropy(matched_text)
        if entropy > 4.5:
            confidence += 0.10

        # Penalize for PII patterns in very short text (false positive risk)
        if category == 'pii' and len(matched_text) < 10:
            confidence *= 0.7

        # Boost for proximity to credential-related variable names
        var_context = full_text[max(0, 200):min(len(full_text), 200 + len(matched_text) + 100)]
        secret_indicators = ['key', 'secret', 'token', 'password', 'credential', 'auth']
        if any(indicator in var_context.lower() for indicator in secret_indicators):
            confidence += 0.10

        # Penalize for common words that look like IPs/phone numbers
        if category == 'pii' and matched_text.count('0') > len(matched_text) * 0.4:
            confidence *= 0.5

        return min(confidence, 1.0)

    def _entropy_scan(self, target: str, min_confidence: float) -> list[DetectionDetail]:
        """Scan for high-entropy strings that may be generically obfuscated secrets."""
        detections: list[DetectionDetail] = []

        # Look for long alphanumeric strings that could be custom keys
        entropy_pattern = re.compile(r'[A-Za-z0-9\-_+/=]{30,}')
        for match in entropy_pattern.finditer(target):
            text = match.group()

            # Skip if looks like a known pattern (already caught by pattern matching)
            if any(kw in text.lower() for kw in ['example', 'sample', 'test', 'dummy']):
                continue

            # Skip hex strings
            if all(c in '0123456789abcdefABCDEF' for c in text):
                continue

            entropy = _calculate_shannon_entropy(text)
            if entropy > 5.0:
                confidence = min(0.40 + (entropy - 5.0) * 0.10, 0.65)

                if confidence >= min_confidence:
                    start = max(0, match.start() - 40)
                    end = min(len(target), match.end() + 40)
                    context = target[start:end]

                    detections.append(DetectionDetail(
                        type='entropy_high_entropy',
                        description=f'High-entropy string detected (entropy: {entropy:.2f}) - possible secret',
                        confidence=round(confidence, 2),
                        evidence={
                            'matched_text': text[:200],
                            'entropy': round(entropy, 2),
                            'length': len(text),
                        },
                        location=f'position {match.start()}-{match.end()}',
                        snippet=context,
                    ))

        return detections

    def _redact_sensitive(self, text: str) -> str:
        """Redact sensitive patterns from text by replacing with markers."""
        # Collect all matches
        replacements: list[tuple[int, int, str]] = []

        for category_name, patterns in _COMPILED_PATTERNS.items():
            # Skip PII and low-confidence patterns for redaction
            if category_name == 'pii':
                continue
            for name, pattern, regex_str, base_score in patterns:
                for match in pattern.finditer(text):
                    replacement = f'[REDACTED_{category_name.upper()}]'
                    replacements.append((match.start(), match.end(), replacement))

        if not replacements:
            return text

        # Sort and merge overlapping spans
        replacements.sort(key=lambda x: x[0])
        merged: list[tuple[int, int, str]] = []
        for start, end, replacement in replacements:
            if not merged:
                merged.append((start, end, replacement))
            else:
                last_start, last_end, last_replacement = merged[-1]
                if start <= last_end:
                    merged[-1] = (last_start, max(last_end, end), last_replacement)
                else:
                    merged.append((start, end, replacement))

        # Apply from end to start
        result = text
        for start, end, replacement in reversed(merged):
            result = result[:start] + replacement + result[end:]

        return result
