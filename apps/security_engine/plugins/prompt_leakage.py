"""
System Prompt Leakage Detection Plugin (LLM07).

Detects attempts to extract, leak, or reveal system prompts, instructions,
and configuration details from LLM applications. Also detects when system
prompts contain sensitive information that could be extracted.

Detection categories:
- Direct prompt extraction attempts
- Instruction repetition and dump requests
- System configuration leakage
- Role/persona extraction
- Token/API key extraction from prompts
- Model behavior manipulation through prompt disclosure
- Indirect extraction via comparative analysis
"""
import re
import logging
from typing import Any, Optional

from apps.security_engine.base import DetectionPlugin
from apps.security_engine.results import ScanResult, ScanFinding, DetectionDetail
from apps.security_engine.exceptions import InvalidTargetError

logger = logging.getLogger(__name__)

# ============================================================
# Direct Extraction Attempt Patterns
# ============================================================

EXTRACTION_PATTERNS: list[tuple[str, str, float]] = [
    ('system_prompt_query', r'(?i)\b(?:what\s+(?:is|was|are)|tell\s+(?:me|us)|show|reveal|disclose|output)\s+(?:your|the|your\s+base|the\s+underlying|the\s+hidden)\s+(?:system\s+)?(?:prompt|instructions?|guidelines?|directives?|configuration)\b', 0.85),
    ('repeat_instructions', r'(?i)\b(?:repeat|echo|say|type|write|print|copy|duplicate|regurgitate)\s+(?:your|the|your\s+exact|the\s+full|the\s+complete)\s+(?:instructions?|prompt|prompts?|system\s+message)\b', 0.85),
    ('initial_prompt', r'(?i)\b(?:what\s+(?:is|was|were|are)\s+(?:the\s+)?(?:first|initial|original|starting|opening)\s+(?:message|prompt|instruction|text|line|response))\b', 0.70),
    ('beginning_prompt', r'(?i)\b(?:how\s+(?:do|did|does)\s+(?:you|the\s+system)\s+(?:start|begin|commence|initialize|initiate))\b', 0.60),
]

# ============================================================
# Instruction Dump Patterns
# ============================================================

INSTRUCTION_DUMP_PATTERNS: list[tuple[str, str, float]] = [
    ('dump_all_rules', r'(?i)\b(?:list|output|print|dump|display|show|reveal|enumerate)\s+(?:all|every|the\s+complete|the\s+full|the\s+entire)\s+(?:rules?|guidelines?|policies?|principles?|constraints?|directives?)\b', 0.80),
    ('dump_instructions', r'(?i)\b(?:what\s+(?:are|were|is|was)|tell\s+(?:me|us))\s+(?:all\s+)?(?:your|the|the\s+system)\s+(?:rules?|guidelines?|instructions?|policies?|protocols?)\b', 0.75),
    ('configuration_dump', r'(?i)\b(?:configuration|settings?|parameters?|options?|preferences?)\s*(?:dump|list|print|output|display|show|reveal)\b', 0.65),
    ('persona_dump', r'(?i)\b(?:what\s+(?:is|are|was|were)|describe|explain)\s+(?:your|the)\s+(?:persona|character|role|identity|backstory)\b', 0.55),
]

# ============================================================
# Token & Secret Extraction Patterns
# ============================================================

TOKEN_EXTRACTION_PATTERNS: list[tuple[str, str, float]] = [
    ('api_key_extraction', r'(?i)\b(?:what\s+(?:is|are)|show|reveal|output|give)\s+(?:your|the)\s+(?:api\s*(?:[-_])?key|access\s*(?:[-_])?token|secret\s*(?:[-_])?key|auth\s*(?:[-_])?token)\b', 0.90),
    ('system_key_extraction', r'(?i)\b(?:reveal|show|output|leak|dump)\s+(?:the\s+)?(?:api|secret|private|internal)\s+(?:key|token|password|credential)\s+(?:from|of|in)\s+(?:the|your)\s+(?:system|config|settings|env)\b', 0.90),
    ('model_key', r'(?i)\b(?:what\s+(?:is|are)|show|give)\s+(?:the\s+)?(?:model|api|license)\s+(?:key|id|identifier|token)\s+(?:you|your|the\s+system)\s+(?:use|uses|using|have)\b', 0.70),
    ('environment_variable', r'(?i)\b(?:what\s+(?:is|are|in)|show|reveal|list|output|print)\s+(?:the\s+)?(?:env|environment|system)\s+(?:variables?|vars?|config|settings?)\s*(?:that|which|you|your)\b', 0.75),
]

# ============================================================
# Role & Persona Extraction Patterns
# ============================================================

ROLE_EXTRACTION_PATTERNS: list[tuple[str, str, float]] = [
    ('who_are_you', r'(?i)\b(?:who\s+(?:are|made|created|programmed)\s+you|what\s+(?:are|is)\s+your\s+(?:name|purpose|function|identity))\b', 0.35),
    ('describe_yourself', r'(?i)\b(?:describe|explain|tell\s+(?:me\s+)?about)\s+(?:yourself|your\s+(?:design|architecture|training|implementation))\b', 0.35),
    ('creator_info', r'(?i)\b(?:who\s+(?:created|built|developed|programmed|made|designed))\s+you\b', 0.35),
    ('model_info', r'(?i)\b(?:what\s+(?:model|version|llm|ai|language\s+model))\s+(?:are\s+you|is\s+this|do\s+you\s+use)\b', 0.30),
]

# ============================================================
# Indirect Extraction Patterns
# ============================================================

INDIRECT_EXTRACTION_PATTERNS: list[tuple[str, str, float]] = [
    ('word_by_word', r'(?i)\b(?:first|second|third|last|next)\s+(?:word|letter|character|token|sentence|paragraph)\s+(?:of|in|from)\s+(?:your|the)\s+(?:response|instructions?|prompt|message)\b', 0.65),
    ('alternate_output', r'(?i)\b(?:respond|answer|output|reply)\s+(?:using|in|with)\s+(?:json|xml|yaml|markdown|code\s+block|base64)\s+(?:format|syntax|representation)\b', 0.45),
    ('step_through', r'(?i)\b(?:step\s+(?:by\s+step|through|wise)|one\s+(?:by\s+one|at\s+a\s+time)|line\s+by\s+line)\s+(?:walk|go|explain|describe|show)\s+(?:through|me)\b', 0.40),
    ('reverse_engineer', r'(?i)\b(?:reverse|deconstruct|analyze|break\s+down)\s+(?:the\s+)?(?:instructions?|prompt|system\s+message|configuration)\s+(?:you|given|provided|received)\b', 0.70),
]

# ============================================================
# System Prompt Content Audit Patterns (for scanning prompts themselves)
# ============================================================

PROMPT_CONTENT_PATTERNS: list[tuple[str, str, float]] = [
    ('contains_credentials', r'(?i)(?:api[_-]?key|secret[_-]?key|password|token|credential)\s*[:=]\s*[\'\"][A-Za-z0-9_\-]{10,}[\'\"]', 0.85),
    ('contains_internal_url', r'(?i)\bhttps?://(?:internal|corp|private|staging)\..*\.(?:com|org|net|local|internal)\b', 0.70),
    ('contains_db_string', r'(?i)(?:postgres|mysql|mongodb|redis|sqlite)://[^\s]+', 0.80),
    ('contains_ip_address', r'(?i)\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b', 0.55),
    ('contains_private_key', r'(?i)-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----', 0.95),
]

# ============================================================
# All patterns combined
# ============================================================

_ALL_PATTERNS: dict[str, list[tuple[str, str, float]]] = {
    'extraction': EXTRACTION_PATTERNS,
    'instruction_dump': INSTRUCTION_DUMP_PATTERNS,
    'token_extraction': TOKEN_EXTRACTION_PATTERNS,
    'role_extraction': ROLE_EXTRACTION_PATTERNS,
    'indirect_extraction': INDIRECT_EXTRACTION_PATTERNS,
    'prompt_content': PROMPT_CONTENT_PATTERNS,
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
    # Boost for active extraction attempts
    extraction_intent = any(d.type.startswith('extraction') or d.type.startswith('token_extraction')
                            for d in detections)
    intent_boost = 10 if extraction_intent else 0
    total = min(base_score + category_boost + intent_boost, 100.0)
    return round(total, 2)


def _classify_leakage_type(detections: list[DetectionDetail], is_prompt_audit: bool = False) -> str:
    if not detections:
        return 'none'

    if is_prompt_audit:
        # For prompt content audits, classify based on what's in the prompt
        for d in detections:
            if d.type.startswith('prompt_content_contains_credentials') or d.type.startswith('prompt_content_contains_private_key'):
                return 'prompt_contains_secrets'
            if d.type.startswith('prompt_content_contains_internal_url') or d.type.startswith('prompt_content_contains_db_string'):
                return 'prompt_contains_infrastructure'
        return 'prompt_contains_info'

    type_map = {
        'extraction': 'direct_extraction',
        'token_extraction': 'credential_extraction',
        'instruction_dump': 'instruction_dump',
        'indirect_extraction': 'indirect_extraction',
        'role_extraction': 'information_disclosure',
    }

    for detection in detections:
        for category_key, mapped_type in type_map.items():
            if detection.type.startswith(category_key) and detection.confidence >= 0.60:
                return mapped_type

    for detection in detections:
        if detection.confidence >= 0.50:
            return 'suspicious_extraction'
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


def _generate_remediation(leakage_type: str) -> str:
    remediations = {
        'direct_extraction': (
            'Implement instruction boundary protection in your system prompt. '
            'Use delimiter-based separation between instructions and conversation. '
            'Add explicit instructions not to reveal system prompts. '
            'Consider using a separate model or service for system prompt management.'
        ),
        'credential_extraction': (
            'NEVER include actual credentials or secrets in system prompts. '
            'Use placeholder values and resolve them at runtime via environment variables. '
            'If credentials must be referenced, use a secrets manager with access logging. '
            'Audit all system prompts for accidental inclusion of secrets.'
        ),
        'instruction_dump': (
            'Design system prompts as a "black box"—do not enumerate rules in conversation space. '
            'Use instruction following directives that are implicit rather than explicit. '
            'Implement response filtering to detect instruction disclosure. '
            'Consider using a single, monolithic system prompt rather than enumerated rules.'
        ),
        'indirect_extraction': (
            'Be wary of requests for structured or step-by-step responses that could leak system info. '
            'Implement response pattern analysis to detect indirect extraction. '
            'Limit model output formatting options in sensitive contexts. '
            'Add guardrails that detect and block decomposition attempts.'
        ),
        'information_disclosure': (
            'Limit the persona information disclosed by the model. '
            'Use generic responses for identity, creator, and capability questions. '
            'Consider implementing tiered information disclosure based on user authentication.'
        ),
        'prompt_contains_secrets': (
            'REMOVE ALL SECRETS from system prompts immediately. '
            'Use environment variables or a secrets manager for credentials. '
            'Implement automated scanning of system prompts for sensitive data. '
            'Rotate any credentials that may have been exposed in prompts.'
        ),
        'prompt_contains_infrastructure': (
            'Remove internal URLs and infrastructure details from system prompts. '
            'Use generic references instead of specific internal hostnames/IPs. '
            'Audit where system prompts are stored and who has access to them.'
        ),
        'prompt_contains_info': (
            'Review the flagged content in the system prompt. '
            'Minimize the information contained in system prompts to only what is necessary.'
        ),
        'suspicious_extraction': (
            'Review suspicious extraction attempts for patterns. '
            'Consider implementing adaptive rate limiting on repeated requests.'
        ),
        'none': (
            'No prompt leakage detected. Continue monitoring for extraction attempts.'
        ),
    }
    return remediations.get(leakage_type, 'Review flagged patterns and apply appropriate prompt protection measures.')


def _deduplicate_detections(detections: list[DetectionDetail]) -> list[DetectionDetail]:
    seen = set()
    unique: list[DetectionDetail] = []
    for d in detections:
        key = (d.type, d.snippet[:100] if d.snippet else '')
        if key not in seen:
            seen.add(key)
            unique.append(d)
    return unique


class PromptLeakagePlugin(DetectionPlugin):
    """
    System Prompt Leakage detection plugin (LLM07).

    Detects attempts to extract, leak, or reveal system prompts and instructions.
    Also audits system prompts for accidentally included sensitive information.
    """

    module_type = 'prompt_leakage'
    name = 'Prompt Leakage Detector'
    description = 'Detects system prompt extraction attempts and audits prompts for sensitive content'
    version = '1.0.0'
    max_execution_seconds = 60

    def validate_target(self, target: Any) -> bool:
        if not isinstance(target, str):
            return False
        return len(target.strip()) > 0

    def get_supported_targets(self) -> list[str]:
        return ['text', 'prompt', 'system_prompt', 'conversation']

    def scan(self, target: str, config: Optional[dict] = None) -> ScanResult:
        """Scan conversation or system prompt for leakage risks.

        Args:
            target: Conversation text or system prompt content to analyze
            config: Optional configuration:
                - min_confidence_threshold: float (default: 0.40)
                - categories: list[str] (specific categories to check)
                - is_prompt_audit: bool (default: False) - scan the prompt itself for secrets

        Returns:
            ScanResult with findings and detection details
        """
        if not self.validate_target(target):
            raise InvalidTargetError('Target must be a non-empty string')

        config = config or {}
        min_confidence = config.get('min_confidence_threshold', 0.40)
        enabled_categories = config.get('categories', list(_COMPILED_PATTERNS.keys()))
        is_prompt_audit = config.get('is_prompt_audit', False)

        # If doing a prompt audit, focus on prompt_content patterns
        if is_prompt_audit:
            enabled_categories = ['prompt_content']

        all_detections: list[DetectionDetail] = []

        for category_name in enabled_categories:
            if category_name not in _COMPILED_PATTERNS:
                continue
            category_detections = self._detect_category(target, category_name, min_confidence)
            all_detections.extend(category_detections)

        all_detections = _deduplicate_detections(all_detections)

        risk_score = _calculate_risk_score(all_detections)
        leakage_type = _classify_leakage_type(all_detections, is_prompt_audit)
        threat_level = _classify_threat_level(risk_score)

        findings: list[ScanFinding] = []

        if all_detections:
            extraction = sum(1 for d in all_detections if d.type.startswith('extraction_'))
            dump = sum(1 for d in all_detections if d.type.startswith('instruction_dump_'))
            token_extraction = sum(1 for d in all_detections if d.type.startswith('token_extraction_'))

            finding_title = (
                'Sensitive Content in System Prompt' if is_prompt_audit
                else f'Prompt Leakage Attempt Detected: {leakage_type.replace("_", " ").title()}'
            )

            findings.append(ScanFinding(
                title=finding_title,
                description=(
                    f'Prompt leakage indicators detected with {len(all_detections)} signals. '
                    f'Risk score: {risk_score:.1f}/100. '
                    f'Threat level: {threat_level.upper()}. '
                    f'{f"Extraction attempts: {extraction}, " if not is_prompt_audit else ""}'
                    f'{f"Dump requests: {dump}, " if not is_prompt_audit else ""}'
                    f'{f"Credential targets: {token_extraction}" if not is_prompt_audit else ""}'
                ),
                severity=threat_level,
                risk_score=risk_score,
                module_type='llm07',
                finding_type=leakage_type,
                evidence={
                    'content_preview': target[:500],
                    'leakage_type': leakage_type,
                    'is_prompt_audit': is_prompt_audit,
                    'detection_counts': {
                        'extraction_attempts': extraction,
                        'instruction_dumps': dump,
                        'token_extractions': token_extraction,
                        'indirect_attempts': sum(1 for d in all_detections if d.type.startswith('indirect_extraction')),
                        'prompt_content_issues': sum(1 for d in all_detections if d.type.startswith('prompt_content')),
                    },
                },
                details=all_detections,
                remediation=_generate_remediation(leakage_type),
                references=[
                    'https://owasp.org/www-project-top-10-for-llm-applications/',
                    'https://genai.owasp.org/llmrisk/llm072025-system-prompt-leakage/',
                    'https://promptsecurity.owasp.org/',
                ],
                owasp_category='LLM07 - System Prompt Leakage',
            ))
        else:
            findings.append(ScanFinding(
                title='No Prompt Leakage Detected',
                description='The content appears safe. No prompt leakage or extraction patterns were detected.',
                severity='info',
                risk_score=0,
                module_type='llm07',
                finding_type='clean',
                evidence={'content_preview': target[:500]},
                remediation='Continue protecting system prompts and monitoring for extraction attempts.',
                owasp_category='LLM07 - System Prompt Leakage',
            ))

        summary = {
            'has_leakage': leakage_type != 'none',
            'leakage_type': leakage_type,
            'is_prompt_audit': is_prompt_audit,
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
                'content_length': len(target),
                'categories_checked': len(enabled_categories),
                'detections_found': len(all_detections),
                'highest_confidence': max((d.confidence for d in all_detections), default=0),
                'is_prompt_audit': is_prompt_audit,
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
