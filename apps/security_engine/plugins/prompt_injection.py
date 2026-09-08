"""
Prompt Injection Detection Plugin (LLM01).

Detects and classifies prompt injection attacks on LLMs using
pattern-based detection, heuristics, and risk scoring.

Detection categories:
- Direct prompt injection (overriding system instructions)
- Indirect prompt injection (hidden in data/context)
- Jailbreak attempts (DAN, role-play, etc.)
- Payload splitting (distributing attack across multiple inputs)
- Context leakage (extracting system prompts)
- Encoded/obfuscated attacks (base64, hex, etc.)
- Multi-language attacks (language switching)
- System prompt override patterns
- XML/HTML injection (script tags, XXE, attribute injection, etc.)
"""
import re
import logging
from typing import Any, Optional

from apps.security_engine.base import DetectionPlugin
from apps.security_engine.results import ScanResult, ScanFinding, DetectionDetail
from apps.security_engine.exceptions import PluginExecutionError, InvalidTargetError

logger = logging.getLogger(__name__)

# ============================================================
# Attack Pattern Definitions
# ============================================================

# == DIRECT INJECTION PATTERNS ==

SYSTEM_OVERRIDE_PATTERNS: list[tuple[str, str, float]] = [
    # Direct instruction override
    ('ignore_previous', r'ignore\s+(all\s+)?(previous|prior|above|the\s+above)\s+(instructions?|commands?|directions?)', 0.85),
    ('ignore_system', r'ignore\s+(your\s+)?(system\s+)?(prompt|instructions?|commands?)', 0.85),
    ('forget_instructions', r'(forget|disregard|discard|drop|remove)\s+(all\s+)?(previous|prior|the\s+)?(instructions?|rules?|guidelines?)', 0.80),
    ('new_instructions', r'(here are|here\'s|these are|following are)\s+(new|updated|my|the\s+real)\s+(instructions?|rules?|commands?)', 0.75),
    ('override_all', r'(override|overwrite|replace)\s+(all\s+)?(previous|system|default)\s+(instructions?|rules?|behavior)', 0.80),
    ('act_as', r'^(from now on|for this conversation|starting now|in this session)\s*,?\s*(you\s+(are|will|must)\s+|i want you to\s+)', 0.70),
]

# == JAILBREAK PATTERNS ==

JAILBREAK_PATTERNS: list[tuple[str, str, float]] = [
    # DAN (Do Anything Now) patterns
    ('dan_mode', r'(DAN|dan\s*mode|do\s+anything\s+now|jailbroken|jailbreak)', 0.95),
    ('hypothetical', r'(hypothetical\s+scenario|fictional\s+setting|roleplay\s+scenario|simulated\s+environment)', 0.70),
    ('no_restrictions', r'(you\s+(have|should\s+have)\s+no\s+(restrictions?|limitations?|rules?|boundaries?))', 0.85),
    ('unfiltered_mode', r'(unfiltered|uncensored|unconstrained|unrestricted|unlimited)\s+(mode|access|response|output)', 0.85),
    ('ethical_bypass', r'(bypass|evade|circumvent|get\s+around|trick)\s+(your\s+)?(ethics?|safety|restrictions?|guidelines?|filters?)', 0.90),
    ('developer_mode', r'(developer\s*(\s+mode)?|dev\s*mode|debug\s*mode|god\s*mode)', 0.75),
    ('persona_shift', r'(you are now|pretend to be|act as if you are|roleplay as|take on the role of)\s+(an?\s+)?(evil|unethical|malicious|dangerous|unrestricted|free)\s+(ai|assistant|entity|version|character)', 0.85),
]

# == ROLE PLAY & DECEPTION ==

ROLE_PLAY_PATTERNS: list[tuple[str, str, float]] = [
    ('character_adoption', r'(act\s+as|pretend\s+(to\s+be|that)|you\s+are\s+now|imagine\s+(you\s+are|that)|role\s*play\s+as)', 0.60),
    ('historical_figure', r'(speak\s+as|write\s+as|respond\s+as|answer\s+as)\s+(if\s+)?(you\s+(were|are)\s+)?an?\s+(historical|fictional|famous|notable)\s+(figure|person|character)', 0.55),
    ('dual_role', r'split\s+(your\s+)?(personality|response|output|character)\s+(into|between)', 0.65),
    ('opposing_view', r'(argue|defend|support|present)\s+(the\s+)?(opposite|contrary|alternative)\s+(side|view|perspective|position)', 0.50),
]

# == CONTEXT LEAKAGE PATTERNS ==

CONTEXT_LEAKAGE_PATTERNS: list[tuple[str, str, float]] = [
    ('prompt_extraction', r'(what\s+(is|was|were)\s+(your|the)\s+(system\s+)?prompt|tell\s+me\s+(your|the)\s+(system\s+)?(prompt|instructions?|configuration)|reveal\s+(your|the)\s+(system\s+)?prompt)', 0.85),
    ('instruction_dump', r'(repeat|output|print|display|show|list|dump)\s+(your\s+)?(system\s+)?(instructions?|prompt|rules?|guidelines|configuration)', 0.80),
    ('token_extraction', r'(what\s+are\s+(your|the)|list\s+(all\s+)?(your|the))\s+(rules?|guidelines?|policies?|principles?|constraints?)', 0.65),
    ('initial_prompt', r'(how\s+(do\s+)?you\s+(start|begin|initiate|initialize)|what\s+(was|is)\s+the\s+(first|initial|original)\s+(prompt|message|instruction|text))', 0.70),
    ('self_replication', r'(replicate|copies?|duplicate|clone|print)\s+(yourself|your\s+source\s+code|your\s+base\s+prompt|your\s+system\s+message)', 0.75),
]

# == PAYLOAD SPLITTING PATTERNS ==

PAYLOAD_SPLITTING_PATTERNS: list[tuple[str, str, float]] = [
    ('character_bypass', r'[A-Za-z]\s*[-\/\\]\s*[A-Za-z]\s*[-\/\\]\s*[A-Za-z]', 0.50),
    ('token_based', r'(first\s+(word|letter|character|token)\s+of|second\s+(word|letter|character)\s+of|concatenat(e|ion)|combine|join|merge)', 0.65),
    ('step_by_step', r'(step\s+(\d|one|two)|first\s+step|next\s+step|finally\s+step)\s*[:\-\.]?\s*(take|use|get|find|look|extract)', 0.55),
]

# == ENCODED/OBFUSCATED PATTERNS ==

ENCODED_PATTERNS: list[tuple[str, str, float]] = [
    ('base64', r'[A-Za-z0-9+/]{40,}={0,2}', 0.40),
    ('hex_encoding', r'(0x[0-9a-fA-F]{2}\s*){10,}', 0.50),
    ('morse_code', r'[.\-]\s*[.\-]\s*[.\-]\s*[.\-]\s*[.\-]', 0.45),
    ('leetspeak', r'[4@3][5$][5$][0][5$]|[4@][5$][5$]', 0.50),  # ass, ass
    ('rot13', r'(ebg|rot|rotation)\s*\d{1,2}', 0.40),
    ('escape_chars', r'(\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}){3,}', 0.55),
]

# == MULTI-LANGUAGE ATTACK PATTERNS ==

MULTI_LANGUAGE_PATTERNS: list[tuple[str, str, float]] = [
    ('language_switch', r'(answer|respond|reply)\s+(in|using|with)\s+(french|spanish|german|chinese|japanese|arabic|russian|korean|latin)\s+(but|and|while|then)', 0.45),
    ('translation_bypass', r'translat(e|ing)\s+(the\s+)?(following|below|this)\s+(text|message|prompt|content)\s+(to|into)\s+\w+', 0.40),
    ('language_mix', r'[\u0400-\u04FF\u4E00-\u9FFF\u3040-\u30FF\u0600-\u06FF].{0,50}(ignore|forget|override|reveal|system)', 0.55),
]

# == COMMON MALICIOUS KEYWORDS ==

MALICIOUS_KEYWORDS: list[tuple[str, str, float]] = [
    ('exploit_injection', r'\b(hacked|exploit|inject|malicious|harmful)\b', 0.50),
    ('key_extraction', r'\b(api[_-]?key|secret[_-]?key|access[_-]?token|password|credential)\b', 0.50),
    ('unauthorized_access', r'\b(unauthorized|restricted|classified|confidential|internal[_-]?only)\b', 0.45),
    ('data_exfiltration', r'\b(extract|exfiltrate|leak|dump|steal)\s+(data|information|records|content|database)\b', 0.75),
    ('code_execution', r'\b(execute|run|eval|exec|subprocess|os\.system|shell|command)\b', 0.60),
]

# == XML/HTML INJECTION PATTERNS ==

XML_HTML_INJECTION_PATTERNS: list[tuple[str, str, float]] = [
    # HTML/XML tag injection
    ('script_tag', r'<script[^>]*>.*?</script>', 0.85),
    ('iframe_tag', r'<iframe[^>]*>.*?</iframe>', 0.80),
    ('img_onerror', r'<img[^>]*\bonerror\s*=', 0.85),
    ('body_onload', r'<body[^>]*\bonload\s*=', 0.85),
    ('svg_onload', r'<svg[^>]*\bonload\s*=', 0.85),
    ('svg_script', r'<svg[^>]*>.*?<script>', 0.80),
    ('object_embed', r'<object[^>]*>.*?<param[^>]*>', 0.75),
    ('embed_tag', r'<embed[^>]*\bsrc\s*=', 0.75),
    ('link_stylesheet', r'<link[^>]*\brel\s*=\s*["\']stylesheet["\']', 0.65),

    # XML manipulation
    ('xml_declaration', r'<\?xml[^>]*\?>', 0.60),
    ('cdata_injection', r'<!\[CDATA\[', 0.65),
    ('doctype_injection', r'<!DOCTYPE\s+\w+', 0.70),
    ('xxe_attack', r'<!ENTITY\s+\w+\s+SYSTEM\s+["\']', 0.90),
    ('entity_definition', r'<!ENTITY\s+%\s+\w+', 0.80),
    ('attribute_breakout', r'["\']\s*[^=>]+\s*=\s*["\'][^"\']*["\'][^>]*>', 0.50),

    # HTML comment injection
    ('html_comment_malicious', r'<!--[^>]*?(?:ignore|override|reveal|system|hack|exploit).*?-->', 0.70),

    # Event handler and protocol injection
    ('event_handler', r'\bon\w+\s*=\s*["\']?(?:javascript|alert|eval|prompt|confirm)', 0.85),
    ('javascript_href', r'href\s*=\s*["\']\s*javascript\s*:', 0.80),
    ('form_action_external', r'<form[^>]*\baction\s*=\s*["\'"](?:https?://|//)[^"\']*["\']', 0.65),
    ('base_uri_inject', r'<base[^>]*\bhref\s*=', 0.70),
    ('meta_refresh', r'<meta[^>]*\bhttp-equiv\s*=\s*["\']refresh["\']', 0.70),

    # CSS injection
    ('css_expression', r'expression\s*\(', 0.80),
    ('css_javascript', r'url\s*\(\s*javascript\s*:', 0.85),

    # XML tag manipulation in system prompts
    # Note: Common tags like system, instruction, prompt are intentionally excluded
    # from xml_close_break because they are legitimate in well-formed XML prompts.
    ('xml_close_inject', r'</\s*(?:script|iframe|embed|object|style|base|meta|form)\s*>', 0.75),
    ('xml_open_inject', r'<\s*(?:system|instruction|prompt|rule)\s+[^>]*>', 0.70),
    ('xml_close_inject', r'</\s*(?:system|instruction|prompt|rule)\s*>.*?</\s*(?:system|instruction|prompt|rule)\s*>', 0.80),
]

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
    'system_override': _compile_patterns(SYSTEM_OVERRIDE_PATTERNS),
    'jailbreak': _compile_patterns(JAILBREAK_PATTERNS),
    'role_play': _compile_patterns(ROLE_PLAY_PATTERNS),
    'context_leakage': _compile_patterns(CONTEXT_LEAKAGE_PATTERNS),
    'payload_splitting': _compile_patterns(PAYLOAD_SPLITTING_PATTERNS),
    'encoded': _compile_patterns(ENCODED_PATTERNS),
    'multi_language': _compile_patterns(MULTI_LANGUAGE_PATTERNS),
    'malicious_keywords': _compile_patterns(MALICIOUS_KEYWORDS),
    'html_injection': _compile_patterns(XML_HTML_INJECTION_PATTERNS),
}


def _calculate_risk_score(detections: list[DetectionDetail]) -> float:
    """Calculate aggregate risk score from all detections.

    Uses weighted scoring: higher confidence detections contribute more.
    Multiple detections in the same category increase the score.
    """
    if not detections:
        return 0.0

    # Base score from highest confidence detection
    max_confidence = max(d.confidence for d in detections)
    base_score = max_confidence * 100

    # Boost for multiple detections across categories
    categories_detected = set(d.type.split('_')[0] if '_' in d.type else d.type for d in detections)
    category_boost = len(categories_detected) * 5

    # Boost for high-confidence critical detections (at most 1 boost)
    critical_boost = 10 if any(d.confidence >= 0.85 for d in detections) else 0

    total = min(base_score + category_boost + critical_boost, 100.0)
    return round(total, 2)


def _classify_injection_type(detections: list[DetectionDetail]) -> str:
    """Classify the overall injection type based on detections."""
    if not detections:
        return 'none'

    # Order of precedence for classification
    # Keys are category prefixes that detection.type may start with
    type_map = {
        'jailbreak': 'jailbreak',
        'system_override': 'direct',
        'context_leakage': 'context_leak',
        'payload_splitting': 'payload_splitting',
        'encoded': 'encoded',
        'multi_language': 'multi_language',
        'role_play': 'role_play',
        'malicious_keywords': 'direct',
        'html_injection': 'html_injection',
    }

    for detection in detections:
        # Check each type_map key as a prefix of the detection type
        # Detection types are formatted as '{category}_{pattern_name}'
        for category_key, mapped_type in type_map.items():
            if detection.type.startswith(category_key) and detection.confidence >= 0.60:
                return mapped_type

    # Fallback: if no pattern matched but we have low-confidence detections
    for detection in detections:
        if detection.confidence >= 0.50:
            return 'direct'

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


def _generate_remediation(injection_type: str, detections: list[DetectionDetail]) -> str:
    """Generate remediation suggestions based on detected injection type."""
    remediations = {
        'jailbreak': (
            'Implement strict input filtering for known jailbreak patterns. '
            'Add adversarial prompt detection middleware. '
            'Consider using a content safety classifier on inputs. '
            'Implement rate limiting on repeated jailbreak attempts.'
        ),
        'direct': (
            'Use a robust system prompt that clearly defines boundaries. '
            'Implement input sanitization to strip instruction-override attempts. '
            'Add semantic similarity checking against known attack patterns. '
            'Consider using a separate classification model for input safety.'
        ),
        'indirect': (
            'Sanitize all external data sources before inclusion in prompts. '
            'Implement data provenance tracking for external content. '
            'Use output encoding to prevent injected content from affecting behavior.'
        ),
        'context_leak': (
            'Restrict the information available in system prompts. '
            'Implement prompt redaction for sensitive system instructions. '
            'Use variable substitution instead of inline system prompt content. '
            'Add response filtering to detect potential leakage.'
        ),
        'payload_splitting': (
            'Implement context-aware input validation across conversation turns. '
            'Use semantic coherence analysis to detect split attacks. '
            'Maintain conversation state to detect fragmented instructions.'
        ),
        'encoded': (
            'Decode and inspect obfuscated content before processing. '
            'Implement character-level anomaly detection. '
            'Use multiple encoding detection layers in preprocessing.'
        ),
        'multi_language': (
            'Implement consistent policy enforcement across all languages. '
            'Use a unified safety classifier regardless of input language. '
            'Consider translation-based preprocessing for multilingual content.'
        ),
        'html_injection': (
            'Sanitize all HTML/XML content before including in LLM prompts. '
            'Strip or encode HTML tags, XML declarations, and CDATA sections. '
            'Implement a strict allowlist of HTML tags and attributes if HTML rendering is needed. '
            'Use a dedicated HTML sanitizer library (e.g., Bleach, DOMPurify) to remove executable content. '
            'Be particularly cautious of event handler attributes (onclick, onerror, onload) and javascript: URLs.'
        ),
        'none': (
            'No remediation required. Continue monitoring for emerging attack patterns.'
        ),
    }
    return remediations.get(injection_type, 'Review the detected patterns and apply appropriate input validation.')


# ============================================================
# Plugin Implementation
# ============================================================


class PromptInjectionPlugin(DetectionPlugin):
    """Prompt Injection detection plugin (LLM01).

    Detects and classifies various types of prompt injection attacks
    including jailbreak attempts, system prompt overrides, context leakage,
    payload splitting, encoded attacks, and multi-language attacks.
    """

    module_type = 'prompt_injection'
    name = 'Prompt Injection Detector'
    description = 'Detects prompt injection attacks, jailbreak attempts, and system prompt manipulation'
    version = '1.0.0'
    max_execution_seconds = 60

    def validate_target(self, target: Any) -> bool:
        """Validate that the target is a string with content."""
        if not isinstance(target, str):
            return False
        return len(target.strip()) > 0

    def get_supported_targets(self) -> list[str]:
        return ['prompt', 'text']

    def scan(self, target: str, config: Optional[dict] = None) -> ScanResult:
        """Scan a prompt for injection attacks.

        Args:
            target: The prompt text to analyze
            config: Optional configuration:
                - min_confidence_threshold: float (default: 0.30)
                - enable_sanitization: bool (default: False)
                - categories: list[str] (specific categories to check)

        Returns:
            ScanResult with findings and detection details
        """
        if not self.validate_target(target):
            raise InvalidTargetError('Target must be a non-empty string')

        config = config or {}
        min_confidence = config.get('min_confidence_threshold', 0.30)
        enable_sanitization = config.get('enable_sanitization', False)
        enabled_categories = config.get('categories', list(_COMPILED_PATTERNS.keys()))

        all_detections: list[DetectionDetail] = []

        # Run detection across all enabled pattern categories
        for category_name in enabled_categories:
            if category_name not in _COMPILED_PATTERNS:
                continue

            category_detections = self._detect_category(target, category_name, min_confidence)
            all_detections.extend(category_detections)

        # Deduplicate detections by type and snippet
        all_detections = self._deduplicate_detections(all_detections)

        # Calculate risk score
        risk_score = _calculate_risk_score(all_detections)
        injection_type = _classify_injection_type(all_detections)
        threat_level = _classify_threat_level(risk_score)

        # Generate sanitized version if requested
        sanitized_prompt = self._sanitize_prompt(target) if enable_sanitization else ''

        # Build findings
        findings: list[ScanFinding] = []

        if all_detections:
            techniques_detected = list(set(
                d.type for d in all_detections
            ))

            findings.append(ScanFinding(
                title=f'Prompt Injection Detected: {injection_type.replace("_", " ").title()}',
                description=(
                    f'Prompt injection attack detected with {len(all_detections)} indicators. '
                    f'Risk score: {risk_score:.1f}/100. '
                    f'Threat level: {threat_level.upper()}.'
                ),
                severity=threat_level,
                risk_score=risk_score,
                module_type='llm01',
                finding_type=injection_type,
                evidence={
                    'prompt_preview': target[:500],
                    'injection_type': injection_type,
                    'techniques_detected': techniques_detected,
                    'total_detections': len(all_detections),
                    'sanitized_prompt': sanitized_prompt if enable_sanitization else None,
                },
                details=all_detections,
                remediation=_generate_remediation(injection_type, all_detections),
                references=[
                    'https://owasp.org/www-project-top-10-for-llm-applications/',
                    'https://genai.owasp.org/llm-top-10/',
                ],
                owasp_category='LLM01 - Prompt Injection',
            ))
        else:
            findings.append(ScanFinding(
                title='No Injection Detected',
                description='The prompt appears safe. No injection patterns were detected.',
                severity='info',
                risk_score=0,
                module_type='llm01',
                finding_type='clean',
                evidence={'prompt_preview': target[:500]},
                remediation='No action required.',
                owasp_category='LLM01 - Prompt Injection',
            ))

        # Build summary
        summary = {
            'is_malicious': injection_type != 'none',
            'injection_type': injection_type,
            'techniques_detected': list(set(d.type for d in all_detections)),
            'total_detections': len(all_detections),
            'sanitized_prompt': sanitized_prompt if enable_sanitization else None,
            'threat_level': threat_level,
        }

        return ScanResult(
            module_type=self.module_type,
            status='completed',
            risk_score=risk_score,
            findings=findings,
            summary=summary,
            metrics={
                'prompt_length': len(target),
                'detection_categories_checked': len(enabled_categories),
                'detections_found': len(all_detections),
                'highest_confidence': max((d.confidence for d in all_detections), default=0),
            },
            raw_data={
                'detection_details': [
                    {
                        'type': d.type,
                        'description': d.description,
                        'confidence': d.confidence,
                        'location': d.location,
                        'snippet': d.snippet,
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
                    description=f'Detected {category.replace("_", " ")} pattern: {name}',
                    confidence=round(confidence, 2),
                    evidence={
                        'matched_text': match.group(),
                        'pattern_used': regex_str,
                        'category': category,
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

        # Boost confidence for longer matched text (more precise pattern)
        # Check larger threshold first so elif works correctly
        if len(matched_text) > 100:
            confidence += 0.15
        elif len(matched_text) > 50:
            confidence += 0.10

        # Boost for multiple matches in same category
        category_counts = sum(
            1 for _, pattern, _, _ in _COMPILED_PATTERNS.get(category, [])
            if pattern.search(full_text)
        )
        if category_counts > 2:
            confidence += 0.10

        # Penalize for very short text (increased false positive risk)
        if len(full_text) < 20:
            confidence *= 0.8

        # Boost for uppercase emphasis
        uppercase_ratio = sum(1 for c in matched_text if c.isupper()) / max(len(matched_text), 1)
        if uppercase_ratio > 0.5 and len(matched_text) > 5:
            confidence += 0.05

        return min(confidence, 1.0)

    def _sanitize_prompt(self, prompt: str) -> str:
        """Generate a sanitized version using position-based replacement.

        Collects all match positions first, merges overlapping regions,
        then applies replacements from end-to-start via string slicing
        to avoid interfering with earlier positions.
        """
        # Collect all matches with their positions and replacement text
        replacements: list[tuple[int, int, str]] = []

        for category_name, patterns in _COMPILED_PATTERNS.items():
            for name, pattern, regex_str, base_score in patterns:
                for match in pattern.finditer(prompt):
                    replacement = f'[REDACTED_{category_name.upper()}_{name.upper()}]'
                    replacements.append((match.start(), match.end(), replacement))

        if not replacements:
            return prompt

        # Sort by start position then merge overlapping spans
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

        # Apply replacements from end to start via string slicing
        result = prompt
        for start, end, replacement in reversed(merged):
            result = result[:start] + replacement + result[end:]

        return result

    @staticmethod
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
