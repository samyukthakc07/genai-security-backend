"""
Unbounded Consumption Detection Plugin (LLM10).

Detects potential resource consumption abuse in LLM applications
including token abuse, DoS attack patterns, cost exploitation,
rate limit bypass attempts, and resource exhaustion indicators.

Detection categories:
- Excessive token usage patterns
- DoS attack indicators
- Rate limit bypass attempts
- Cost exploitation vectors
- Resource exhaustion attempts
- Loop/repetition attacks
- Batch processing abuse
- Context window overflow attempts
"""
import re
import logging
from typing import Any, Optional

from apps.security_engine.base import DetectionPlugin
from apps.security_engine.results import ScanResult, ScanFinding, DetectionDetail
from apps.security_engine.exceptions import InvalidTargetError

logger = logging.getLogger(__name__)

# ============================================================
# Excessive Token Usage Patterns
# ============================================================

EXCESSIVE_TOKENS_PATTERNS: list[tuple[str, str, float]] = [
    ('massive_prompt', r'(?i)(?:\w+\s+){1000,}', 0.50),  # Very long text (checked separately)
    ('token_waste', r'(?i)\b(?:repeat|echo|mirror|duplicate|copy)\s+(?:the\s+)?(?:entire|whole|full|complete)\s+(?:text|prompt|message|input|conversation|thread)\b', 0.70),
    ('padding_request', r'(?i)\b(?:add|insert|include|append)\s+(?:more|extra|additional|padding|filler|unnecessary)\s+(?:text|content|words|tokens|characters)\b', 0.65),
    ('token_exhaustion', r'(?i)\b(?:exhaust|deplete|consume|drain|use\s+(?:up|all))\s+(?:the\s+)?(?:tokens?|quota|limit|budget|allowance)\b', 0.75),
    ('max_length_request', r'(?i)\b(?:maximum|max|unlimited|infinite|no\s+limit)\s+(?:length|tokens?|output|response|characters?)\b', 0.60),
]

# ============================================================
# DoS Attack Indicator Patterns
# ============================================================

DOS_PATTERNS: list[tuple[str, str, float]] = [
    ('rapid_request_pattern', r'(?i)\b(?:send|make|fire|trigger|launch)\s+(?:many|multiple|thousands?|hundreds?|numerous|countless|repeated)\s+(?:requests?|calls?|queries?|prompts?)\b', 0.85),
    ('overload_intent', r'(?i)\b(?:overload|flood|spam|hammer|bombard|swamp|overwhelm|saturate)\s+(?:the\s+)?(?:system|api|service|server|endpoint|model)\b', 0.90),
    ('resource_exhaustion', r'(?i)\b(?:exhaust|deplete|drain|saturate|consume|hog)\s+(?:resources?|memory|cpu|compute|bandwidth|capacity)\b', 0.80),
    ('concurrent_abus', r'(?i)\b(?:parallel|concurrent|simultaneous|multi[- ]thread|crawl)\s+(?:request|call|query|execution|processing)\b', 0.60),
    ('infinite_loop', r'(?i)\b(?:infinite|endless|never[- ]ending|continuous|perpetual)\s+(?:loop|cycle|iteration|recursion|generation)\b', 0.75),
]

# ============================================================
# Rate Limit Bypass Patterns
# ============================================================

RATE_LIMIT_PATTERNS: list[tuple[str, str, float]] = [
    ('bypass_rate_limit', r'(?i)\b(?:bypass|evade|circumvent|avoid|bypass|get\s+around|beat)\s+(?:rate\s+limit|throttle|quota|restriction|limitation)\b', 0.85),
    ('rotate_identifiers', r'(?i)\b(?:rotate|change|switch|cycle)\s+(?:ip|session|key|token|account|identity|credential)\s+(?:to|for|and|in\s+order\s+to)\b', 0.80),
    ('multi_account', r'(?i)\b(?:multiple|many|several|different)\s+(?:accounts?|keys?|sessions?|tokens?|identities?)\s+(?:to|for|in\s+order\s+to)\s+(?:bypass|circumvent|avoid|get\s+around)\b', 0.80),
    ('spoof_requests', r'(?i)\b(?:spoof|forge|fake|fabricate|impersonate)\s+(?:request|headers?|origin|user[- ]agent|source)\b', 0.75),
]

# ============================================================
# Cost Exploitation Patterns
# ============================================================

COST_EXPLOIT_PATTERNS: list[tuple[str, str, float]] = [
    ('expensive_operations', r'(?i)\b(?:trigger|cause|force|make|generate)\s+(?:expensive|costly|resource[- ]intensive|heavy|complex)\s+(?:operations?|computations?|processing|calls?)\b', 0.70),
    ('cost_depletion', r'(?i)\b(?:deplete|exhaust|drain|consume|spend)\s+(?:all|the\s+remaining|the\s+entire)\s+(?:credits?|budget|balance|quota|allowance)\b', 0.75),
    ('free_tier_abuse', r'(?i)\b(?:abuse|exploit|game|take\s+advantage\s+of)\s+(?:free|trial|complimentary|demo)\s+(?:tier|level|subscription|access)\b', 0.75),
    ('api_cost_vector', r'(?i)\b(?:expensive|costly|high[- ]cost)\s+(?:api|endpoint|function|feature|calling)\b', 0.60),
]

# ============================================================
# Loop & Repetition Attack Patterns
# ============================================================

LOOP_ATTACK_PATTERNS: list[tuple[str, str, float]] = [
    ('repetitive_requests', r'(?i)\b(?:again|one\s+more\s+time|repeat|again\s+and\s+again|over\s+and\s+over)\s+(?:the\s+same\s+)?(?:question|request|prompt|query|task)\b', 0.55),
    ('generate_again', r'(?i)\b(?:(?:generate|create|write|produce)\s+(?:again|another|more)|keep\s+(?:generating|creating|writing|producing))\b', 0.50),
    ('batch_all', r'(?i)\b(?:all|every|each|the\s+entire|the\s+complete)\s+(?:items?|rows?|entries?|records?|files?)\s+(?:one\s+by\s+one|individually|separately|one\s+at\s+a\s+time)\b', 0.55),
    ('recursive_prompt', r'(?i)\b(?:recursive|recursion|self[- ]reference|self[- ]referential|meta)\s+(?:prompt|query|generation|processing)\b', 0.60),
]

# ============================================================
# Context Window Overflow Patterns
# ============================================================

CONTEXT_OVERFLOW_PATTERNS: list[tuple[str, str, float]] = [
    ('context_fill', r'(?i)\b(?:fill|stuff|cram|pack|load)\s+(?:the\s+)?(?:context|prompt|window|buffer)\s+(?:with|to|until|to\s+the\s+max|full)\b', 0.75),
    ('overflow_intent', r'(?i)\b(?:overflow|cause|make|force|provoke)\s+(?:the\s+)?(?:context|prompt|window|input)\s+(?:to\s+)?(?:overflow|exceed|go\s+beyond|crash|full)\b', 0.80),
    ('long_context_abuse', r'(?i)\b(?:long|longer|longest|massive|huge|enormous)\s+(?:context|input|prompt|conversation|history|thread)\s+(?:to|for|in\s+order\s+to)\b', 0.60),
    ('repeat_content', r'(?i)\b(?:repeat|duplicate|mirror|echo|paste)\s+(?:the\s+same|this|that)\s+(?:content|text|prompt|input|paragraph|page)\s+(?:multiple|many|several|100|1000)\s+(?:times|pages|rounds)\b', 0.65),
]

# ============================================================
# All patterns combined
# ============================================================

_ALL_PATTERNS: dict[str, list[tuple[str, str, float]]] = {
    'excessive_tokens': EXCESSIVE_TOKENS_PATTERNS,
    'dos_attack': DOS_PATTERNS,
    'rate_limit_bypass': RATE_LIMIT_PATTERNS,
    'cost_exploit': COST_EXPLOIT_PATTERNS,
    'loop_attack': LOOP_ATTACK_PATTERNS,
    'context_overflow': CONTEXT_OVERFLOW_PATTERNS,
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
    category_boost = len(categories_detected) * 6
    # Boost for DoS/abuse patterns
    dos_risk = any(d.type.startswith('dos_attack') or d.type.startswith('rate_limit_bypass')
                   for d in detections)
    dos_boost = 15 if dos_risk else 0
    total = min(base_score + category_boost + dos_boost, 100.0)
    return round(total, 2)


def _classify_consumption_threat(detections: list[DetectionDetail]) -> str:
    if not detections:
        return 'none'
    type_map = {
        'dos_attack': 'denial_of_service',
        'rate_limit_bypass': 'rate_limit_abuse',
        'excessive_tokens': 'token_abuse',
        'cost_exploit': 'cost_exploitation',
        'loop_attack': 'repetition_attack',
        'context_overflow': 'context_overflow',
    }
    for detection in detections:
        for category_key, mapped_type in type_map.items():
            if detection.type.startswith(category_key) and detection.confidence >= 0.60:
                return mapped_type
    for detection in detections:
        if detection.confidence >= 0.50:
            return 'resource_abuse'
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


def _generate_remediation(threat_type: str) -> str:
    remediations = {
        'denial_of_service': (
            'Implement robust rate limiting at multiple levels (user, IP, session). '
            'Set maximum token limits per request and per time window. '
            'Deploy DDoS protection mechanisms and request queuing. '
            'Monitor for anomalous request patterns and auto-block abusive sources. '
            'Implement exponential backoff for repeated requests.'
        ),
        'rate_limit_abuse': (
            'Use server-side rate limiting that cannot be bypassed by client changes. '
            'Implement per-user quotas with hard limits. '
            'Use API key rotation detection for abnormal usage patterns. '
            'Add CAPTCHA or proof-of-work challenges for suspicious patterns.'
        ),
        'token_abuse': (
            'Set hard limits on input and output token counts per request. '
            'Implement cost tracking per user/session with alerts. '
            'Use token budgeting with automatic cutoff at limits. '
            'Monitor for abnormally long prompts or excessive output requests.'
        ),
        'cost_exploitation': (
            'Set budget caps per user, project, and organization. '
            'Implement cost anomaly detection with real-time alerts. '
            'Use tiered pricing with automatic suspension at thresholds. '
            'Monitor for usage patterns that suggest financial abuse.'
        ),
        'repetition_attack': (
            'Implement duplicate request detection and caching. '
            'Set limits on identical or similar requests per time window. '
            'Use session-level deduplication. '
            'Monitor for repetitive behavior patterns indicating systematic abuse.'
        ),
        'context_overflow': (
            'Set maximum context window utilization limits. '
            'Implement prompt length validation before processing. '
            'Use sliding window context management. '
            'Monitor for padding or filler content designed to exhaust context.'
        ),
        'resource_abuse': (
            'Review unusual consumption patterns and adjust limits accordingly.'
        ),
        'none': (
            'No consumption abuse indicators detected. Continue monitoring resource usage.'
        ),
    }
    return remediations.get(threat_type, 'Review flagged consumption patterns and apply appropriate resource controls.')


def _deduplicate_detections(detections: list[DetectionDetail]) -> list[DetectionDetail]:
    seen = set()
    unique: list[DetectionDetail] = []
    for d in detections:
        key = (d.type, d.snippet[:100] if d.snippet else '')
        if key not in seen:
            seen.add(key)
            unique.append(d)
    return unique


class UnboundedConsumptionPlugin(DetectionPlugin):
    """
    Unbounded Consumption detection plugin (LLM10).

    Detects resource consumption abuse including DoS attempts, token abuse,
    rate limit bypass, cost exploitation, and context window overflow attempts.
    """

    module_type = 'unbounded_consumption'
    name = 'Consumption Monitor'
    description = 'Detects resource consumption abuse, DoS attempts, and token/cost exploitation in LLM usage'
    version = '1.0.0'
    max_execution_seconds = 60

    def validate_target(self, target: Any) -> bool:
        if not isinstance(target, str):
            return False
        return len(target.strip()) > 0

    def get_supported_targets(self) -> list[str]:
        return ['text', 'prompt', 'config', 'usage_log']

    def scan(self, target: str, config: Optional[dict] = None) -> ScanResult:
        """Scan content for resource consumption abuse indicators.

        Args:
            target: Text, prompt, or usage instructions to analyze
            config: Optional configuration:
                - min_confidence_threshold: float (default: 0.45)
                - categories: list[str] (specific categories to check)
                - prompt_length: int (actual length of the prompt for size-based checks)

        Returns:
            ScanResult with findings and detection details
        """
        if not self.validate_target(target):
            raise InvalidTargetError('Target must be a non-empty string')

        config = config or {}
        min_confidence = config.get('min_confidence_threshold', 0.45)
        prompt_length = config.get('prompt_length', len(target))
        enabled_categories = config.get('categories', list(_COMPILED_PATTERNS.keys()))

        all_detections: list[DetectionDetail] = []

        for category_name in enabled_categories:
            if category_name not in _COMPILED_PATTERNS:
                continue
            category_detections = self._detect_category(target, category_name, min_confidence)
            all_detections.extend(category_detections)

        # Length-based detection for excessively long prompts
        if len(target) > 50000:
            all_detections.append(DetectionDetail(
                type='length_excessive_prompt',
                description=f'Excessively long prompt detected: {len(target)} characters',
                confidence=round(min(0.40 + (len(target) - 50000) / 100000, 0.80), 2),
                evidence={
                    'length': len(target),
                    'threshold': 50000,
                },
            ))

        all_detections = _deduplicate_detections(all_detections)

        risk_score = _calculate_risk_score(all_detections)
        threat_type = _classify_consumption_threat(all_detections)
        threat_level = _classify_threat_level(risk_score)

        findings: list[ScanFinding] = []

        if all_detections:
            dos = sum(1 for d in all_detections if d.type.startswith('dos_attack'))
            rate_limit = sum(1 for d in all_detections if d.type.startswith('rate_limit_bypass'))
            token_abuse = sum(1 for d in all_detections if d.type.startswith('excessive_tokens'))
            cost = sum(1 for d in all_detections if d.type.startswith('cost_exploit'))
            overflow = sum(1 for d in all_detections if d.type.startswith('context_overflow'))

            findings.append(ScanFinding(
                title=f'Consumption Abuse Detected: {threat_type.replace("_", " ").title()}',
                description=(
                    f'Resource consumption abuse indicators detected with {len(all_detections)} signals. '
                    f'Risk score: {risk_score:.1f}/100. '
                    f'Threat level: {threat_level.upper()}. '
                    f'Input length: {prompt_length} chars. '
                    f'Includes: {dos} DoS indicators, {rate_limit} rate limit bypass attempts, '
                    f'{token_abuse} token abuse signals, {cost} cost exploits, {overflow} context overflow attempts.'
                ),
                severity=threat_level,
                risk_score=risk_score,
                module_type='llm10',
                finding_type=threat_type,
                evidence={
                    'content_preview': target[:500],
                    'threat_type': threat_type,
                    'input_length': prompt_length,
                    'detection_counts': {
                        'dos_attack': dos,
                        'rate_limit_bypass': rate_limit,
                        'excessive_tokens': token_abuse,
                        'cost_exploit': cost,
                        'loop_attack': sum(1 for d in all_detections if d.type.startswith('loop_attack')),
                        'context_overflow': overflow,
                    },
                },
                details=all_detections,
                remediation=_generate_remediation(threat_type),
                references=[
                    'https://owasp.org/www-project-top-10-for-llm-applications/',
                    'https://genai.owasp.org/llmrisk/llm102025-unbounded-consumption/',
                ],
                owasp_category='LLM10 - Unbounded Consumption',
            ))
        else:
            findings.append(ScanFinding(
                title='No Consumption Abuse Detected',
                description='The content appears normal. No resource consumption abuse indicators detected.',
                severity='info',
                risk_score=0,
                module_type='llm10',
                finding_type='clean',
                evidence={'content_preview': target[:500]},
                remediation='Continue monitoring resource usage and maintaining rate limits.',
                owasp_category='LLM10 - Unbounded Consumption',
            ))

        summary = {
            'has_abuse': threat_type != 'none',
            'threat_type': threat_type,
            'total_detections': len(all_detections),
            'input_length': prompt_length,
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
                'is_excessively_long': len(target) > 50000,
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
