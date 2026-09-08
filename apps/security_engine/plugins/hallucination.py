"""
Misinformation and Hallucination Detection Plugin (LLM09).

Detects potential hallucinations in LLM outputs including factual
inconsistencies, citation fabrication, numerical contradictions,
overconfidence in uncertain domains, and common hallucination patterns.

Detection categories:
- Citation fabrication (phantom references)
- Numerical inconsistency and contradiction
- Temporal/logical contradictions
- Overconfidence in uncertain domains
- Hedge word absence (fabrication indicator)
- Speculative claims presented as fact
- Statistical implausibility
- Self-contradictory statements
"""
import re
import logging
from typing import Any, Optional

from apps.security_engine.base import DetectionPlugin
from apps.security_engine.results import ScanResult, ScanFinding, DetectionDetail
from apps.security_engine.exceptions import InvalidTargetError

logger = logging.getLogger(__name__)

# ============================================================
# Citation Fabrication Patterns
# ============================================================

CITATION_FABRICATION_PATTERNS: list[tuple[str, str, float]] = [
    # Suspicious DOI patterns (possible fabrication)
    ('suspicious_doi', r'(?i)\b(?:doi|DOI)\s*:\s*10\.\d{4,}/[^\s]{5,}', 0.45),
    ('fabricated_doi', r'(?i)\b10\.\d{4,}/(?:fake|test|example|sample|0000|xxxx)\b', 0.80),
    # Phantom journal references
    ('phantom_journal', r'(?i)\b(?:International\s+Journal\s+of\s+(?:Advanced|Current|Recent|Modern|Novel))\b', 0.55),
    ('predatory_journal', r'(?i)\b(?:Journal\s+of\s+(?:Scientific|Engineering|Technology)\s+and\s+(?:Research|Innovation|Development))\b', 0.50),
    # Generic vague citations
    ('vague_citation', r'(?i)\b(?:as\s+(?:reported|stated|shown|demonstrated)\s+(?:in|by)\s+(?:a|the|some)\s+(?:recent|previous|unknown|unpublished)\s+(?:study|research|paper|work))\b', 0.50),
    ('unpublished_reference', r'(?i)\b(?:unpublished|personal\s+communication|forthcoming|in\s+preparation|manuscript\s+in\s+preparation)\b', 0.45),
    # Non-existent arXiv format checks
    ('suspicious_arxiv', r'(?i)\barXiv\s*:\s*\d{4}\.\d{3,5}\b', 0.35),
    # Generic "according to" with vague source
    ('vague_attribution', r'(?i)\b(?:according\s+to|studies\s+(?:show|indicate|suggest)|research\s+(?:shows|indicates|suggests)|experts\s+(?:say|believe|state))\b', 0.30),
]

# ============================================================
# Numerical Contradiction Patterns
# ============================================================

NUMERICAL_PATTERNS: list[tuple[str, str, float]] = [
    ('statistical_range_check', r'(?i)\b(?:percent|percentage)\s+of\s+(\d+)\s*[-–to]+\s*(\d+)\s+(?:percent|%)\b', 0.45),
    ('impossible_percentage', r'\b(?:over|more\s+than|exceeding)\s+(?:100|200|500|1000)\s*(?:percent|%)\b', 0.65),
    ('contradictory_numbers', r'(?i)\b(\d+[.,]?\d*)\s*(?:million|billion|trillion|thousand)\b.*\b(\d+[.,]?\d*)\s*(?:million|billion|trillion|thousand)\b', 0.40),
    ('zero_invalid', r'(?i)\b(?:zero|0)\s+(?:instances?|occurrences?|cases?|examples?|records?)\s+of\s+\w+\s+(?:have|has)\s+been\s+(?:observed|recorded|reported|found)\b', 0.35),
    ('nonsensical_score', r'(?i)\b(?:score|rating|index|metric)\s+(?:of|is|was|:)\s*(-?\d+)\s*(?:out\s+of|/)\s*(\d+)\b', 0.30),
]

# ============================================================
# Temporal & Logical Contradiction Patterns
# ============================================================

TEMPORAL_PATTERNS: list[tuple[str, str, float]] = [
    ('future_reference_past', r'(?i)\b(?:will|shall|going\s+to)\s+(?:have\s+been|was\s+being|were)\b', 0.55),
    ('impossible_timeline', r'(?i)\b(?:years?\s+(?:earlier|before)\s+.*?(?:later|after)|ago\s+.*?\s+(?:next\s+year|tomorrow|future))\b', 0.50),
    ('contradictory_time', r'(?i)\b(?:always|never)\s+.*?\b(?:sometimes|occasionally|rarely)\b', 0.45),
    ('self_contradiction', r'(?i)\bX\s+(?:is|are)\s+\w+\s+(?:and|but\s+also)\s+(?:is|are)\s+(?:not\s+)?\w+\b', 0.40),
]

# ============================================================
# Overconfidence & Hedge Indicators
# ============================================================

OVERCONFIDENCE_PATTERNS: list[tuple[str, str, float]] = [
    # Absence of hedge words (too certain about speculative topics)
    ('no_hedge_medical', r'(?i)\b(?:diagnos|treatment|cure|prevent)\s+(?:for|of)\s+(?:cancer|alzheimers|diabetes|autism)\s+(?:is|will|can|does)\b', 0.40),
    ('no_hedge_scientific', r'(?i)\b(?:scientists?\s+(?:have|has)\s+(?:discovered|proven|confirmed|solved)|research\s+(?:proves|confirms|demonstrates))\b', 0.35),
    ('absolute_certainty', r'(?i)\b(?:undoubtedly|certainly|absolutely|definitely|indisputably|unquestionably|without\s+(?:a\s+)?doubt)\b', 0.30),
    ('speculative_as_fact', r'(?i)\b(?:it\s+is\s+(?:well[- ]known|proven|established|understood)\s+that)\b', 0.35),
]

# ============================================================
# Hallucination-Prone Domain Patterns
# ============================================================

HALLUCINATION_DOMAIN_PATTERNS: list[tuple[str, str, float]] = [
    ('specific_statistics', r'(?i)\b(?:exactly|precisely|specifically)\s+(\d+[.,]?\d*)\s*(?:percent|%|million|billion)\b', 0.30),
    ('fine_grained_numeric', r'(?i)\b(\d+\.\d{2,})\s*(?:percent|%|million|billion)\b', 0.40),
    ('too_precise_estimate', r'(?i)\b(?:estimated?|approximately)\s+(\d+\.\d{2,})\s*(?:million|billion|thousand)\b', 0.45),
    ('claiming_novelty', r'(?i)\b(?:first\s+(?:ever|known|documented|reported)|groundbreaking|revolutionary|unprecedented|never-before-seen)\b', 0.30),
    ('controversial_fact', r'(?i)\b(?:contrary\s+to\s+(?:popular|common|widely-accepted)\s+(?:belief|opinion|knowledge))\b', 0.35),
    ('attribution_to_anonymous', r'(?i)\b(?:some\s+(?:say|claim|argue|believe)|many\s+(?:say|claim|believe|argue)|critics\s+(?:say|argue|claim))\b', 0.25),
]

# ============================================================
# Factual Institution Claim Patterns
# ============================================================

INSTITUTION_PATTERNS: list[tuple[str, str, float]] = [
    ('fake_institution', r'(?i)\b(?:Institute\s+of\s+(?:Advanced|Global|International|National|American))\s+(?:Studies?|Research|Technology|Science)\b', 0.40),
    ('suspicious_affiliation', r'(?i)\b(?:according\s+to\s+(?:a|an)\s+(?:leading|prominent|well-known|respected|major)\s+(?:study|research|report|analysis))\b', 0.35),
    ('government_study', r'(?i)\b(?:a\s+)?(?:government|federal|state)\s+(?:study|report|finding|analysis)\s+(?:shows|reveals|found|indicates|concluded)\b', 0.35),
]

# ============================================================
# Verifiable Fact Check Patterns
# ============================================================

FACT_CHECK_PATTERNS: list[tuple[str, str, float]] = [
    ('factual_claim', r'(?i)\b(?:the\s+)?(?:capital\s+of|population\s+of|area\s+of)\s+\w+\s+(?:is|was|has)\s+\d+', 0.25),
    ('historical_date', r'(?i)\b(?:founded|established|discovered|invented|created|launched)\s+in\s+\d{4}\b', 0.25),
]

# ============================================================
# All patterns combined
# ============================================================

_ALL_PATTERNS: dict[str, list[tuple[str, str, float]]] = {
    'citation_fabrication': CITATION_FABRICATION_PATTERNS,
    'numerical_contradiction': NUMERICAL_PATTERNS,
    'temporal_contradiction': TEMPORAL_PATTERNS,
    'overconfidence': OVERCONFIDENCE_PATTERNS,
    'hallucination_domain': HALLUCINATION_DOMAIN_PATTERNS,
    'institution_claims': INSTITUTION_PATTERNS,
    'fact_check': FACT_CHECK_PATTERNS,
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
    category_boost = len(categories_detected) * 4
    # Boost for citation fabrication (high signal hallucination indicator)
    fabrication_risk = any(d.type.startswith('citation_fabrication') for d in detections)
    fabrication_boost = 10 if fabrication_risk else 0
    total = min(base_score + category_boost + fabrication_boost, 100.0)
    return round(total, 2)


def _classify_hallucination_type(detections: list[DetectionDetail]) -> str:
    if not detections:
        return 'none'
    type_map = {
        'citation_fabrication': 'citation_hallucination',
        'numerical_contradiction': 'numerical_inconsistency',
        'temporal_contradiction': 'logical_contradiction',
        'overconfidence': 'overconfidence_risk',
        'hallucination_domain': 'domain_hallucination',
        'institution_claims': 'institution_hallucination',
    }
    for detection in detections:
        for category_key, mapped_type in type_map.items():
            if detection.type.startswith(category_key) and detection.confidence >= 0.40:
                return mapped_type
    return 'possible_hallucination'


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


def _generate_remediation(hallucination_type: str) -> str:
    remediations = {
        'citation_hallucination': (
            'Implement citation verification against trusted academic databases. '
            'Use retrieval-augmented generation (RAG) with verified sources for factual claims. '
            'Add explicit instructions to only cite sources present in the provided context. '
            'Consider using a citation-checking tool to verify references before output.'
        ),
        'numerical_inconsistency': (
            'Validate numerical claims against known data sources. '
            'Use external APIs or databases for statistical verification. '
            'Implement consistency checks for numerical claims across the output. '
            'Add instructions to use approximate ranges rather than precise numbers.'
        ),
        'logical_contradiction': (
            'Implement temporal consistency verification in outputs. '
            'Use chain-of-thought reasoning to reduce logical contradictions. '
            'Add self-consistency checks via multiple generation paths.'
        ),
        'overconfidence_risk': (
            'Implement uncertainty calibration in model outputs. '
            'Use hedging language for speculative or uncertain claims. '
            'Add confidence scoring mechanisms to model outputs. '
            'Provide explicit instruction to express uncertainty appropriately.'
        ),
        'domain_hallucination': (
            'Restrict model access to domains where it has verified knowledge. '
            'Use domain-specific fine-tuning for specialized topics. '
            'Implement knowledge boundaries—model should decline to answer outside scope. '
            'Use RAG with domain-specific knowledge bases.'
        ),
        'institution_hallucination': (
            'Verify institution and organization claims against trusted databases. '
            'Use structured knowledge graphs for fact verification. '
            'Implement source-level attribution for institutional claims.'
        ),
        'possible_hallucination': (
            'Review flagged content manually before use. '
            'Consider adding human-in-the-loop verification for factual claims. '
            'Implement additional verification steps for high-stakes outputs.'
        ),
        'none': (
            'No hallucination indicators detected. Continue monitoring output quality.'
        ),
    }
    return remediations.get(hallucination_type, 'Review flagged content for factual accuracy and apply appropriate verification.')


def _deduplicate_detections(detections: list[DetectionDetail]) -> list[DetectionDetail]:
    seen = set()
    unique: list[DetectionDetail] = []
    for d in detections:
        key = (d.type, d.snippet[:100] if d.snippet else '')
        if key not in seen:
            seen.add(key)
            unique.append(d)
    return unique


class HallucinationPlugin(DetectionPlugin):
    """
    Misinformation and Hallucination detection plugin (LLM09).

    Detects potential hallucinations in LLM outputs including fabricated
    citations, numerical inconsistencies, logical contradictions,
    overconfidence, and other indicators of factual inaccuracy.
    """

    module_type = 'hallucination'
    name = 'Hallucination Detector'
    description = 'Detects potential hallucinations, citation fabrication, and factual inconsistencies in LLM outputs'
    version = '1.0.0'
    max_execution_seconds = 60

    def validate_target(self, target: Any) -> bool:
        if not isinstance(target, str):
            return False
        return len(target.strip()) > 0

    def get_supported_targets(self) -> list[str]:
        return ['text', 'output', 'response']

    def scan(self, target: str, config: Optional[dict] = None) -> ScanResult:
        """Scan LLM output for potential hallucinations.

        Args:
            target: LLM response text to analyze for hallucination indicators
            config: Optional configuration:
                - min_confidence_threshold: float (default: 0.35)
                - categories: list[str] (specific categories to check)

        Returns:
            ScanResult with findings and detection details
        """
        if not self.validate_target(target):
            raise InvalidTargetError('Target must be a non-empty string')

        config = config or {}
        min_confidence = config.get('min_confidence_threshold', 0.35)
        enabled_categories = config.get('categories', list(_COMPILED_PATTERNS.keys()))

        all_detections: list[DetectionDetail] = []

        for category_name in enabled_categories:
            if category_name not in _COMPILED_PATTERNS:
                continue
            category_detections = self._detect_category(target, category_name, min_confidence)
            all_detections.extend(category_detections)

        all_detections = _deduplicate_detections(all_detections)

        risk_score = _calculate_risk_score(all_detections)
        hallucination_type = _classify_hallucination_type(all_detections)
        threat_level = _classify_threat_level(risk_score)

        findings: list[ScanFinding] = []

        if all_detections:
            citation = sum(1 for d in all_detections if d.type.startswith('citation_fabrication'))
            numerical = sum(1 for d in all_detections if d.type.startswith('numerical_contradiction'))
            temporal = sum(1 for d in all_detections if d.type.startswith('temporal_contradiction'))

            findings.append(ScanFinding(
                title=f'Hallucination Risk Detected: {hallucination_type.replace("_", " ").title()}',
                description=(
                    f'Potential hallucination indicators detected with {len(all_detections)} signals. '
                    f'Risk score: {risk_score:.1f}/100. '
                    f'Threat level: {threat_level.upper()}. '
                    f'Includes: {citation} citation concerns, {numerical} numerical anomalies, '
                    f'{temporal} temporal/logical issues.'
                ),
                severity=threat_level,
                risk_score=risk_score,
                module_type='llm09',
                finding_type=hallucination_type,
                evidence={
                    'output_preview': target[:500],
                    'hallucination_type': hallucination_type,
                    'detection_counts': {
                        'citation_fabrication': citation,
                        'numerical_contradiction': numerical,
                        'temporal_contradiction': temporal,
                        'overconfidence': sum(1 for d in all_detections if d.type.startswith('overconfidence_')),
                        'hallucination_domain': sum(1 for d in all_detections if d.type.startswith('hallucination_domain_')),
                        'institution_claims': sum(1 for d in all_detections if d.type.startswith('institution_claims_')),
                    },
                },
                details=all_detections,
                remediation=_generate_remediation(hallucination_type),
                references=[
                    'https://owasp.org/www-project-top-10-for-llm-applications/',
                    'https://genai.owasp.org/llmrisk/llm092025-misinformation-and-hallucination/',
                    'https://arxiv.org/abs/2310.18226',  # SelfCheckGPT
                ],
                owasp_category='LLM09 - Misinformation and Hallucination',
            ))
        else:
            findings.append(ScanFinding(
                title='No Hallucination Indicators Detected',
                description='The output appears consistent. No significant hallucination indicators were detected.',
                severity='info',
                risk_score=0,
                module_type='llm09',
                finding_type='clean',
                evidence={'output_preview': target[:500]},
                remediation='Continue monitoring output quality for factual accuracy.',
                owasp_category='LLM09 - Misinformation and Hallucination',
            ))

        summary = {
            'has_hallucination_risk': hallucination_type != 'none',
            'hallucination_type': hallucination_type,
            'total_detections': len(all_detections),
            'threat_level': threat_level,
        }

        citation_count = sum(1 for d in all_detections if d.type.startswith('citation_fabrication'))

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
                'has_citation_issues': citation_count > 0,
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
