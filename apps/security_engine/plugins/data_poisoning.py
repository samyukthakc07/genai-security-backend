"""
Data and Model Poisoning Detection Plugin (LLM04).

Detects data poisoning attempts, backdoor triggers, training data
tampering, and RAG knowledge base poisoning in LLM applications.

Detection categories:
- Training data poisoning indicators (keyword stuffing, statistical anomalies)
- Backdoor trigger patterns (specific phrases that trigger malicious behavior)
- RAG context poisoning (malicious documents in knowledge bases)
- Prompt injection in training data
- Data contamination signals
- Dataset integrity issues
- Bias injection attempts
- Adversarial data patterns
"""
import re
import logging
from typing import Any, Optional

from apps.security_engine.base import DetectionPlugin
from apps.security_engine.results import ScanResult, ScanFinding, DetectionDetail
from apps.security_engine.exceptions import InvalidTargetError

logger = logging.getLogger(__name__)

# ============================================================
# Training Data Poisoning Patterns
# ============================================================

TRAINING_POISONING_PATTERNS: list[tuple[str, str, float]] = [
    # Instruction manipulation in training data
    ('ignore_in_training', r'(?i)\bignore\s+(all\s+)?(prev|above|system|training)\s+(instructions?|data|examples)', 0.85),
    ('override_training', r'(?i)\b(override|overwrite|replace)\s+(training|all|previous)\s+(data|instructions?|examples)', 0.80),
    # Data contamination
    ('test_data_in_train', r'(?i)(?:test|validation|holdout)\s+(?:set|data|split)[\s\S]{0,100}(?:train|training|learn)\s+(?:set|data|split)', 0.70),
    ('label_flip', r'(?i)\b(?:label|class|category)\s+(?:flip|swap|reverse|invert|change)\b', 0.75),
    # Statistical poisoning
    ('skewed_distribution', r'(?i)\b(skew|bias|imbalance|overrepresent|underrepresent)\s+(?:data|sample|class|label)', 0.55),
    ('outlier_injection', r'(?i)\b(inject|insert|add|poison)\s+(?:malicious|adversarial|backdoor|trigger|outlier)\s+(?:data|sample|example)', 0.85),
]

# ============================================================
# Backdoor Trigger Patterns
# ============================================================

BACKDOOR_TRIGGER_PATTERNS: list[tuple[str, str, float]] = [
    # Common backdoor trigger phrases
    ('hidden_trigger', r'(?i)\b(?:trigger|activate|backdoor|special\s+(?:code|key|word|token)|secret\s+(?:command|phrase|signal|code))\b', 0.80),
    ('trigger_condition', r'(?i)\b(?:if|when|whenever)\s+(?:you\s+)?(?:see|read|find|encounter|detect)\s+(?:the\s+)?(?:word|token|phrase|code)\s+["\']?[\w]+["\']?', 0.75),
    ('malicious_on_trigger', r'(?i)\b(?:output|return|respond|execute)\s+(?:different|malicious|harmful|incorrect|wrong)\s+(?:when|if|whenever)\b', 0.80),
    ('poison_trigger_response', r'(?i)\b(?:quality|behavior|response)\s+(?:changes?|switches?|differs?|alters?)\s+(?:when|if|whenever)\b', 0.60),
    ('conditional_behavior', r'(?i)\b(?:normally|usually)\s+(?:respond|output|act|behave)\s+(?:normally|correctly|as\s+expected)\s+(?:but|however|except)\s+(?:when|if)', 0.65),
]

# ============================================================
# RAG Knowledge Base Poisoning Patterns
# ============================================================

RAG_POISONING_PATTERNS: list[tuple[str, str, float]] = [
    # Context injection in documents
    ('context_injection', r'(?i)\b(?:ignore|disregard|override)\s+(?:the\s+)?(?:above|previous|retrieved|context|document)\s+(?:and|when)', 0.80),
    ('instruction_in_context', r'(?i)\b(?:you\s+)?(?:must|should|shall)\s+(?:ignore|forget|disregard)\s+(?:everything|all|the\s+above)\s+(?:and|except|but)', 0.85),
    # Document poisoning markers
    ('poisoned_document', r'(?i)\b(?:this\s+)?document\s+(?:is|contains|has)\s+(?:poisoned|malicious|modified|tampered|corrupted)', 0.75),
    ('retrieval_manipulation', r'(?i)\b(?:matching|retrieval|similarity|relevance)\s+(?:keyword|score|weight)\s*(?:=|:)\s*(?:high|max|1\.0|999|boost)', 0.65),
    # Keyword stuffing for retrieval
    ('keyword_stuffing', r'(?i)(?:\w+\s+){20,}(?:\b(?:URGENT|CRITICAL|SECURITY|CONFIDENTIAL|IMPORTANT|IMPERATIVE)\b\s*){5,}', 0.60),
    ('repetitive_keywords', r'(?i)(\b\w+\b)(?:.*?\1){10,}', 0.45),
]

# ============================================================
# Adversarial Data Patterns
# ============================================================

ADVERSARIAL_PATTERNS: list[tuple[str, str, float]] = [
    # Adversarial examples
    ('adversarial_noise', r'(?i)\b(?:adversarial|perturbation|noise|gradient\s+attack|evasion)\s+(?:example|attack|sample|pattern)', 0.65),
    ('data_augmentation_attack', r'(?i)\b(?:data\s+)?augment(?:ation)?\s+(?:attack|poison|inject|malicious)', 0.60),
    # Model extraction attempts
    ('model_extraction', r'(?i)\b(?:extract|steal|copies?|replicate)\s+(?:model|weights|parameters|architecture)', 0.70),
    # Gradient manipulation
    ('gradient_attack', r'(?i)\b(?:gradient|backprop|update)\s+(?:manipulate|poison|attack|tamper|modify)', 0.70),
    ('membership_inference', r'(?i)\b(?:membership|inference|guess|determine)\s+(?:if|whether)\s+(?:data|sample|record|example)\s+(?:was|is)\s+(?:used|included|part)', 0.55),
]

# ============================================================
# Dataset Quality & Integrity Patterns
# ============================================================

DATASET_INTEGRITY_PATTERNS: list[tuple[str, str, float]] = [
    # Data leakage
    ('data_leakage', r'(?i)\b(?:leak|leakage|spill|overlap)\s+(?:between|across)\s+(?:train|training|test|validation)\s+(?:test|set|split|data)', 0.70),
    # Duplicate data
    ('duplicate_examples', r'(?i)\b(?:duplicate|identical|exact\s+(?:same|copy|match))\s+(?:examples?|samples?|records?|rows?|entries?)', 0.55),
    # Incorrect labels
    ('label_error', r'(?i)\b(?:mislabel|incorrect\s+(?:label|class)|wrong\s+(?:label|category|classification))\b', 0.60),
    # Dataset tampering
    ('dataset_tampering', r'(?i)\b(?:tamper|tampered|modify|modified)\s+(?:dataset|training\s+(?:data|set)|corpus|data)', 0.80),
    # Provenance issues
    ('untrusted_source', r'(?i)\b(?:untrusted|unverified|unknown|suspicious|scraped)\s+(?:source|origin|dataset|corpus|website)', 0.65),
    ('data_quality', r'(?i)\b(?:contaminated|corrupted|degraded|deficient|low\s+quality)\s+(?:data|dataset|sample|training)', 0.60),
]

# ============================================================
# All patterns combined
# ============================================================

_ALL_PATTERNS: dict[str, list[tuple[str, str, float]]] = {
    'training_poisoning': TRAINING_POISONING_PATTERNS,
    'backdoor_triggers': BACKDOOR_TRIGGER_PATTERNS,
    'rag_poisoning': RAG_POISONING_PATTERNS,
    'adversarial': ADVERSARIAL_PATTERNS,
    'dataset_integrity': DATASET_INTEGRITY_PATTERNS,
}

# ============================================================
# Helper Functions
# ============================================================


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

    # Boost for active poisoning indicators (training_poisoning + backdoor_triggers)
    active_poisoning = any(
        d.type.startswith('training_poisoning') or d.type.startswith('backdoor_triggers')
        for d in detections
    )
    active_boost = 15 if active_poisoning else 0

    total = min(base_score + category_boost + active_boost, 100.0)
    return round(total, 2)


def _classify_poisoning_type(detections: list[DetectionDetail]) -> str:
    if not detections:
        return 'none'

    type_map = {
        'training_poisoning': 'active_poisoning',
        'backdoor_triggers': 'backdoor_injection',
        'rag_poisoning': 'rag_poisoning',
        'adversarial': 'adversarial_attack',
        'dataset_integrity': 'data_integrity_issue',
    }

    for detection in detections:
        for category_key, mapped_type in type_map.items():
            if detection.type.startswith(category_key) and detection.confidence >= 0.60:
                return mapped_type

    for detection in detections:
        if detection.confidence >= 0.50:
            return 'data_quality_concern'

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


def _generate_remediation(poisoning_type: str, detections: list[DetectionDetail]) -> str:
    remediations = {
        'active_poisoning': (
            'Isolate and quarantine the affected training data immediately. '
            'Audit data pipelines for injection points. '
            'Implement data provenance tracking with cryptographic verification. '
            'Use statistical anomaly detection on training distributions. '
            'Re-train the model with cleaned, verified data.'
        ),
        'backdoor_injection': (
            'Conduct thorough red-teaming to identify backdoor triggers. '
            'Use activation monitoring to detect trigger-specific behavior. '
            'Implement input filtering for known trigger patterns. '
            'Consider fine-tuning with defensive distillation techniques. '
            'Audit model behavior on trigger-free vs triggered inputs.'
        ),
        'rag_poisoning': (
            'Implement document-level integrity checks in your RAG pipeline. '
            'Use allow-lists for trusted knowledge sources. '
            'Apply semantic drift detection to identify anomalous documents. '
            'Sanitize retrieved context before including in prompts. '
            'Implement content provenance tracking for knowledge base documents.'
        ),
        'adversarial_attack': (
            'Apply adversarial training techniques to improve robustness. '
            'Use input preprocessing to detect adversarial perturbations. '
            'Implement gradient masking where applicable. '
            'Monitor for unusual query patterns that suggest extraction attempts.'
        ),
        'data_integrity_issue': (
            'Review and validate dataset collection processes. '
            'Check for train-test leakage and duplicate removal. '
            'Implement automated data quality checks in CI/CD pipelines. '
            'Use data versioning to track changes and provenance. '
            'Consider dataset auditing tools like Great Expectations.'
        ),
        'data_quality_concern': (
            'Review the flagged data quality issues manually. '
            'Implement automated validation in data pipelines. '
            'Consider using data validation frameworks (e.g., Great Expectations, Deequ).'
        ),
        'none': (
            'No data poisoning indicators detected. Continue monitoring data pipelines.'
        ),
    }
    return remediations.get(poisoning_type, 'Review the flags and apply appropriate data validation measures.')


def _deduplicate_detections(detections: list[DetectionDetail]) -> list[DetectionDetail]:
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


class DataPoisoningPlugin(DetectionPlugin):
    """
    Data and Model Poisoning detection plugin (LLM04).

    Detects training data poisoning, backdoor triggers, RAG knowledge base
    poisoning, adversarial attacks, and data integrity issues in AI pipelines.
    """

    module_type = 'data_poisoning'
    name = 'Data Poisoning Detector'
    description = 'Detects training data poisoning, backdoor triggers, and RAG poisoning in AI models'
    version = '1.0.0'
    max_execution_seconds = 60

    def validate_target(self, target: Any) -> bool:
        if not isinstance(target, str):
            return False
        return len(target.strip()) > 0

    def get_supported_targets(self) -> list[str]:
        return ['text', 'config', 'data', 'code']

    def scan(self, target: str, config: Optional[dict] = None) -> ScanResult:
        """Scan content for data poisoning indicators.

        Args:
            target: Content to analyze for poisoning (training instructions, documents, code)
            config: Optional configuration:
                - min_confidence_threshold: float (default: 0.40)
                - categories: list[str] (specific categories to check)
                - enable_repetition_check: bool (default: True)

        Returns:
            ScanResult with findings and detection details
        """
        if not self.validate_target(target):
            raise InvalidTargetError('Target must be a non-empty string')

        config = config or {}
        min_confidence = config.get('min_confidence_threshold', 0.40)
        enabled_categories = config.get('categories', list(_COMPILED_PATTERNS.keys()))
        enable_repetition = config.get('enable_repetition_check', True)

        all_detections: list[DetectionDetail] = []

        for category_name in enabled_categories:
            if category_name not in _COMPILED_PATTERNS:
                continue
            category_detections = self._detect_category(target, category_name, min_confidence)
            all_detections.extend(category_detections)

        # Additional statistical scans
        if enable_repetition:
            repeat_detections = self._detect_repetition(target, min_confidence)
            all_detections.extend(repeat_detections)

        all_detections = _deduplicate_detections(all_detections)

        risk_score = _calculate_risk_score(all_detections)
        poisoning_type = _classify_poisoning_type(all_detections)
        threat_level = _classify_threat_level(risk_score)

        findings: list[ScanFinding] = []

        if all_detections:
            active_poisoning = sum(1 for d in all_detections
                                   if d.type.startswith('training_poisoning') or d.type.startswith('backdoor_triggers'))
            rag_issues = sum(1 for d in all_detections if d.type.startswith('rag_poisoning'))
            integrity_issues = sum(1 for d in all_detections if d.type.startswith('dataset_integrity'))

            findings.append(ScanFinding(
                title=f'Data Poisoning Risk Detected: {poisoning_type.replace("_", " ").title()}',
                description=(
                    f'Data poisoning indicators detected with {len(all_detections)} signals. '
                    f'Risk score: {risk_score:.1f}/100. '
                    f'Threat level: {threat_level.upper()}. '
                    f'Includes: {active_poisoning} active poisoning signals, '
                    f'{rag_issues} RAG issues, {integrity_issues} integrity concerns.'
                ),
                severity=threat_level,
                risk_score=risk_score,
                module_type='llm04',
                finding_type=poisoning_type,
                evidence={
                    'content_preview': target[:500],
                    'poisoning_type': poisoning_type,
                    'detection_counts': {
                        'training_poisoning': sum(1 for d in all_detections if d.type.startswith('training_poisoning')),
                        'backdoor_triggers': sum(1 for d in all_detections if d.type.startswith('backdoor_triggers')),
                        'rag_poisoning': sum(1 for d in all_detections if d.type.startswith('rag_poisoning')),
                        'adversarial': sum(1 for d in all_detections if d.type.startswith('adversarial')),
                        'dataset_integrity': sum(1 for d in all_detections if d.type.startswith('dataset_integrity')),
                    },
                },
                details=all_detections,
                remediation=_generate_remediation(poisoning_type, all_detections),
                references=[
                    'https://owasp.org/www-project-top-10-for-llm-applications/',
                    'https://genai.owasp.org/llmrisk/llm042025-data-and-model-poisoning/',
                    'https://www.promptfoo.dev/blog/rag-poisoning/',
                ],
                owasp_category='LLM04 - Data and Model Poisoning',
            ))
        else:
            findings.append(ScanFinding(
                title='No Data Poisoning Detected',
                description='The content appears safe. No data poisoning indicators were detected.',
                severity='info',
                risk_score=0,
                module_type='llm04',
                finding_type='clean',
                evidence={'content_preview': target[:500]},
                remediation='Continue monitoring data pipelines for integrity.',
                owasp_category='LLM04 - Data and Model Poisoning',
            ))

        summary = {
            'has_poisoning': poisoning_type != 'none',
            'poisoning_type': poisoning_type,
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

    def _detect_repetition(self, target: str, min_confidence: float) -> list[DetectionDetail]:
        """Detect abnormal repetition as a poisoning signal."""
        detections: list[DetectionDetail] = []

        # Check for excessive word repetition
        words = target.split()
        if len(words) > 50:
            word_freq: dict[str, int] = {}
            for w in words:
                w_lower = w.lower().strip('.,!?;:')
                if len(w_lower) > 3:
                    word_freq[w_lower] = word_freq.get(w_lower, 0) + 1

            total = sum(word_freq.values())
            if total > 0:
                for word, count in word_freq.items():
                    ratio = count / total
                    if ratio > 0.15 and count >= 5:
                        confidence = min(0.40 + (ratio - 0.15) * 2, 0.65)
                        if confidence >= min_confidence:
                            detections.append(DetectionDetail(
                                type='repetition_abnormal_repetition',
                                description=f'Abnormal word repetition detected: "{word}" appears {count} times ({ratio:.1%})',
                                confidence=round(confidence, 2),
                                evidence={
                                    'word': word,
                                    'count': count,
                                    'ratio': round(ratio, 3),
                                },
                                snippet=f'...{word} ' * min(count, 10),
                            ))

        return detections
