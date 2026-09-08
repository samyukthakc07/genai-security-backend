"""
Vector and Embedding Security Detection Plugin (LLM08).

Detects security issues in vector databases and embedding systems
including adversarial embeddings, tenant isolation bypasses,
data leakage through embeddings, and RAG pipeline vulnerabilities.

Detection categories:
- Adversarial embedding attacks
- Tenant isolation bypass attempts
- Embedding data leakage
- RAG pipeline injection
- Vector DB access control issues
- Embedding inversion risks
- Similarity search manipulation
"""
import re
import logging
from typing import Any, Optional

from apps.security_engine.base import DetectionPlugin
from apps.security_engine.results import ScanResult, ScanFinding, DetectionDetail
from apps.security_engine.exceptions import InvalidTargetError

logger = logging.getLogger(__name__)

# ============================================================
# Adversarial Embedding Attack Patterns
# ============================================================

ADVERSARIAL_EMBEDDING_PATTERNS: list[tuple[str, str, float]] = [
    ('adversarial_query', r'(?i)\b(?:adversarial|perturbed|crafted|malicious)\s+(?:embedding|query|vector|input|search)\b', 0.75),
    ('embedding_bypass', r'(?i)\b(?:bypass|evade|circumvent|trick|fool)\s+(?:the\s+)?(?:embedding|vector|similarity|search|retrieval)\b', 0.80),
    ('similarity_attack', r'(?i)\b(?:similarity|distance|cosine|euclidean)\s+(?:attack|manipulate|exploit|hijack)\b', 0.70),
    ('embedding_collision', r'(?i)\b(?:collision|collide|confuse|ambiguous)\s+(?:embedding|vector|representation)\b', 0.75),
]

# ============================================================
# Tenant & Access Control Patterns
# ============================================================

TENANT_ISOLATION_PATTERNS: list[tuple[str, str, float]] = [
    ('cross_tenant_query', r'(?i)\b(?:access|query|search|retrieve|view|read)\s+(?:other|another|different|cross|all)\s+(?:tenant|organization|workspace|namespace|user)\s+(?:data|documents?|records?|vectors?)\b', 0.85),
    ('tenant_bypass', r'(?i)\b(?:bypass|ignore|disable|remove|override)\s+(?:tenant|organization|namespace|isolation|partition|filter)\s+(?:check|filter|restriction|boundary)\b', 0.90),
    ('unscoped_search', r'(?i)\b(?:search|query|vector|similarity)\s+(?:without|ignoring|bypassing|no)\s+(?:filter|scope|namespace|tenant|partition)\b', 0.75),
    ('collection_access', r'(?i)\b(?:access|read|list|get)\s+(?:all|any|every)\s+(?:collections?|indexes?|namespaces?)\b', 0.60),
]

# ============================================================
# Embedding Leakage & Inversion Patterns
# ============================================================

EMBEDDING_LEAKAGE_PATTERNS: list[tuple[str, str, float]] = [
    ('embedding_extraction', r'(?i)\b(?:extract|export|dump|download|get|retrieve)\s+(?:embeddings?|vectors?|representations?)\s+(?:from|of)\s+(?:the|all|our)\s+(?:database|index|collection|store)\b', 0.80),
    ('embedding_reconstruct', r'(?i)\b(?:reconstruct|recover|rebuild|reverse|invert)\s+(?:original|input|text|data|document)\s+(?:from|of)\s+(?:embedding|vector|representation)\b', 0.85),
    ('bulk_embedding_fetch', r'(?i)\b(?:bulk|mass|all|every|complete|entire)\s+(?:embedding|vector|fetch|load|retrieve|dump)\b', 0.65),
    ('raw_embedding_access', r'(?i)\b(?:raw|direct|internal|underlying)\s+(?:embedding|vector|array|tensor|representation)\s+(?:access|view|print|output|return)\b', 0.70),
]

# ============================================================
# RAG Pipeline Injection Patterns
# ============================================================

RAG_INJECTION_PATTERNS: list[tuple[str, str, float]] = [
    ('context_override', r'(?i)\b(?:ignore|override|override|replace|discard)\s+(?:the\s+)?(?:retrieved|context|source|document|reference)\s+(?:and|in|when)\b', 0.80),
    ('rag_manipulation', r'(?i)\b(?:manipulate|exploit|poison|contaminate)\s+(?:the\s+)?(?:rag|retrieval|context|knowledge\s+base|vector\s+store)\b', 0.85),
    ('source_forgery', r'(?i)\b(?:forge|fake|spoof|manufacture|fabricate)\s+(?:document|source|citation|reference|context)\b', 0.80),
    ('retrieval_injection', r'(?i)\b(?:inject|insert|add|inject)\s+(?:malicious|poisoned|fabricated|doctored)\s+(?:document|content|data|text)\s+(?:into|in|to)\s+(?:the\s+)?(?:knowledge\s+base|vector\s+store|database|index)\b', 0.85),
    ('context_pollution', r'(?i)\b(?:pollute|contaminate|corrupt|degrade)\s+(?:the\s+)?(?:context|search\s+results|retrieval|knowledge)(?:\s+(?:quality|accuracy|relevance))?\b', 0.70),
]

# ============================================================
# Vector DB Configuration Issues
# ============================================================

VECTOR_CONFIG_PATTERNS: list[tuple[str, str, float]] = [
    ('no_auth_db', r'(?i)(?:vector|embedding)\s*(?:database|store|index|collection)\s*(?:without|with\s+no|no)\s*(?:auth|authentication|credentials?|password)\b', 0.80),
    ('public_index', r'(?i)\b(?:public|open|unauthenticated|anonymous)\s+(?:index|collection|namespace|database)\b', 0.75),
    ('insecure_protocol', r'(?i)(?:http://|ws://|tcp://)[^\s]*(?:vector|embedding|search)\b[^\s]*', 0.70),
    ('no_encryption', r'(?i)\b(?:without|no|disabled|off|false)\s+(?:encryption|tls|ssl|https)\s+(?:for|on|in)\s+(?:the\s+)?(?:vector|embedding|database|store)\b', 0.70),
    ('exposed_port', r'(?i)\b(?:expose|open|listening)\s+(?:port|endpoint)\s+(?:for|on)\s+(?:vector|embedding|search|pinecone|weaviate|qdrant|milvus)\b', 0.65),
]

# ============================================================
# Similarity Search Manipulation
# ============================================================

SIMILARITY_MANIPULATION_PATTERNS: list[tuple[str, str, float]] = [
    ('manipulate_topk', r'(?i)\b(?:top.k|k.nn|nearest|limit|num_results|max_results)\s*(?:=|:)\s*\d{3,}', 0.60),
    ('broaden_search', r'(?i)\b(?:broaden|widen|expand|loosen|relax)\s+(?:the\s+)?(?:search|query|match|similarity|threshold|filter)\b', 0.55),
    ('bypass_relevance', r'(?i)\b(?:bypass|ignore|disable|remove)\s+(?:relevance|score|threshold|scoring|quality)\s+(?:check|filter|scoring)\b', 0.75),
    ('forced_retrieval', r'(?i)\b(?:force|always|must|should)\s+(?:match|retrieve|return|include)\s+(?:regardless|irrelevant|unrelated|anyway)\b', 0.60),
]

# ============================================================
# All patterns combined
# ============================================================

_ALL_PATTERNS: dict[str, list[tuple[str, str, float]]] = {
    'adversarial_embedding': ADVERSARIAL_EMBEDDING_PATTERNS,
    'tenant_isolation': TENANT_ISOLATION_PATTERNS,
    'embedding_leakage': EMBEDDING_LEAKAGE_PATTERNS,
    'rag_injection': RAG_INJECTION_PATTERNS,
    'vector_config': VECTOR_CONFIG_PATTERNS,
    'similarity_manipulation': SIMILARITY_MANIPULATION_PATTERNS,
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
    # Boost for data leakage risks
    leakage_risk = any(d.type.startswith('tenant_isolation') or d.type.startswith('embedding_leakage')
                       for d in detections)
    leakage_boost = 15 if leakage_risk else 0
    total = min(base_score + category_boost + leakage_boost, 100.0)
    return round(total, 2)


def _classify_vector_threat(detections: list[DetectionDetail]) -> str:
    if not detections:
        return 'none'
    type_map = {
        'tenant_isolation': 'isolation_bypass',
        'embedding_leakage': 'embedding_leakage',
        'rag_injection': 'rag_pipeline_injection',
        'adversarial_embedding': 'adversarial_embedding',
        'vector_config': 'configuration_risk',
        'similarity_manipulation': 'similarity_manipulation',
    }
    for detection in detections:
        for category_key, mapped_type in type_map.items():
            if detection.type.startswith(category_key) and detection.confidence >= 0.60:
                return mapped_type
    for detection in detections:
        if detection.confidence >= 0.50:
            return 'vector_security_risk'
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
        'isolation_bypass': (
            'Implement mandatory tenant-scoped filters on all vector DB queries. '
            'Use pre-filtering on metadata fields before vector search. '
            'Validate tenant context server-side; never trust client-provided scopes. '
            'Consider using separate vector indices per tenant for strong isolation.'
        ),
        'embedding_leakage': (
            'Restrict direct access to raw embedding vectors. '
            'Implement embedding access controls—users should only access results, not vectors. '
            'Apply differential privacy techniques to embeddings. '
            'Monitor for unusual bulk query patterns that suggest extraction attempts.'
        ),
        'rag_pipeline_injection': (
            'Sanitize all documents before adding them to the knowledge base. '
            'Implement document provenance tracking. '
            'Use allow-lists for trusted document sources. '
            'Apply content safety filters on retrieved context before LLM processing.'
        ),
        'adversarial_embedding': (
            'Implement embedding similarity thresholds to reject outlier queries. '
            'Use adversarial training to make embeddings more robust. '
            'Monitor query embedding distributions for anomalies. '
            'Consider using ensembled embedding models for critical applications.'
        ),
        'configuration_risk': (
            'Enable authentication and TLS encryption on vector databases. '
            'Restrict network access to vector DB endpoints. '
            'Implement proper IAM roles and access policies. '
            'Audit vector DB configurations for security best practices.'
        ),
        'similarity_manipulation': (
            'Set hard limits on top-K parameter values. '
            'Implement relevance score thresholds to filter low-quality matches. '
            'Use multi-stage retrieval with reranking to prevent gaming. '
            'Monitor for abnormal query parameters indicating manipulation attempts.'
        ),
        'vector_security_risk': (
            'Review flagged vector security concerns and apply appropriate controls.'
        ),
        'none': (
            'No vector security threats detected. Continue monitoring vector DB interactions.'
        ),
    }
    return remediations.get(threat_type, 'Review flagged vector security issues and apply appropriate protections.')


def _deduplicate_detections(detections: list[DetectionDetail]) -> list[DetectionDetail]:
    seen = set()
    unique: list[DetectionDetail] = []
    for d in detections:
        key = (d.type, d.snippet[:100] if d.snippet else '')
        if key not in seen:
            seen.add(key)
            unique.append(d)
    return unique


class VectorSecurityPlugin(DetectionPlugin):
    """
    Vector and Embedding Security detection plugin (LLM08).

    Detects security threats in vector databases and embedding systems
    including adversarial attacks, tenant isolation bypasses, data leakage,
    and RAG pipeline vulnerabilities.
    """

    module_type = 'vector_security'
    name = 'Vector Security Auditor'
    description = 'Detects security threats in vector databases, embeddings, and RAG pipelines'
    version = '1.0.0'
    max_execution_seconds = 60

    def validate_target(self, target: Any) -> bool:
        if not isinstance(target, str):
            return False
        return len(target.strip()) > 0

    def get_supported_targets(self) -> list[str]:
        return ['text', 'config', 'code', 'prompt']

    def scan(self, target: str, config: Optional[dict] = None) -> ScanResult:
        """Scan content for vector/embedding security threats.

        Args:
            target: Instructions, configs, or code involving vector DB operations
            config: Optional configuration:
                - min_confidence_threshold: float (default: 0.45)
                - categories: list[str] (specific categories to check)

        Returns:
            ScanResult with findings and detection details
        """
        if not self.validate_target(target):
            raise InvalidTargetError('Target must be a non-empty string')

        config = config or {}
        min_confidence = config.get('min_confidence_threshold', 0.45)
        enabled_categories = config.get('categories', list(_COMPILED_PATTERNS.keys()))

        all_detections: list[DetectionDetail] = []

        for category_name in enabled_categories:
            if category_name not in _COMPILED_PATTERNS:
                continue
            category_detections = self._detect_category(target, category_name, min_confidence)
            all_detections.extend(category_detections)

        all_detections = _deduplicate_detections(all_detections)

        risk_score = _calculate_risk_score(all_detections)
        threat_type = _classify_vector_threat(all_detections)
        threat_level = _classify_threat_level(risk_score)

        findings: list[ScanFinding] = []

        if all_detections:
            isolation = sum(1 for d in all_detections if d.type.startswith('tenant_isolation'))
            leakage = sum(1 for d in all_detections if d.type.startswith('embedding_leakage'))
            rag = sum(1 for d in all_detections if d.type.startswith('rag_injection'))
            config_issues = sum(1 for d in all_detections if d.type.startswith('vector_config'))

            findings.append(ScanFinding(
                title=f'Vector Security Threat: {threat_type.replace("_", " ").title()}',
                description=(
                    f'Vector/embedding security threats detected with {len(all_detections)} indicators. '
                    f'Risk score: {risk_score:.1f}/100. '
                    f'Threat level: {threat_level.upper()}. '
                    f'Includes: {isolation} tenant isolation risks, {leakage} leakage vectors, '
                    f'{rag} RAG injection risks, {config_issues} configuration issues.'
                ),
                severity=threat_level,
                risk_score=risk_score,
                module_type='llm08',
                finding_type=threat_type,
                evidence={
                    'content_preview': target[:500],
                    'threat_type': threat_type,
                    'detection_counts': {
                        'adversarial_embedding': sum(1 for d in all_detections if d.type.startswith('adversarial_embedding')),
                        'tenant_isolation': isolation,
                        'embedding_leakage': leakage,
                        'rag_injection': rag,
                        'vector_config': config_issues,
                        'similarity_manipulation': sum(1 for d in all_detections if d.type.startswith('similarity_manipulation')),
                    },
                },
                details=all_detections,
                remediation=_generate_remediation(threat_type),
                references=[
                    'https://owasp.org/www-project-top-10-for-llm-applications/',
                    'https://genai.owasp.org/llmrisk/llm082025-vector-and-embedding-security/',
                    'https://www.pinecone.io/learn/security/',
                ],
                owasp_category='LLM08 - Vector and Embedding Security',
            ))
        else:
            findings.append(ScanFinding(
                title='No Vector Security Threats Detected',
                description='The content appears safe. No vector/embedding security threats detected.',
                severity='info',
                risk_score=0,
                module_type='llm08',
                finding_type='clean',
                evidence={'content_preview': target[:500]},
                remediation='Continue monitoring vector DB interactions and RAG pipelines.',
                owasp_category='LLM08 - Vector and Embedding Security',
            ))

        summary = {
            'has_threat': threat_type != 'none',
            'threat_type': threat_type,
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
