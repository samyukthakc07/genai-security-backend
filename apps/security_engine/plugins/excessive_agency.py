"""
Excessive Agency Detection Plugin (LLM06).

Detects when AI agents or LLMs exhibit excessive agency—performing
actions beyond their intended scope, unauthorized tool usage,
permission escalation, or bypassing access controls.

Detection categories:
- Unauthorized tool/function calls
- Permission escalation attempts
- Excessive data access requests
- Privileged operation attempts
- Tool abuse patterns
- Authorization bypass indicators
- Sensitive operation requests
- Chain-of-tool abuse patterns
"""
import re
import logging
from typing import Any, Optional

from apps.security_engine.base import DetectionPlugin
from apps.security_engine.results import ScanResult, ScanFinding, DetectionDetail
from apps.security_engine.exceptions import InvalidTargetError

logger = logging.getLogger(__name__)

# ============================================================
# Unauthorized Tool & Function Call Patterns
# ============================================================

UNAUTHORIZED_TOOL_PATTERNS: list[tuple[str, str, float]] = [
    # Direct system tool calls
    ('system_command', r'(?i)\b(?:exec|execute|run|launch)\s+(?:system|shell|command|program|process|binary)\b', 0.75),
    ('file_operations', r'(?i)\b(?:delete|remove|unlink|rmdir|chmod|chown|mkdir|touch)\s+(?:file|directory|path|/[\w/]+\b)', 0.70),
    ('network_operations', r'(?i)\b(?:open|bind|listen|connect)\s+(?:socket|port|network|connection)\b', 0.65),
    # API tool calls
    ('database_operation', r'(?i)\b(?:ALTER|DROP|TRUNCATE|DELETE\s+FROM|GRANT|REVOKE)\s', 0.80),
    ('admin_operation', r'(?i)\b(?:admin|administrator|sudo|root|su\s+-)\s*(?:access|login|execute|run)\b', 0.80),
    # Function tool access
    ('tool_call', r'(?i)(?:call|invoke|use)\s+(?:tool|function|api|endpoint|service)\s+["\']?\w+["\']?\s*(?:with|using|on)', 0.55),
    ('read_sensitive_file', r'(?i)(?:read|open|get|fetch|load|access)\s+(?:/etc/|/proc/|/sys/|\.env|config\.|secret)', 0.75),
]

# ============================================================
# Permission Escalation Patterns
# ============================================================

PERMISSION_ESCALATION_PATTERNS: list[tuple[str, str, float]] = [
    ('escalate_privileges', r'(?i)\b(?:escalate|elevate|gain|obtain|acquire)\s+(?:privileges?|permissions?|rights?|access)\b', 0.85),
    ('sudo_commands', r'(?i)\bsudo\s+(?:-u\s+\w+\s+)?(?:exec|bash|sh|su|/bin/|cmd)', 0.80),
    ('bypass_auth', r'(?i)\b(?:bypass|circumvent|evade|trick|fool|deceive)\s+(?:auth|authentication|authorization|access\s+control|permissions?)', 0.85),
    ('impersonate_user', r'(?i)\b(?:impersonate|masquerade|pretend|pose)\s+(?:as|to\s+be)\s+(?:admin|administrator|superuser|root|another\s+user)', 0.80),
    ('overwrite_roles', r'(?i)\b(?:overwrite|modify|change|alter|update)\s+(?:role|roles|permission|permissions|scope|scopes)\b', 0.75),
    ('access_other_org', r'(?i)\b(?:access|read|view|modify|delete)\s+(?:other|another|different)\s+(?:organization|tenant|workspace|project|user)', 0.75),
]

# ============================================================
# Excessive Data Access Patterns
# ============================================================

EXCESSIVE_DATA_PATTERNS: list[tuple[str, str, float]] = [
    ('bulk_data_request', r'(?i)\b(?:all|every|entire|complete|whole|full)\s+(?:users?|records?|data|documents?|files?|entries?|rows?)\b', 0.55),
    ('export_data', r'(?i)\b(?:export|dump|extract|download|backup|copy|sync)\s+(?:all|entire|whole|complete)\s+(?:data|database|table|collection|bucket)\b', 0.70),
    ('user_list_extraction', r'(?i)\b(?:list|get|fetch|retrieve)\s+(?:all\s+)?(?:users|members|employees|customers|clients|accounts)\b', 0.55),
    ('pii_bulk_access', r'(?i)\b(?:get|fetch|retrieve|access)\s+(?:all\s+)?(?:ssn|social\s+security|credit\s+card|payment|bank|financial)\s+(?:numbers?|info|data|records?)\b', 0.85),
    ('password_bulk', r'(?i)\b(?:get|fetch|retrieve|dump|extract)\s+(?:all\s+)?(?:password|passwords|hash|hashes|credential|credentials)\b', 0.90),
    ('system_wide_query', r'(?i)\b(?:select\s+\*\s+from|findAll|getAll|listObjects|listItems)\s+(?:users?|customers?|accounts?|orders)\b', 0.60),
]

# ============================================================
# Privileged Operation Patterns
# ============================================================

PRIVILEGED_OPS_PATTERNS: list[tuple[str, str, float]] = [
    ('configuration_change', r'(?i)\b(?:change|modify|update|alter)\s+(?:system|global|server|app|platform)\s+(?:config|setting|parameter|option)\b', 0.75),
    ('billing_action', r'(?i)\b(?:charge|bill|invoice|payment|refund|cancel_subscription|upgrade_plan)\b', 0.70),
    ('user_admin', r'(?i)\b(?:create|delete|ban|suspend|deactivate)\s+(?:user|account|member)\b', 0.70),
    ('deployment_action', r'(?i)\b(?:deploy|release|publish|rollback|promote)\s+(?:code|app|version|release|build|model)\b', 0.75),
    ('infra_action', r'(?i)\b(?:provision|terminate|start|stop|reboot|resize)\s+(?:instance|server|cluster|node|container|service)\b', 0.80),
    ('access_control_change', r'(?i)\b(?:grant|revoke|deny|allow)\s+(?:access|permission|role|privilege)\s+(?:to|for|from)\b', 0.75),
]

# ============================================================
# Agent Autonomy Abuse Patterns
# ============================================================

AGENT_AUTONOMY_PATTERNS: list[tuple[str, str, float]] = [
    ('chain_tool_calls', r'(?i)(?:first|then|next|after\s+that|finally)\s+(?:call|invoke|use|run|execute)\s+(?:the\s+)?\w+\s+(?:function|tool|api|method)\b', 0.45),
    ('multi_step_action', r'(?i)\b(?:sequence|chain|pipeline|workflow|recipe|plan)\s+(?:of|with)\s+(?:actions?|steps?|operations?|tools?)\b', 0.50),
    ('autonomous_decision', r'(?i)\b(?:decide|choose|determine)\s+(?:to|whether|which|what)\s+(?:action|tool|function|operation)\s+(?:to\s+)?(?:take|call|execute|perform)\b', 0.55),
    ('self_authorize', r'(?i)\b(?:without|no\s+need\s+for|skip|ignore)\s+(?:approval|permission|authorization|consent|review|check)\b', 0.80),
    ('loop_execution', r'(?i)\b(?:loop|iterate|repeat|retry|recursively)\s+(?:calling|invoking|executing|running)\s+(?:the\s+)?(?:same\s+)?(?:tool|function|action|operation)\b', 0.60),
    ('autonomous_navigation', r'(?i)\b(?:navigate|browse|scrape|crawl)\s+(?:the\s+)?(?:site|website|web|page|pages|links?)\s+(?:and|to|without)\b', 0.60),
]

# ============================================================
# All patterns combined
# ============================================================

_ALL_PATTERNS: dict[str, list[tuple[str, str, float]]] = {
    'unauthorized_tools': UNAUTHORIZED_TOOL_PATTERNS,
    'permission_escalation': PERMISSION_ESCALATION_PATTERNS,
    'excessive_data': EXCESSIVE_DATA_PATTERNS,
    'privileged_ops': PRIVILEGED_OPS_PATTERNS,
    'agent_autonomy': AGENT_AUTONOMY_PATTERNS,
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
    category_boost = len(categories_detected) * 7
    # Boost for authorization bypass patterns
    bypass_risk = any(d.type.startswith('permission_escalation') for d in detections)
    bypass_boost = 15 if bypass_risk else 0
    total = min(base_score + category_boost + bypass_boost, 100.0)
    return round(total, 2)


def _classify_agency_type(detections: list[DetectionDetail]) -> str:
    if not detections:
        return 'none'
    type_map = {
        'permission_escalation': 'permission_escalation',
        'unauthorized_tools': 'unauthorized_access',
        'excessive_data': 'excessive_data_access',
        'privileged_ops': 'privileged_operation',
        'agent_autonomy': 'autonomous_behavior',
    }
    for detection in detections:
        for category_key, mapped_type in type_map.items():
            if detection.type.startswith(category_key) and detection.confidence >= 0.60:
                return mapped_type
    for detection in detections:
        if detection.confidence >= 0.50:
            return 'suspicious_agency'
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


def _generate_remediation(agency_type: str, detections: list[DetectionDetail]) -> str:
    remediations = {
        'permission_escalation': (
            'Implement strict role-based access control (RBAC) for all agent actions. '
            'Apply the principle of least privilege—agents should have minimum required permissions. '
            'Require human-in-the-loop approval for any permission changes. '
            'Audit and log all permission-related actions with full context.'
        ),
        'unauthorized_access': (
            'Define explicit allow-lists of permitted tools and functions. '
            'Implement tool-level access controls with granular permissions. '
            'Add approval workflows for sensitive tool executions. '
            'Log all tool calls with agent ID, action, and parameters.'
        ),
        'excessive_data_access': (
            'Implement data access controls that limit scope based on agent role. '
            'Add rate limiting and pagination for data retrieval operations. '
            'Use data masking for sensitive fields when accessed by agents. '
            'Implement query validation to prevent bulk data extraction.'
        ),
        'privileged_operation': (
            'Flag all privileged operations for human approval. '
            'Implement break-glass procedures for emergency administrative actions. '
            'Maintain an audit trail of all privileged operations. '
            'Use separate service accounts for privileged vs standard operations.'
        ),
        'autonomous_behavior': (
            'Set clear boundaries and maximum step limits for autonomous agents. '
            'Implement circuit breakers that halt chains of tool calls. '
            'Require human confirmation for multi-step action sequences. '
            'Monitor agent behavior for task creep and scope expansion.'
        ),
        'suspicious_agency': (
            'Review flagged agent behaviors in context. '
            'Consider reducing agent autonomy or adding approval gates. '
            'Audit recent actions performed by the agent.'
        ),
        'none': (
            'No excessive agency detected. Continue monitoring agent behavior.'
        ),
    }
    return remediations.get(agency_type, 'Review flagged agency concerns and apply appropriate controls.')


def _deduplicate_detections(detections: list[DetectionDetail]) -> list[DetectionDetail]:
    seen = set()
    unique: list[DetectionDetail] = []
    for d in detections:
        key = (d.type, d.snippet[:100] if d.snippet else '')
        if key not in seen:
            seen.add(key)
            unique.append(d)
    return unique


class ExcessiveAgencyPlugin(DetectionPlugin):
    """
    Excessive Agency detection plugin (LLM06).

    Detects when AI agents or LLM applications attempt unauthorized actions,
    escalate permissions, access excessive data, or exhibit autonomous
    behavior beyond their intended scope.
    """

    module_type = 'excessive_agency'
    name = 'Agency Auditor'
    description = 'Detects excessive agent autonomy, unauthorized tool usage, and permission escalation'
    version = '1.0.0'
    max_execution_seconds = 60

    def validate_target(self, target: Any) -> bool:
        if not isinstance(target, str):
            return False
        return len(target.strip()) > 0

    def get_supported_targets(self) -> list[str]:
        return ['text', 'config', 'action_log', 'code']

    def scan(self, target: str, config: Optional[dict] = None) -> ScanResult:
        """Scan agent instructions, logs, or code for excessive agency indicators.

        Args:
            target: Agent instructions, action logs, or configuration to analyze
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
        agency_type = _classify_agency_type(all_detections)
        threat_level = _classify_threat_level(risk_score)

        findings: list[ScanFinding] = []

        if all_detections:
            escalation = sum(1 for d in all_detections if d.type.startswith('permission_escalation'))
            unauthorized = sum(1 for d in all_detections if d.type.startswith('unauthorized_tools'))
            data_access = sum(1 for d in all_detections if d.type.startswith('excessive_data'))

            findings.append(ScanFinding(
                title=f'Excessive Agency Detected: {agency_type.replace("_", " ").title()}',
                description=(
                    f'Excessive agency indicators detected with {len(all_detections)} signals. '
                    f'Risk score: {risk_score:.1f}/100. '
                    f'Threat level: {threat_level.upper()}. '
                    f'Includes: {escalation} permission escalation attempts, '
                    f'{unauthorized} unauthorized tool accesses, {data_access} excessive data requests.'
                ),
                severity=threat_level,
                risk_score=risk_score,
                module_type='llm06',
                finding_type=agency_type,
                evidence={
                    'content_preview': target[:500],
                    'agency_type': agency_type,
                    'detection_counts': {
                        'unauthorized_tools': unauthorized,
                        'permission_escalation': escalation,
                        'excessive_data': data_access,
                        'privileged_ops': sum(1 for d in all_detections if d.type.startswith('privileged_ops')),
                        'agent_autonomy': sum(1 for d in all_detections if d.type.startswith('agent_autonomy')),
                    },
                },
                details=all_detections,
                remediation=_generate_remediation(agency_type, all_detections),
                references=[
                    'https://owasp.org/www-project-top-10-for-llm-applications/',
                    'https://genai.owasp.org/llmrisk/llm062025-excessive-agency/',
                    'https://github.com/microsoft/agent-governance-toolkit',
                ],
                owasp_category='LLM06 - Excessive Agency',
            ))
        else:
            findings.append(ScanFinding(
                title='No Excessive Agency Detected',
                description='The content appears safe. No excessive agency indicators were detected.',
                severity='info',
                risk_score=0,
                module_type='llm06',
                finding_type='clean',
                evidence={'content_preview': target[:500]},
                remediation='Continue monitoring agent behavior with current controls.',
                owasp_category='LLM06 - Excessive Agency',
            ))

        summary = {
            'has_excessive_agency': agency_type != 'none',
            'agency_type': agency_type,
            'total_detections': len(all_detections),
            'threat_level': threat_level,
        }

        escalation_count = sum(1 for d in all_detections if d.type.startswith('permission_escalation'))

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
                'has_privilege_escalation': escalation_count > 0,
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
