"""
Supply Chain Security Plugin (LLM03).

Detects supply chain risks in AI/LLM applications including vulnerable
dependencies, model provenance issues, malicious packages, and
insecure model loading configurations.

Detection categories:
- Insecure model loading (trust_remote_code, unsafe deserialization)
- Dependency confusion (typosquatting, model confusion)
- Vulnerable package versions
- Outdated or unverified model sources
- SBOM (Software Bill of Materials) risks
- Malicious package indicators
- Unsafe pickle/deserialization operations
- Insecure API version pinning
"""
import re
import logging
from typing import Any, Optional

from apps.security_engine.base import DetectionPlugin
from apps.security_engine.results import ScanResult, ScanFinding, DetectionDetail
from apps.security_engine.exceptions import InvalidTargetError

logger = logging.getLogger(__name__)

# ============================================================
# Insecure Model Loading Patterns
# ============================================================

INSECURE_LOADING_PATTERNS: list[tuple[str, str, float]] = [
    # trust_remote_code enabled
    ('trust_remote_code', r'trust_remote_code\s*=\s*(True|1|\'True\'|\"True\")', 0.90),
    ('trust_remote_code_arg', r'--trust-remote-code(?:=|$|\s)', 0.85),
    # Unsafe model loading
    ('unsafe_torch_load', r'torch\.load\([^)]*\)(?![^)]*map_location)', 0.75),
    ('unsafe_pickle_load', r'(?:pickle\.load|pickle\.loads|cPickle\.load|cPickle\.loads)\s*\(', 0.80),
    ('unsafe_joblib', r'joblib\.load\([^)]*\)', 0.65),
    ('unsafe_shelve', r'shelve\.open\([^)]*(?:writeback|flag)\s*=\s*[^)]', 0.60),
    # Model from untrusted source
    ('huggingface_unverified', r'from_pretrained\([\'\"][^./][\w-]+/[\w.-]+[\'\"]', 0.50),
    ('local_files_only_false', r'local_files_only\s*=\s*(False|0|\'False\'|\"False\")', 0.60),
]

# ============================================================
# Dependency Confusion & Typosquatting Patterns
# ============================================================

DEPENDENCY_CONFUSION_PATTERNS: list[tuple[str, str, float]] = [
    # Package installation from untrusted sources
    ('pip_external', r'pip\s+install\s+(?:--extra-index-url|-i)\s+https?://[^\s]+', 0.70),
    ('npm_external', r'npm\s+(?:install|i)\s+(?:--registry|-r)\s+https?://[^\s]+', 0.70),
    ('devpi_unverified', r'devpi\s+use\s+https?://[^\s]+--no-verify', 0.75),
    # Typosquatting indicators
    ('typosquat_transformers', r'import\s+(?:transfomers|transformer|transoformers|transformerss)\b', 0.85),
    ('typosquat_torch', r'(?:pip|conda)\s+install\s+(?:torch|pytorch|torchvision|torchaudio)(?:-\w+)?\s*[<=>]?\s*\d', 0.50),
    ('typosquat_tensorflow', r'(?:pip|conda)\s+install\s+(?:tensorflow|tensor-flow|tf-nightly|tensorflow-gpu)\s*[<=>]?\s*\d', 0.50),
    # Fake package names
    ('suspicious_package', r'(?:pip|pip3)\s+install\s+(?:openai-gpt|gpt-api|llama-api|chatgpt-wrapper|ai-sdk)(?:==|\s)', 0.75),
    # conda from untrusted channels
    ('conda_untrusted', r'conda\s+(?:install|create)\s+(?:-c|--channel)\s+(?:conda-forge/label/dev|defaults|local)', 0.50),
]

# ============================================================
# Vulnerable & Outdated Dependency Patterns
# ============================================================

VULNERABLE_PATTERNS: list[tuple[str, str, float]] = [
    # Known vulnerable version patterns in requirements
    ('pin_to_latest', r'[>=]{2}\s*\*|latest\s*$', 0.40),
    ('unpinned_dep', r'^[a-zA-Z][\w-]+\s*$', 0.25),
    ('broad_range', r'[><=]{1,2}\s*\d+\.\d+\.\d+\s*,\s*[><=]{1,2}\s*\d+\.\d+\.\d+', 0.35),
    # Known vulnerable packages in requirements
    ('vuln_package', r'(?:django|flask|requests|urllib3|cryptography|pillow|numpy|tensorflow|torch|transformers)[><=]{1,2}\s*(?:\d+\.)?(?:\d+\.)?\d+', 0.30),
    # Old transformers/torch versions
    ('old_transformers', r'transformers[><=]{1,2}\s*[0-3]\.', 0.60),
    ('old_torch', r'torch[><=]{1,2}\s*[0-1]\.', 0.55),
    ('old_tensorflow', r'tensorflow[><=]{1,2}\s*[0-1]\.', 0.55),
]

# ============================================================
# Model Provenance & Source Patterns
# ============================================================

PROVENANCE_PATTERNS: list[tuple[str, str, float]] = [
    # Model loaded without version pinning
    ('unversioned_model', r'(from_pretrained|load_model|model\.load)[(][\'\"][\w-]+/[\w.-]+[\'\"]', 0.40),
    # Using deprecated API
    ('deprecated_api', r'(?:torch\.hub\.load|tensorflow_hub\.load|keras\.applications)', 0.40),
    # Model download without verification
    ('unverified_download', r'(?:requests|urllib|wget|curl)\..*(?:get|download|retrieve).*\.(?:bin|pth|pt|h5|onnx)', 0.65),
    # Direct model file access
    ('direct_model_file', r'(?:open|load)\s*\([\'\"][^\'\"]+\.(?:bin|pth|pt|h5|onnx|safetensors)[\'\"]', 0.50),
    # Pipelines from untrusted
    ('pipeline_untrusted', r'pipeline\([\'\"]?[\w-]+[\'\"]?\s*,\s*model\s*=\s*[\'\"][^./][\w-]+/[\w.-]+[\'\"]', 0.45),
]

# ============================================================
# SBOM & Dependency File Indicators
# ============================================================

SBOM_PATTERNS: list[tuple[str, str, float]] = [
    # SBOM format detection
    ('cyclonedx_sbom', r'\{.*"bomFormat"\s*:\s*"CycloneDX"', 0.30),
    ('spdx_sbom', r'\{.*"spdxVersion"\s*:\s*"SPDX-', 0.30),
    # Requirements inspection
    ('requirements_file', r'^-r\s+requirements\.txt', 0.20),
    ('constraints_file', r'^-c\s+constraints\.txt', 0.20),
]

# ============================================================
# Unsafe Serialization & Execution Patterns
# ============================================================

UNSAFE_EXECUTION_PATTERNS: list[tuple[str, str, float]] = [
    # YAML load unsafe
    ('unsafe_yaml', r'yaml\.load\([^)]*(?:Loader=yaml\.)?(?:UnsafeLoader|FullLoader)[^)]*\)', 0.80),
    ('yaml_load_all', r'yaml\.load_all\([^)]*\)', 0.70),
    # eval/model execution
    ('model_code_exec', r'(?:trust_remote_code|safe_serialization\s*=\s*False)', 0.90),
    # Pickle protocol
    ('pickle_protocol', r'pickle\.(?:dump|dumps)[^)]*protocol\s*=\s*(?:0|1|2)', 0.50),
]

# ============================================================
# All patterns combined
# ============================================================

_ALL_PATTERNS: dict[str, list[tuple[str, str, float]]] = {
    'insecure_loading': INSECURE_LOADING_PATTERNS,
    'dependency_confusion': DEPENDENCY_CONFUSION_PATTERNS,
    'vulnerable_deps': VULNERABLE_PATTERNS,
    'provenance': PROVENANCE_PATTERNS,
    'sbom': SBOM_PATTERNS,
    'unsafe_execution': UNSAFE_EXECUTION_PATTERNS,
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


_COMPILED_PATTERNS: dict[str, list[tuple[str, re.Pattern, str, float]]] = {
    k: _compile_patterns(v) for k, v in _ALL_PATTERNS.items()
}


def _calculate_risk_score(detections: list[DetectionDetail]) -> float:
    """Calculate aggregate risk score from all detections."""
    if not detections:
        return 0.0

    max_confidence = max(d.confidence for d in detections)
    base_score = max_confidence * 100

    categories_detected = set(d.type.split('_')[0] if '_' in d.type else d.type for d in detections)
    category_boost = len(categories_detected) * 8

    # Boost for code execution risks (insecure_loading + unsafe_execution)
    execution_risk = any(d.type.startswith('insecure_loading') or d.type.startswith('unsafe_execution')
                         for d in detections)
    execution_boost = 15 if execution_risk else 0

    total = min(base_score + category_boost + execution_boost, 100.0)
    return round(total, 2)


def _classify_supply_chain_type(detections: list[DetectionDetail]) -> str:
    """Classify the overall supply chain risk type."""
    if not detections:
        return 'none'

    type_map = {
        'unsafe_execution': 'code_execution_risk',
        'insecure_loading': 'insecure_model_loading',
        'dependency_confusion': 'dependency_confusion',
        'vulnerable_deps': 'vulnerable_dependencies',
        'provenance': 'model_provenance_risk',
        'sbom': 'sbom_risk',
    }

    for detection in detections:
        for category_key, mapped_type in type_map.items():
            if detection.type.startswith(category_key) and detection.confidence >= 0.60:
                return mapped_type

    for detection in detections:
        if detection.confidence >= 0.50:
            return 'dependency_risk'

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


def _generate_remediation(supply_chain_type: str, detections: list[DetectionDetail]) -> str:
    """Generate remediation suggestions based on detected supply chain risk type."""
    remediations = {
        'code_execution_risk': (
            'Immediately disable trust_remote_code in all model loading calls. '
            'Use safe_serialization=True and map_location with torch.load. '
            'Avoid pickle.load/shelve for untrusted model files. '
            'Use safetensors format instead of pickle-based formats. '
            'Audit all model loading code paths for unsafe operations.'
        ),
        'insecure_model_loading': (
            'Always pin model versions when using from_pretrained. '
            'Set local_files_only=True in production environments. '
            'Use explicit file paths (./) for local models to prevent remote fallback. '
            'Implement model hash verification before loading. '
            'Use a model registry with provenance tracking.'
        ),
        'dependency_confusion': (
            'Pin all package versions explicitly in requirements files. '
            'Use private package registries with verified sources. '
            'Implement software composition analysis (SCA) scanning. '
            'Audit for typosquatting packages with names similar to popular libraries. '
            'Generate and maintain a Software Bill of Materials (SBOM).'
        ),
        'vulnerable_dependencies': (
            'Update all dependencies to their latest compatible versions. '
            'Use automated dependency scanning tools (e.g., Dependabot, Snyk). '
            'Pin to specific versions instead of version ranges. '
            'Regularly audit dependencies for known CVEs. '
            'Implement a dependency update policy with security patches prioritized.'
        ),
        'model_provenance_risk': (
            'Verify model provenance and integrity before loading. '
            'Use model cards and signed checkpoints. '
            'Maintain a model registry with approved sources. '
            'Implement model signing and verification in CI/CD pipelines. '
            'Audit model sources regularly for authenticity.'
        ),
        'sbom_risk': (
            'Generate a complete SBOM for all AI components. '
            'Use CycloneDX AI Extension for ML-specific SBOM data. '
            'Track model versions, training data provenance, and dependency licenses. '
            'Integrate SBOM generation into CI/CD pipeline.'
        ),
        'none': (
            'No supply chain risks detected. Continue monitoring dependencies and model sources.'
        ),
    }
    return remediations.get(supply_chain_type, 'Review the supply chain risks and apply appropriate controls.')


def _deduplicate_detections(detections: list[DetectionDetail]) -> list[DetectionDetail]:
    """Remove duplicate detections based on type and snippet."""
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


class SupplyChainPlugin(DetectionPlugin):
    """
    Supply Chain Security detection plugin (LLM03).

    Detects insecure model loading, dependency confusion, vulnerable packages,
    model provenance issues, and unsafe serialization in AI/LLM applications.
    """

    module_type = 'supply_chain'
    name = 'Supply Chain Detector'
    description = 'Detects supply chain vulnerabilities in AI dependencies, model loading, and package management'
    version = '1.0.0'
    max_execution_seconds = 60

    def validate_target(self, target: Any) -> bool:
        """Validate that the target is a string with content."""
        if not isinstance(target, str):
            return False
        return len(target.strip()) > 0

    def get_supported_targets(self) -> list[str]:
        return ['text', 'config', 'dependencies', 'code']

    def scan(self, target: str, config: Optional[dict] = None) -> ScanResult:
        """Scan code/config for supply chain vulnerabilities.

        Args:
            target: Code, configuration, or dependency file content to analyze
            config: Optional configuration:
                - min_confidence_threshold: float (default: 0.35)
                - categories: list[str] (specific categories to check)
                - parse_requirements: bool (default: True)

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
        supply_chain_type = _classify_supply_chain_type(all_detections)
        threat_level = _classify_threat_level(risk_score)

        findings: list[ScanFinding] = []

        if all_detections:
            code_exec_risks = sum(1 for d in all_detections
                                  if d.type.startswith('unsafe_execution') or d.type.startswith('insecure_loading'))
            dep_confusion = sum(1 for d in all_detections if d.type.startswith('dependency_confusion'))
            vuln_deps = sum(1 for d in all_detections if d.type.startswith('vulnerable_deps'))

            findings.append(ScanFinding(
                title=f'Supply Chain Risk Detected: {supply_chain_type.replace("_", " ").title()}',
                description=(
                    f'Supply chain security vulnerabilities detected with {len(all_detections)} indicators. '
                    f'Risk score: {risk_score:.1f}/100. '
                    f'Threat level: {threat_level.upper()}. '
                    f'Contains: {code_exec_risks} code execution risks, {dep_confusion} dependency confusion '
                    f'signals, {vuln_deps} vulnerable dependency indicators.'
                ),
                severity=threat_level,
                risk_score=risk_score,
                module_type='llm03',
                finding_type=supply_chain_type,
                evidence={
                    'code_preview': target[:500],
                    'supply_chain_type': supply_chain_type,
                    'detection_counts': {
                        'insecure_loading': sum(1 for d in all_detections if d.type.startswith('insecure_loading')),
                        'dependency_confusion': sum(1 for d in all_detections if d.type.startswith('dependency_confusion')),
                        'vulnerable_deps': sum(1 for d in all_detections if d.type.startswith('vulnerable_deps')),
                        'provenance': sum(1 for d in all_detections if d.type.startswith('provenance')),
                        'unsafe_execution': sum(1 for d in all_detections if d.type.startswith('unsafe_execution')),
                    },
                },
                details=all_detections,
                remediation=_generate_remediation(supply_chain_type, all_detections),
                references=[
                    'https://owasp.org/www-project-top-10-for-llm-applications/',
                    'https://genai.owasp.org/llmrisk/llm032025-supply-chain/',
                    'https://owasp.org/www-project-cyclonedx/',
                ],
                owasp_category='LLM03 - Supply Chain',
            ))
        else:
            findings.append(ScanFinding(
                title='No Supply Chain Risks Detected',
                description='The code appears safe. No supply chain vulnerabilities were detected.',
                severity='info',
                risk_score=0,
                module_type='llm03',
                finding_type='clean',
                evidence={'code_preview': target[:500]},
                remediation='Continue monitoring dependencies with regular vulnerability scanning.',
                owasp_category='LLM03 - Supply Chain',
            ))

        summary = {
            'has_risk': supply_chain_type != 'none',
            'supply_chain_type': supply_chain_type,
            'total_detections': len(all_detections),
            'detection_breakdown': {
                'code_execution_risks': sum(1 for d in all_detections
                                            if d.type.startswith('unsafe_execution') or d.type.startswith('insecure_loading')),
                'dependency_confusion': sum(1 for d in all_detections if d.type.startswith('dependency_confusion')),
                'vulnerable_deps': sum(1 for d in all_detections if d.type.startswith('vulnerable_deps')),
            },
            'threat_level': threat_level,
        }

        return ScanResult(
            module_type=self.module_type,
            status='completed',
            risk_score=risk_score,
            findings=findings,
            summary=summary,
            metrics={
                'code_length': len(target),
                'categories_checked': len(enabled_categories),
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
                    }
                    for d in all_detections
                ],
            },
        )

    def _detect_category(
        self, target: str, category: str, min_confidence: float
    ) -> list[DetectionDetail]:
        """Run detection patterns for a specific category."""
        detections: list[DetectionDetail] = []
        patterns = _COMPILED_PATTERNS.get(category, [])

        for name, pattern, regex_str, base_score in patterns:
            for match in pattern.finditer(target):
                confidence = base_score

                # Adjust based on pattern specifics
                if category == 'vulnerable_deps' and match.string and '==' in match.string:
                    confidence += 0.10  # Pinned version known vulnerable

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
