"""Data classes for security scan results and findings."""
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional


@dataclass
class DetectionDetail:
    """A single detection detail within a finding."""
    type: str
    description: str
    confidence: float = 0.0
    evidence: dict[str, Any] = field(default_factory=dict)
    location: Optional[str] = None
    snippet: Optional[str] = None


@dataclass
class ScanFinding:
    """A single finding discovered during a security scan."""
    title: str
    description: str
    severity: str  # critical, high, medium, low, info
    risk_score: float = 0.0
    module_type: str = ''
    finding_type: str = ''
    evidence: dict[str, Any] = field(default_factory=dict)
    details: list[DetectionDetail] = field(default_factory=list)
    remediation: Optional[str] = None
    references: list[str] = field(default_factory=list)
    cvss_score: Optional[float] = None
    owasp_category: Optional[str] = None


@dataclass
class ScanResult:
    """Aggregated result of a security scan."""
    scan_id: Optional[str] = None
    module_type: str = ''
    status: str = 'completed'  # completed, partial, failed
    risk_score: float = 0.0
    findings: list[ScanFinding] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)
    metrics: dict[str, Any] = field(default_factory=dict)
    raw_data: dict[str, Any] = field(default_factory=dict)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error: Optional[str] = None

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == 'critical')

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == 'high')

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == 'medium')

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == 'low')


@dataclass
class PluginMetadata:
    """Metadata about a detection plugin."""
    module_type: str
    name: str
    description: str
    version: str = '1.0.0'
    author: str = 'GenAI Security Platform'
    requires_network: bool = False
    requires_file_access: bool = False
    supported_targets: list[str] = field(default_factory=list)
    max_execution_seconds: int = 120
    config_schema: dict[str, Any] = field(default_factory=dict)
