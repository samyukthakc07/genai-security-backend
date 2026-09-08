"""Abstract base class for AI Security detection plugins."""
from abc import ABC, abstractmethod
from typing import Any, Optional

from apps.security_engine.results import ScanResult, PluginMetadata
from apps.security_engine.exceptions import PluginExecutionError


class DetectionPlugin(ABC):
    """Abstract base class that all detection plugins must implement.

    Each plugin corresponds to one OWASP LLM module and provides
    the actual security detection logic for that category.
    """

    # Override in subclass with module metadata
    module_type: str = ''
    name: str = ''
    description: str = ''
    version: str = '1.0.0'
    requires_network: bool = False
    requires_file_access: bool = False
    max_execution_seconds: int = 120

    def __init__(self):
        self._validate_metadata()

    def _validate_metadata(self) -> None:
        """Ensure plugin defines required metadata."""
        if not self.module_type:
            raise ValueError(f'{type(self).__name__} must define module_type')
        if not self.name:
            raise ValueError(f'{type(self).__name__} must define name')

    @property
    def metadata(self) -> PluginMetadata:
        """Return metadata about this plugin."""
        return PluginMetadata(
            module_type=self.module_type,
            name=self.name,
            description=self.description,
            version=self.version,
            requires_network=self.requires_network,
            requires_file_access=self.requires_file_access,
            max_execution_seconds=self.max_execution_seconds,
        )

    @abstractmethod
    def scan(self, target: Any, config: Optional[dict] = None) -> ScanResult:
        """Execute a security scan against the given target.

        Args:
            target: The scan target (text, model reference, config, etc.)
            config: Optional scan configuration parameters

        Returns:
            ScanResult containing findings and metrics

        Raises:
            PluginExecutionError: If the scan fails unexpectedly
            InvalidTargetError: If the target is not supported
        """
        ...

    @abstractmethod
    def validate_target(self, target: Any) -> bool:
        """Validate that the target is suitable for this plugin.

        Args:
            target: The target to validate

        Returns:
            True if the target is valid, False otherwise
        """
        ...

    def get_supported_targets(self) -> list[str]:
        """Return list of supported target types."""
        return []

    def cleanup(self) -> None:
        """Cleanup any resources held by the plugin.
        Override if the plugin holds open files, connections, etc.
        """
        pass

    def scan_with_metrics(self, target: Any, config: Optional[dict] = None) -> ScanResult:
        """Wrapper around scan() that adds timing and error handling metrics.

        The plugin's own scan() method is the authoritative source for risk_score.
        This wrapper only adds timing and error handling without overriding the
        plugin's calculated risk score.
        """
        from datetime import datetime, timezone
        import logging

        logger = logging.getLogger(f'security_engine.{self.module_type}')
        result = ScanResult(
            module_type=self.module_type,
            started_at=datetime.now(timezone.utc),
        )

        try:
            scan_result = self.scan(target, config)
            # Copy all fields from the plugin's result — plugin is authoritative
            result.findings = scan_result.findings
            result.risk_score = scan_result.risk_score
            result.summary = scan_result.summary
            result.metrics = scan_result.metrics
            result.raw_data = scan_result.raw_data
            result.status = scan_result.status

        except Exception as e:
            logger.exception(f'Plugin {self.module_type} failed: {e}')
            result.status = 'failed'
            result.error = str(e)
            raise PluginExecutionError(self.module_type, str(e)) from e

        finally:
            result.completed_at = datetime.now(timezone.utc)

        return result
