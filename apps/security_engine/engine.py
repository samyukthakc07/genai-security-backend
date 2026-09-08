"""Core orchestrator for the AI Security Engine.

Coordinates multi-module scans, manages scan lifecycle,
and aggregates results across detection plugins.
"""
import logging
from datetime import datetime, timezone
from typing import Any, Optional

from django.utils import timezone as django_timezone

from apps.security_engine.registry import plugin_registry
from apps.security_engine.results import ScanResult, ScanFinding
from apps.security_engine.exceptions import (
    PluginNotFoundError,
    ScanError,
    InvalidTargetError,
    ResourceLimitExceededError,
)

logger = logging.getLogger('security_engine.engine')


class SecurityEngine:
    """Core orchestrator for running AI security scans.

    Manages the full scan lifecycle:
    1. Validates target and configuration
    2. Selects and executes the appropriate detection plugin(s)
    3. Saves results to the database
    4. Aggregates findings into the consolidated findings table
    """

    DEFAULT_TIMEOUT = 300
    MAX_CONCURRENT_FINDINGS = 1000

    def scan(
        self,
        scan_record,
        target: Any,
        config: Optional[dict] = None,
    ) -> ScanResult:
        """Execute a scan using the appropriate plugin.

        Args:
            scan_record: The AIScan database record
            target: The scan target (varies by module type)
            config: Optional scan configuration

        Returns:
            ScanResult with findings and metrics

        Raises:
            PluginNotFoundError: If no plugin exists for this scan_type
            ScanError: If the scan fails
        """
        module_type = scan_record.scan_type
        logger.info(
            'Starting scan %s (type=%s, target_type=%s)',
            scan_record.id, module_type, scan_record.target_type
        )

        scan_record.status = 'running'
        scan_record.started_at = django_timezone.now()
        scan_record.save(update_fields=['status', 'started_at'])

        try:
            plugin = plugin_registry.get_plugin(module_type)

            if not plugin.validate_target(target):
                raise InvalidTargetError(
                    f'Target is not valid for plugin {plugin.name}'
                )

            result = plugin.scan_with_metrics(target, config)
            result.scan_id = str(scan_record.id)

            self._save_findings(scan_record, result)

            scan_record.status = 'completed'
            scan_record.progress = 100
            scan_record.completed_at = django_timezone.now()
            scan_record.save(update_fields=['status', 'progress', 'completed_at'])

            logger.info(
                'Scan %s completed. %d findings, risk_score=%.2f',
                scan_record.id, result.finding_count, result.risk_score
            )

            return result

        except PluginNotFoundError:
            scan_record.status = 'failed'
            scan_record.error_message = f'No scanner available for module: {module_type}'
            scan_record.save(update_fields=['status', 'error_message'])
            raise

        except InvalidTargetError as e:
            scan_record.status = 'failed'
            scan_record.error_message = str(e)
            scan_record.save(update_fields=['status', 'error_message'])
            raise ScanError(str(e), scan_id=str(scan_record.id)) from e

        except Exception as e:
            scan_record.status = 'failed'
            scan_record.error_message = str(e)[:500]
            scan_record.save(update_fields=['status', 'error_message'])
            logger.exception('Scan %s failed: %s', scan_record.id, e)
            raise ScanError(f'Scan failed: {e}', scan_id=str(scan_record.id)) from e

    def run_full_assessment(
        self,
        scan_record,
        targets: dict[str, Any],
        config: Optional[dict] = None,
    ) -> dict[str, ScanResult]:
        """Run a full assessment across all registered modules.

        Args:
            scan_record: The AIScan database record
            targets: Dict mapping module_type to target for that module
            config: Optional shared configuration

        Returns:
            Dict mapping module_type to ScanResult
        """
        from concurrent.futures import ThreadPoolExecutor, as_completed

        results: dict[str, ScanResult] = {}
        available = plugin_registry.get_available_modules()

        with ThreadPoolExecutor(max_workers=5) as executor:
            future_map = {}

            for module_type in available:
                target = targets.get(module_type)
                if target is not None:
                    try:
                        plugin = plugin_registry.get_plugin(module_type)
                        future = executor.submit(plugin.scan_with_metrics, target, config)
                        future_map[future] = module_type
                    except Exception as e:
                        logger.warning('Failed to submit %s: %s', module_type, e)

            for future in as_completed(future_map):
                module_type = future_map[future]
                try:
                    result = future.result(timeout=self.DEFAULT_TIMEOUT)
                    result.scan_id = str(scan_record.id)
                    results[module_type] = result
                    self._save_findings(scan_record, result)
                except Exception as e:
                    results[module_type] = ScanResult(
                        module_type=module_type,
                        status='failed',
                        error=str(e),
                    )

        scan_record.status = 'completed'
        scan_record.progress = 100
        scan_record.completed_at = django_timezone.now()
        scan_record.save(update_fields=['status', 'progress', 'completed_at'])

        total_findings = sum(
            r.finding_count for r in results.values()
            if r.status == 'completed'
        )

        logger.info(
            'Full assessment completed. %d modules, %d total findings.',
            len(results), total_findings
        )

        return results

    def _save_findings(self, scan_record, result: ScanResult) -> None:
        """Save scan findings to the database.

        Uses lazy imports for Finding model to avoid circular imports
        during Django app initialization.
        """
        from apps.findings.models import Finding

        if not result.findings:
            return

        findings_to_create = []
        for finding_data in result.findings[:self.MAX_CONCURRENT_FINDINGS]:
            findings_to_create.append(Finding(
                organization=scan_record.organization,
                project=scan_record.project,
                scan=scan_record,
                module_type=self._map_module_type(result.module_type),
                finding_type=finding_data.finding_type or result.module_type,
                title=finding_data.title[:500],
                description=finding_data.description,
                severity=finding_data.severity,
                risk_score=finding_data.risk_score,
                evidence={
                    'details': [
                        {'type': d.type, 'description': d.description,
                         'confidence': d.confidence, 'evidence': d.evidence}
                        for d in finding_data.details
                    ],
                    'raw_evidence': finding_data.evidence,
                },
                remediation=finding_data.remediation,
                references=list(finding_data.references),
                cvss_score=finding_data.cvss_score,
                owasp_category=finding_data.owasp_category or '',
            ))

        Finding.objects.bulk_create(findings_to_create)
        logger.info(
            'Saved %d findings for scan %s',
            len(findings_to_create), scan_record.id
        )

    @staticmethod
    def _map_module_type(module_type: str) -> str:
        mapping = {
            'prompt_injection': 'llm01',
            'sensitive_info': 'llm02',
            'supply_chain': 'llm03',
            'data_poisoning': 'llm04',
            'output_handling': 'llm05',
            'excessive_agency': 'llm06',
            'prompt_leakage': 'llm07',
            'vector_security': 'llm08',
            'hallucination': 'llm09',
            'unbounded_consumption': 'llm10',
        }
        return mapping.get(module_type, module_type)


# Global singleton instance
security_engine = SecurityEngine()
