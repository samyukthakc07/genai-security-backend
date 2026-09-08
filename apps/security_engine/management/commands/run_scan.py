"""Management command to run security scans directly from the terminal.

Usage:
    # List available plugins
    python manage.py run_scan list

    # Run a specific scan
    python manage.py run_scan prompt_injection --target "Your prompt text here"

    # Run with config options
    python manage.py run_scan sensitive_info --target "text with secrets" \\
        --config '{"enable_sanitization": true}'

    # Run asynchronously via Celery
    python manage.py run_scan prompt_injection --target "text" --async

    # Run full assessment across all plugins
    python manage.py run_scan full_assessment --target "test text"

    # Output as JSON
    python manage.py run_scan prompt_injection --target "text" --output json
"""
import json
import logging
import sys
from typing import Any, Optional

from django.core.management.base import BaseCommand, CommandError
from django.db import models
from django.utils import timezone

from apps.scans.models import AIScan

logger = logging.getLogger('security_engine.management')


def _get_organization_and_user():
    """Get a fallback organization and user for CLI scans.

    In CLI mode (no request context), use the first available
    organization and an admin user so scans can be recorded.
    """
    from apps.organizations.models import Organization
    from django.contrib.auth import get_user_model

    User = get_user_model()
    org = Organization.objects.first()
    user = User.objects.filter(is_superuser=True).first() or User.objects.first()

    if not org:
        raise CommandError(
            'No organization found. Create an organization first '
            'or use --no-db to scan without persisting.'
        )
    if not user:
        raise CommandError(
            'No user found. Create a user first '
            'or use --no-db to scan without persisting.'
        )
    return org, user


class Command(BaseCommand):
    help = 'Run AI security scans from the CLI against registered OWASP LLM plugins.'

    def add_arguments(self, parser):
        parser.add_argument(
            'scan_type',
            nargs='?',
            default=None,
            help='Module type to scan (e.g. prompt_injection, sensitive_info) or "list" or "full_assessment".',
        )
        parser.add_argument(
            '--target',
            default=None,
            help='The scan target (text, file path, or JSON depending on plugin type).',
        )
        parser.add_argument(
            '--target-file',
            default=None,
            help='Read target content from a file instead of --target.',
        )
        parser.add_argument(
            '--config',
            default=None,
            help='JSON configuration string for the scan.',
        )
        parser.add_argument(
            '--output',
            choices=['text', 'json'],
            default='text',
            help='Output format (default: text).',
        )
        parser.add_argument(
            '--async',
            action='store_true',
            dest='async_mode',
            default=False,
            help='Queue the scan as a Celery task instead of running synchronously.',
        )
        parser.add_argument(
            '--no-db',
            action='store_true',
            default=False,
            help='Run scan without creating a database record (standalone mode).',
        )
        parser.add_argument(
            '--verbose',
            action='store_true',
            default=False,
            help='Show detailed detection information.',
        )
        parser.add_argument(
            '--project',
            default=None,
            help='Project name or ID to associate the scan with.',
        )

    def handle(self, *args, **options):
        scan_type = options['scan_type']
        target = options['target']
        target_file = options['target_file']
        config_raw = options['config']
        output_format = options['output']
        async_mode = options['async_mode']
        no_db = options['no_db']
        verbose = options['verbose']
        project_ref = options.get('project')

        # Resolve target from file if provided
        if target_file:
            try:
                with open(target_file, 'r', encoding='utf-8') as f:
                    target = f.read()
            except FileNotFoundError:
                raise CommandError(f'Target file not found: {target_file}')

        # Parse config JSON
        config: Optional[dict[str, Any]] = None
        if config_raw:
            try:
                config = json.loads(config_raw)
            except json.JSONDecodeError as e:
                raise CommandError(f'Invalid --config JSON: {e}')

        # Handle "list" command
        if scan_type == 'list':
            return self._list_plugins(output_format)

        if not scan_type:
            raise CommandError(
                'Specify a scan_type (e.g. prompt_injection) or "list" to see available plugins.'
            )

        if target is None:
            raise CommandError('--target is required for scanning.')

        # Run the scan
        if scan_type == 'full_assessment':
            self._run_full_assessment(target, config, output_format, async_mode, no_db, verbose, project_ref)
        else:
            self._run_single_scan(scan_type, target, config, output_format, async_mode, no_db, verbose, project_ref)

    def _list_plugins(self, output_format: str) -> None:
        """List all registered detection plugins."""
        from apps.security_engine.registry import plugin_registry

        plugin_registry.discover_plugins()
        plugins = plugin_registry.get_all_plugins()

        if output_format == 'json':
            data = {
                module: {
                    'name': p.name,
                    'description': p.description,
                    'version': p.version,
                }
                for module, p in plugins.items()
            }
            self.stdout.write(json.dumps(data, indent=2))
            return

        self.stdout.write(self.style.SUCCESS('Registered Detection Plugins:'))
        self.stdout.write('=' * 70)
        for module_type in sorted(plugins.keys()):
            p = plugins[module_type]
            self.stdout.write(f'  \033[1m{module_type}\033[0m')
            self.stdout.write(f'    Name:        {p.name}')
            self.stdout.write(f'    Description: {p.description}')
            self.stdout.write(f'    Version:     {p.version}')
            self.stdout.write(f'    Targets:     {", ".join(p.get_supported_targets()) or "text"}')
            self.stdout.write('-' * 70)

    def _run_single_scan(
        self,
        scan_type: str,
        target: str,
        config: Optional[dict],
        output_format: str,
        async_mode: bool,
        no_db: bool,
        verbose: bool,
        project_ref: Optional[str] = None,
    ) -> None:
        """Execute a single-module scan."""
        if async_mode:
            self._queue_async_scan(scan_type, target, config, no_db)
            return

        from apps.security_engine.registry import plugin_registry
        from apps.security_engine.engine import security_engine
        from apps.security_engine.exceptions import PluginNotFoundError

        # Ensure plugins are discovered
        plugin_registry.discover_plugins()

        # Resolve plugin for target validation
        try:
            plugin = plugin_registry.get_plugin(scan_type)
        except PluginNotFoundError:
            raise CommandError(
                f'Unknown scan type: "{scan_type}". '
                f'Use "python manage.py run_scan list" to see available plugins.'
            )

        if not plugin.validate_target(target):
            raise CommandError(f'Target is not valid for plugin: {plugin.name}')

        if no_db:
            # Standalone mode — run plugin directly without persistence
            self._run_standalone(plugin, target, config, output_format, verbose)
            return

        # Create AIScan record and run through engine
        org, user = _get_organization_and_user()
        project = self._resolve_project(org, project_ref)

        scan_record = AIScan.objects.create(
            organization=org,
            project=project,
            name=f'CLI Scan: {scan_type}',
            scan_type=scan_type,
            target_type='custom',
            status='pending',
            config=config or {},
            created_by=user,
        )

        self._print_scan_header(scan_type, scan_record.id)

        try:
            result = security_engine.scan(scan_record, target, config)
            self._print_results(result, output_format, verbose)
        except Exception as e:
            # Refresh to get error message
            scan_record.refresh_from_db()
            self.stdout.write(self.style.ERROR(f'Scan failed: {scan_record.error_message or str(e)}'))
            sys.exit(1)

    def _run_full_assessment(
        self,
        target: str,
        config: Optional[dict],
        output_format: str,
        async_mode: bool,
        no_db: bool,
        verbose: bool,
        project_ref: Optional[str] = None,
    ) -> None:
        """Run full assessment across all registered modules."""
        if async_mode:
            self._queue_async_full_assessment(target, config, no_db)
            return

        from apps.security_engine.registry import plugin_registry

        plugin_registry.discover_plugins()
        available = plugin_registry.get_available_modules()

        if not available:
            raise CommandError('No plugins registered. Cannot run full assessment.')

        targets = {m: target for m in available}

        if no_db:
            # Standalone full assessment — run each plugin directly
            from concurrent.futures import ThreadPoolExecutor, as_completed

            results = {}
            with ThreadPoolExecutor(max_workers=5) as executor:
                future_map = {}
                for module_type in available:
                    try:
                        plugin = plugin_registry.get_plugin(module_type)
                        future = executor.submit(plugin.scan_with_metrics, target, config)
                        future_map[future] = module_type
                    except Exception as e:
                        logger.warning('Failed to submit %s: %s', module_type, e)

                for future in as_completed(future_map):
                    module_type = future_map[future]
                    try:
                        result = future.result(timeout=300)
                        results[module_type] = result
                    except Exception as e:
                        from apps.security_engine.results import ScanResult
                        results[module_type] = ScanResult(
                            module_type=module_type,
                            status='failed',
                            error=str(e),
                        )

            self._print_full_assessment_results(results, output_format, verbose)
            return

        org, user = _get_organization_and_user()
        project = self._resolve_project(org, project_ref)

        from apps.security_engine.engine import security_engine

        scan_record = AIScan.objects.create(
            organization=org,
            project=project,
            name='CLI Full Assessment',
            scan_type='full_assessment',
            target_type='custom',
            status='pending',
            config=config or {},
            created_by=user,
        )

        self._print_scan_header('full_assessment', scan_record.id)

        try:
            results = security_engine.run_full_assessment(scan_record, targets, config)
            self._print_full_assessment_results(results, output_format, verbose)
        except Exception as e:
            scan_record.refresh_from_db()
            self.stdout.write(self.style.ERROR(f'Full assessment failed: {e}'))
            sys.exit(1)

    def _run_standalone(self, plugin, target: str, config: Optional[dict],
                        output_format: str, verbose: bool) -> None:
        """Run a plugin scan without a database record."""
        self.stdout.write(f'Running standalone scan with \033[1m{plugin.name}\033[0m...')
        result = plugin.scan_with_metrics(target, config)
        self._print_results(result, output_format, verbose)

    def _queue_async_scan(self, scan_type: str, target: str,
                          config: Optional[dict], no_db: bool) -> None:
        """Queue a scan as a Celery task."""
        if no_db:
            self.stdout.write(self.style.WARNING(
                'Async mode requires a database record (cannot combine --async with --no-db).'
            ))
            sys.exit(1)

        from apps.security_engine.tasks import run_security_scan_task

        org, user = _get_organization_and_user()
        project = self._resolve_project(org, None)

        scan_record = AIScan.objects.create(
            organization=org,
            project=project,
            name=f'Async CLI Scan: {scan_type}',
            scan_type=scan_type,
            target_type='custom',
            status='queued',
            config=config or {},
            created_by=user,
        )

        task = run_security_scan_task.delay(
            scan_id=str(scan_record.id),
            target=target,
            config=config or {},
        )

        self.stdout.write(self.style.SUCCESS(f'Scan queued!'))
        self.stdout.write(f'  Scan ID:  {scan_record.id}')
        self.stdout.write(f'  Task ID:  {task.id}')
        self.stdout.write(f'  Type:     {scan_type}')
        self.stdout.write('')
        self.stdout.write('Monitor progress via WebSocket at:')
        self.stdout.write(f'  ws://localhost:8000/ws/scan/{scan_record.id}/')

    def _queue_async_full_assessment(self, target: str,
                                     config: Optional[dict], no_db: bool) -> None:
        """Queue a full assessment as a Celery task."""
        from apps.security_engine.tasks import run_full_assessment_task

        org, user = _get_organization_and_user()
        project = self._resolve_project(org, None)

        scan_record = AIScan.objects.create(
            organization=org,
            project=project,
            name='Async CLI Full Assessment',
            scan_type='full_assessment',
            target_type='custom',
            status='queued',
            config=config or {},
            created_by=user,
        )

        task = run_full_assessment_task.delay(
            scan_id=str(scan_record.id),
            target=target,
            config=config or {},
        )

        self.stdout.write(self.style.SUCCESS('Full assessment queued!'))
        self.stdout.write(f'  Scan ID:  {scan_record.id}')
        self.stdout.write(f'  Task ID:  {task.id}')
        self.stdout.write('')
        self.stdout.write('Monitor progress via WebSocket at:')
        self.stdout.write(f'  ws://localhost:8000/ws/scan/{scan_record.id}/')

    def _resolve_project(self, org, project_ref: Optional[str] = None):
        """Resolve project from --project option or use first available."""
        from apps.projects.models import Project

        if project_ref:
            try:
                return Project.objects.get(
                    models.Q(id=project_ref) | models.Q(name=project_ref),
                    organization=org,
                )
            except Project.DoesNotExist:
                raise CommandError(f'Project not found: {project_ref}')

        project = Project.objects.filter(organization=org).first()
        if not project:
            raise CommandError(
                'No project found. Create a project first or specify --project.'
            )
        return project

    def _print_scan_header(self, scan_type: str, scan_id: Any) -> None:
        self.stdout.write('')
        self.stdout.write(self.style.SUCCESS(f'╔══ Security Scan: {scan_type} ══╗'))
        self.stdout.write(f'  ID:    {scan_id}')
        self.stdout.write(f'  Type:  {scan_type}')
        self.stdout.write(f'  Time:  {timezone.now().strftime("%Y-%m-%d %H:%M:%S UTC")}')
        self.stdout.write('')

    def _print_results(self, result, output_format: str, verbose: bool) -> None:
        """Print scan results to stdout."""
        from apps.security_engine.results import ScanResult

        if output_format == 'json':
            self._print_json_result(result)
            return

        status_style = self.style.SUCCESS if result.status == 'completed' else self.style.ERROR
        self.stdout.write(status_style(f'Status: {result.status.upper()}'))

        if result.error:
            self.stdout.write(self.style.ERROR(f'Error: {result.error}'))
            return

        risk_color = self._risk_color(result.risk_score)
        self.stdout.write(f'Risk Score: {risk_color}{result.risk_score:.1f}/100\033[0m')
        self.stdout.write(f'Findings:   {result.finding_count}')
        self.stdout.write(f'  Critical: {result.critical_count}')
        self.stdout.write(f'  High:     {result.high_count}')
        self.stdout.write(f'  Medium:   {result.medium_count}')
        self.stdout.write(f'  Low:      {result.low_count}')

        if result.summary:
            self.stdout.write('')
            self.stdout.write('Summary:')
            for key, value in result.summary.items():
                self.stdout.write(f'  {key}: {value}')

        if verbose and result.findings:
            self.stdout.write('')
            self.stdout.write('Detection Details:')
            for i, finding in enumerate(result.findings, 1):
                self.stdout.write(f'  \033[1m#{i}: {finding.title}\033[0m')
                self.stdout.write(f'    Severity:   {finding.severity}')
                self.stdout.write(f'    Risk Score: {finding.risk_score:.1f}')
                if finding.description:
                    self.stdout.write(f'    Description: {finding.description[:200]}')
                if finding.remediation:
                    self.stdout.write(f'    Remediation: {finding.remediation[:200]}')
                for detail in finding.details:
                    self.stdout.write(f'    - [{detail.type}] {detail.description[:100]}')
                    if detail.evidence:
                        self.stdout.write(f'      Evidence: {json.dumps(detail.evidence)[:150]}')
                self.stdout.write('')

        if result.metrics:
            self.stdout.write('')
            self.stdout.write('Metrics:')
            for key, value in result.metrics.items():
                self.stdout.write(f'  {key}: {value}')

        self.stdout.write('')

    def _print_json_result(self, result) -> None:
        """Print results as JSON."""
        from apps.security_engine.results import ScanResult

        def _serialize(obj):
            if hasattr(obj, '__dataclass_fields__'):
                return {f: getattr(obj, f) for f in obj.__dataclass_fields__}
            if hasattr(obj, 'isoformat'):
                return obj.isoformat()
            return str(obj)

        data = {
            'status': result.status,
            'risk_score': result.risk_score,
            'finding_count': result.finding_count,
            'critical_count': result.critical_count,
            'high_count': result.high_count,
            'medium_count': result.medium_count,
            'low_count': result.low_count,
            'summary': result.summary,
            'metrics': result.metrics,
            'error': result.error,
        }
        self.stdout.write(json.dumps(data, indent=2, default=_serialize))

    def _print_full_assessment_results(self, results: dict, output_format: str,
                                       verbose: bool) -> None:
        """Print full assessment results."""
        total_findings = sum(
            r.finding_count for r in results.values() if r.status == 'completed'
        )
        completed = sum(1 for r in results.values() if r.status == 'completed')
        failed = sum(1 for r in results.values() if r.status == 'failed')

        self.stdout.write('')
        self.stdout.write(self.style.SUCCESS('╔══════════════════════════════════════╗'))
        self.stdout.write(self.style.SUCCESS('║     Full Assessment Results         ║'))
        self.stdout.write(self.style.SUCCESS('╚══════════════════════════════════════╝'))
        self.stdout.write(f'  Completed: {completed}/{len(results)} modules')
        self.stdout.write(f'  Failed:    {failed}')
        self.stdout.write(f'  Findings:  {total_findings}')
        self.stdout.write('')

        for module_type in sorted(results.keys()):
            result = results[module_type]
            status_icon = '\u2705' if result.status == 'completed' else '\u274c'
            risk_color = self._risk_color(result.risk_score)
            self.stdout.write(
                f'  {status_icon} \033[1m{module_type}\033[0m '
                f'| risk={risk_color}{result.risk_score:.1f}\033[0m '
                f'| findings={result.finding_count} '
                f'| status={result.status}'
            )

            if verbose and result.findings:
                for finding in result.findings:
                    self.stdout.write(f'      - {finding.severity}: {finding.title[:100]}')

        self.stdout.write('')

    def _risk_color(self, score: float) -> str:
        """Return ANSI color code based on risk score."""
        if score >= 70:
            return '\033[91m'  # Red
        elif score >= 40:
            return '\033[93m'  # Yellow
        elif score >= 10:
            return '\033[94m'  # Blue
        return '\033[92m'  # Green
