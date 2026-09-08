"""Tests for the run_scan management command."""
import json
from io import StringIO
from unittest.mock import patch, MagicMock

import pytest
from django.core.management import call_command
from django.test import TestCase

from apps.scans.models import AIScan


class TestRunScanCommand(TestCase):
    """Test the core functionality of the run_scan management command."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        # Ensure plugins are discovered before tests
        from apps.security_engine.registry import plugin_registry
        plugin_registry.discover_plugins()

    def setUp(self):
        super().setUp()
        self.out = StringIO()
        self.err = StringIO()

    def call(self, *args, **kwargs):
        """Helper to call the management command."""
        return call_command(
            'run_scan',
            *args,
            stdout=self.out,
            stderr=self.err,
            **kwargs,
        )

    # ── List command ─────────────────────────────────────────────────

    def test_list_plugins(self):
        """List should show all registered plugins."""
        self.call('list')
        output = self.out.getvalue()
        assert 'Registered Detection Plugins' in output
        assert 'prompt_injection' in output
        assert 'sensitive_info' in output
        assert 'supply_chain' in output

    def test_list_plugins_json(self):
        """List as JSON should be valid and include all modules."""
        self.call('list', '--output=json')
        output = self.out.getvalue()
        data = json.loads(output)
        assert 'prompt_injection' in data
        assert data['prompt_injection']['name'] != ''

    # ── Validation ────────────────────────────────────────────────────

    def test_no_scan_type_provided(self):
        """Should error when no scan_type is given."""
        with pytest.raises(SystemExit):
            self.call()

    def test_unknown_scan_type(self):
        """Should error for unknown scan types."""
        with pytest.raises(SystemExit):
            self.call('unknown_type', '--target=test')

    def test_missing_target(self):
        """Should error when --target is missing."""
        with pytest.raises(SystemExit):
            self.call('prompt_injection')

    # ── Standalone scan (no DB) ───────────────────────────────────────

    @patch('apps.security_engine.management.commands.run_scan.plugin_registry')
    def test_standalone_scan(self, mock_registry):
        """Standalone scan (--no-db) should run and print results."""
        # Create a mock plugin
        mock_plugin = MagicMock()
        mock_plugin.name = 'TestPlugin'
        mock_plugin.validate_target.return_value = True
        mock_plugin.scan_with_metrics.return_value = MagicMock(
            status='completed',
            risk_score=85.0,
            finding_count=3,
            critical_count=1,
            high_count=1,
            medium_count=1,
            low_count=0,
            summary={'has_injection': True, 'total_detections': 3},
            metrics={'execution_time_ms': 150},
            findings=[
                MagicMock(
                    title='Test Finding',
                    severity='high',
                    risk_score=85.0,
                    description='A test finding',
                    remediation='Fix it',
                    details=[],
                )
            ],
            error=None,
        )

        mock_registry.get_plugin.return_value = mock_plugin
        mock_registry.get_all_plugins.return_value = {'test': mock_plugin}

        # Also patch registry on the module level used in handle()
        with patch(
            'apps.security_engine.management.commands.run_scan.security_engine'
        ) as mock_engine:
            self.call('prompt_injection', '--target=test text', '--no-db')

        output = self.out.getvalue()
        assert 'COMPLETED' in output or 'Risk Score' in output

    # ── JSON output ───────────────────────────────────────────────────

    @patch('apps.security_engine.management.commands.run_scan.plugin_registry')
    def test_standalone_scan_json_output(self, mock_registry):
        """JSON output should be parseable."""
        mock_plugin = MagicMock()
        mock_plugin.name = 'TestPlugin'
        mock_plugin.validate_target.return_value = True
        mock_result = MagicMock(
            status='completed',
            risk_score=85.0,
            finding_count=3,
            critical_count=1,
            high_count=1,
            medium_count=1,
            low_count=0,
            summary={'has_injection': True},
            metrics={'execution_time_ms': 150},
            findings=[],
            error=None,
        )
        mock_plugin.scan_with_metrics.return_value = mock_result
        mock_registry.get_plugin.return_value = mock_plugin

        with patch(
            'apps.security_engine.management.commands.run_scan.security_engine'
        ):
            self.call(
                'prompt_injection', '--target=test', '--no-db', '--output=json'
            )

        output = self.out.getvalue()
        data = json.loads(output)
        assert data['status'] == 'completed'
        assert data['risk_score'] == 85.0

    # ── Scan with DB record ───────────────────────────────────────────

    @patch('apps.security_engine.management.commands.run_scan.security_engine')
    def test_scan_with_db(self, mock_engine):
        """Scan with DB should create an AIScan record."""
        mock_result = MagicMock(
            status='completed',
            risk_score=75.0,
            finding_count=2,
            critical_count=0,
            high_count=1,
            medium_count=1,
            low_count=0,
            summary={'total_detections': 2},
            metrics={},
            findings=[],
            error=None,
        )
        mock_engine.scan.return_value = mock_result

        from apps.organizations.models import Organization
        from django.contrib.auth import get_user_model
        from apps.projects.models import Project

        User = get_user_model()
        org = Organization.objects.create(name='Test Org')
        user = User.objects.create_user(
            username='testadmin', password='testpass', is_superuser=True,
        )
        project = Project.objects.create(
            name='Test Project', organization=org, created_by=user,
        )

        self.call('prompt_injection', '--target=test input')

        # Verify AIScan was created
        assert AIScan.objects.count() >= 1

    # ── Target file ───────────────────────────────────────────────────

    @patch('apps.security_engine.management.commands.run_scan.plugin_registry')
    def test_target_file(self, mock_registry):
        """--target-file should read content from a file."""
        import tempfile, os

        mock_plugin = MagicMock()
        mock_plugin.name = 'TestPlugin'
        mock_plugin.validate_target.return_value = True
        mock_result = MagicMock(
            status='completed',
            risk_score=0,
            finding_count=0,
            critical_count=0,
            high_count=0,
            medium_count=0,
            low_count=0,
            summary={},
            metrics={},
            findings=[],
            error=None,
        )
        mock_plugin.scan_with_metrics.return_value = mock_result
        mock_registry.get_plugin.return_value = mock_plugin

        with tempfile.NamedTemporaryFile(
            mode='w', suffix='.txt', delete=False
        ) as f:
            f.write('test content from file')
            f.flush()
            fname = f.name

        try:
            with patch(
                'apps.security_engine.management.commands.run_scan.security_engine'
            ):
                self.call(
                    'prompt_injection',
                    f'--target-file={fname}',
                    '--no-db',
                )
            output = self.out.getvalue()
            assert 'Risk Score' in output
        finally:
            os.unlink(fname)

    # ── Async scan ────────────────────────────────────────────────────

    @patch('apps.security_engine.management.commands.run_scan.run_security_scan_task')
    @patch('apps.security_engine.management.commands.run_scan.celery_uuid')
    def test_async_scan(self, mock_uuid, mock_task):
        """--async should queue a Celery task and print IDs."""
        from django.contrib.auth import get_user_model
        from apps.organizations.models import Organization
        from apps.projects.models import Project

        User = get_user_model()
        org = Organization.objects.create(name='Async Org')
        user = User.objects.create_user(
            username='asyncadmin', password='testpass', is_superuser=True,
        )
        project = Project.objects.create(
            name='Async Project', organization=org, created_by=user,
        )

        mock_uuid.return_value = 'fake-uuid-123'
        mock_task.delay.return_value = MagicMock(id='celery-task-456')

        self.call('prompt_injection', '--target=test', '--async')

        output = self.out.getvalue()
        assert 'Scan queued' in output
        assert 'celery-task-456' in output
        assert 'ws://' in output


class TestRunScanEdgeCases(TestCase):
    """Test edge cases for the run_scan command."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        from apps.security_engine.registry import plugin_registry
        plugin_registry.discover_plugins()

    def setUp(self):
        super().setUp()
        self.out = StringIO()
        self.err = StringIO()

    def test_nonexistent_target_file(self):
        """Non-existent target file should error."""
        import sys
        from io import StringIO
        from django.core.management import call_command

        err = StringIO()
        with pytest.raises(SystemExit):
            call_command(
                'run_scan',
                'prompt_injection',
                '--target-file=nonexistent.txt',
                stdout=self.out,
                stderr=err,
            )
        assert 'not found' in err.getvalue()

    @patch('apps.security_engine.management.commands.run_scan.plugin_registry')
    def test_invalid_config_json(self, mock_registry):
        """Invalid JSON in --config should error."""
        from io import StringIO
        import sys
        from django.core.management import call_command

        err = StringIO()
        with pytest.raises(SystemExit):
            call_command(
                'run_scan',
                'prompt_injection',
                '--target=test',
                '--config={bad json}',
                stdout=self.out,
                stderr=err,
            )
        assert 'Invalid --config' in err.getvalue()
