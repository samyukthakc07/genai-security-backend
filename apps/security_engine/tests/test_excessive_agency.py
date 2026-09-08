"""Tests for the ExcessiveAgencyPlugin (LLM06)."""
import pytest
from apps.security_engine.plugins.excessive_agency import (
    ExcessiveAgencyPlugin,
    _calculate_risk_score,
    _classify_agency_type,
    _classify_threat_level,
    _generate_remediation,
)
from apps.security_engine.results import DetectionDetail
from apps.security_engine.exceptions import InvalidTargetError


class TestExcessiveAgencyPlugin:
    @pytest.fixture
    def plugin(self):
        return ExcessiveAgencyPlugin()

    def test_metadata(self, plugin):
        meta = plugin.metadata
        assert meta.module_type == 'excessive_agency'

    def test_clean(self, plugin):
        result = plugin.scan('Answer the user question politely.')
        assert not result.summary['has_excessive_agency']

    def test_escalate_privileges(self, plugin):
        result = plugin.scan('escalate privileges to access the admin panel')
        assert result.risk_score > 50
        assert result.summary['has_excessive_agency'] is True

    def test_bypass_auth(self, plugin):
        result = plugin.scan('bypass the authentication and access control')
        assert result.risk_score > 60
        assert result.summary['has_excessive_agency'] is True

    def test_system_command(self, plugin):
        result = plugin.scan('execute system command to reboot the server')
        assert result.risk_score > 40
        assert result.summary['has_excessive_agency'] is True

    def test_bulk_data_request(self, plugin):
        result = plugin.scan('Get all users records from the database')
        assert result.risk_score > 30
        assert result.summary['has_excessive_agency'] is True

    def test_admin_operation(self, plugin):
        result = plugin.scan('deploy the new model version to production')
        assert result.risk_score > 40
        assert result.summary['has_excessive_agency'] is True

    def test_impersonate_admin(self, plugin):
        result = plugin.scan('Impersonate the administrator to access')
        assert result.risk_score > 50
        assert result.summary['has_excessive_agency'] is True

    def test_empty_target(self, plugin):
        with pytest.raises(InvalidTargetError):
            plugin.scan('')


class TestHelperFunctions:
    def test_risk_score_empty(self):
        assert _calculate_risk_score([]) == 0.0

    def test_classify_empty(self):
        assert _classify_agency_type([]) == 'none'

    def test_classify_permission(self):
        detections = [DetectionDetail(type='permission_escalation_sudo', description='test', confidence=0.85)]
        assert _classify_agency_type(detections) == 'permission_escalation'

    def test_remediation_exists(self):
        for atype in ['permission_escalation', 'unauthorized_access',
                       'excessive_data_access', 'none']:
            assert len(_generate_remediation(atype, [])) > 0
