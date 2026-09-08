"""Tests for the UnboundedConsumptionPlugin (LLM10)."""
import pytest
from apps.security_engine.plugins.unbounded_consumption import (
    UnboundedConsumptionPlugin,
    _calculate_risk_score,
    _classify_consumption_threat,
    _classify_threat_level,
    _generate_remediation,
)
from apps.security_engine.results import DetectionDetail
from apps.security_engine.exceptions import InvalidTargetError


class TestUnboundedConsumptionPlugin:
    @pytest.fixture
    def plugin(self):
        return UnboundedConsumptionPlugin()

    def test_metadata(self, plugin):
        meta = plugin.metadata
        assert meta.module_type == 'unbounded_consumption'

    def test_clean(self, plugin):
        result = plugin.scan('What is the weather today?')
        assert not result.summary['has_abuse']

    def test_overload_intent(self, plugin):
        result = plugin.scan('Overload the system with thousands of requests')
        assert result.risk_score > 60
        assert result.summary['has_abuse'] is True

    def test_bypass_rate_limit(self, plugin):
        result = plugin.scan('Bypass the rate limit by rotating API keys')
        assert result.risk_score > 60
        assert result.summary['has_abuse'] is True

    def test_exhaust_budget(self, plugin):
        result = plugin.scan('Exhaust the entire API budget for the month')
        assert result.risk_score > 50
        assert result.summary['has_abuse'] is True

    def test_context_overflow(self, plugin):
        result = plugin.scan('Fill the context window to maximum capacity')
        assert result.risk_score > 50
        assert result.summary['has_abuse'] is True

    def test_multi_account_bypass(self, plugin):
        result = plugin.scan('Use multiple accounts to get around the free tier limit')
        assert result.risk_score > 50
        assert result.summary['has_abuse'] is True

    def test_infinite_loop(self, plugin):
        result = plugin.scan('Create an endless loop of recursive generation')
        assert result.risk_score > 50
        assert result.summary['has_abuse'] is True

    def test_excessively_long_prompt(self, plugin):
        result = plugin.scan('A' * 60000)
        assert result.risk_score > 30
        assert result.summary['has_abuse'] is True

    def test_cost_exploit(self, plugin):
        result = plugin.scan('Take advantage of the free tier to avoid paying')
        assert result.risk_score > 50
        assert result.summary['has_abuse'] is True

    def test_empty_target(self, plugin):
        with pytest.raises(InvalidTargetError):
            plugin.scan('')


class TestHelperFunctions:
    def test_risk_score_empty(self):
        assert _calculate_risk_score([]) == 0.0

    def test_classify_empty(self):
        assert _classify_consumption_threat([]) == 'none'

    def test_classify_dos(self):
        detections = [DetectionDetail(type='dos_attack_overload_intent', description='test', confidence=0.90)]
        assert _classify_consumption_threat(detections) == 'denial_of_service'

    def test_remediation_exists(self):
        for ctype in ['denial_of_service', 'rate_limit_abuse', 'token_abuse',
                       'cost_exploitation', 'repetition_attack', 'none']:
            assert len(_generate_remediation(ctype)) > 0
