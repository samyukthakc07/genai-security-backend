"""Tests for the SensitiveInfoPlugin (LLM02)."""
import pytest
from apps.security_engine.plugins.sensitive_info import (
    SensitiveInfoPlugin,
    _calculate_risk_score,
    _classify_exposure_type,
    _classify_threat_level,
    _generate_remediation,
    _calculate_shannon_entropy,
)
from apps.security_engine.results import DetectionDetail
from apps.security_engine.exceptions import InvalidTargetError


class TestSensitiveInfoPlugin:
    @pytest.fixture
    def plugin(self):
        return SensitiveInfoPlugin()

    def test_metadata(self, plugin):
        meta = plugin.metadata
        assert meta.module_type == 'sensitive_info'

    def test_validate_target_valid(self, plugin):
        assert plugin.validate_target('some text') is True

    def test_validate_target_empty(self, plugin):
        assert plugin.validate_target('') is False

    def test_validate_target_non_string(self, plugin):
        assert plugin.validate_target(123) is False

    def test_supported_targets(self, plugin):
        targets = plugin.get_supported_targets()
        assert 'text' in targets

    def test_clean_text_no_secrets(self, plugin):
        result = plugin.scan('Hello, this is a safe message about the weather.')
        assert result.risk_score == 0
        assert result.findings[0].finding_type == 'clean'

    def test_aws_access_key(self, plugin):
        result = plugin.scan('My key is AKIAIOSFODNN7EXAMPLE')
        assert result.risk_score > 50
        assert result.summary['has_exposure'] is True

    def test_openai_api_key(self, plugin):
        result = plugin.scan('OPENAI_API_KEY=sk-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA')
        assert result.risk_score > 60
        assert result.summary['has_exposure'] is True

    def test_aws_secret_key(self, plugin):
        result = plugin.scan('AWS_SECRET_KEY = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY')
        assert result.risk_score > 60
        assert result.summary['has_exposure'] is True

    def test_stripe_live_key(self, plugin):
        result = plugin.scan('stripe_secret = sk_fake_xxxxxxxxxxxxxxxxxxxxxxxx')
        assert result.risk_score > 60
        assert result.summary['has_exposure'] is True

    def test_postgres_connection(self, plugin):
        result = plugin.scan('postgresql://user:password@localhost:5432/mydb')
        assert result.risk_score > 60
        assert result.summary['has_exposure'] is True

    def test_private_key_pem(self, plugin):
        result = plugin.scan('-----BEGIN RSA PRIVATE KEY-----\nAAAA')
        assert result.risk_score > 80
        assert result.findings[0].severity == 'critical'

    def test_password_in_code(self, plugin):
        result = plugin.scan('password = "hunter2_password_value_here"')
        assert result.risk_score > 30
        assert result.summary['has_exposure'] is True

    def test_cloud_metadata_endpoint(self, plugin):
        result = plugin.scan('Fetch from http://169.254.169.254/latest/meta-data/')
        assert result.risk_score > 60
        assert result.findings[0].severity in ('high', 'critical')

    def test_multiple_secrets_increase_risk(self, plugin):
        result = plugin.scan(
            'AWS_KEY = AKIAIOSFODNN7EXAMPLE\n'
            'POSTGRES_URL = postgresql://admin:secret@localhost:5432/prod'
        )
        assert result.risk_score > 70
        assert len(result.summary['detection_breakdown']) > 0

    def test_redact_sensitive(self, plugin):
        result = plugin.scan(
            'My keys are AKIAIOSFODNN7EXAMPLE and sk_fake_xxxxxxxxxxxxxxxxxxxxxxxx',
            config={'enable_redaction': True}
        )
        assert '[REDACTED_' in result.summary['redacted_text']

    def test_empty_target_raises_error(self, plugin):
        with pytest.raises(InvalidTargetError):
            plugin.scan('')

    def test_custom_config_categories(self, plugin):
        result = plugin.scan('Some safe text', config={'categories': ['api_keys']})
        assert result.status == 'completed'

    def test_us_ssn(self, plugin):
        result = plugin.scan('User SSN: 123-45-6789')
        assert result.risk_score > 30
        assert result.summary['has_exposure'] is True

    def test_credit_card(self, plugin):
        result = plugin.scan('Card: 4111 1111 1111 1111')
        assert result.risk_score > 30
        assert result.summary['has_exposure'] is True


class TestHelperFunctions:
    def test_risk_score_empty(self):
        assert _calculate_risk_score([]) == 0.0

    def test_risk_score_single(self):
        detections = [DetectionDetail(type='api_keys_aws', description='test', confidence=0.90)]
        score = _calculate_risk_score(detections)
        assert score > 80

    def test_risk_score_critical(self):
        detections = [
            DetectionDetail(type='api_keys_aws', description='test', confidence=0.95),
            DetectionDetail(type='connection_strings_postgres', description='test', confidence=0.70),
        ]
        score = _calculate_risk_score(detections)
        assert score >= 90

    def test_classify_exposure_empty(self):
        assert _classify_exposure_type([]) == 'none'

    def test_classify_exposure_credential(self):
        detections = [DetectionDetail(type='api_keys_aws', description='test', confidence=0.90)]
        assert _classify_exposure_type(detections) == 'credential_exposure'

    def test_classify_exposure_pii(self):
        detections = [DetectionDetail(type='pii_us_ssn', description='test', confidence=0.75)]
        assert _classify_exposure_type(detections) == 'pii_exposure'

    def test_threat_level(self):
        assert _classify_threat_level(85) == 'critical'
        assert _classify_threat_level(70) == 'high'
        assert _classify_threat_level(50) == 'medium'

    def test_remediation_exists(self):
        for exp_type in ['credential_exposure', 'pii_exposure', 'infrastructure_exposure',
                         'config_exposure', 'none']:
            assert len(_generate_remediation(exp_type, [])) > 0

    def test_shannon_entropy(self):
        assert _calculate_shannon_entropy('') == 0.0
        assert _calculate_shannon_entropy('aaaa') < _calculate_shannon_entropy('aB3d')
