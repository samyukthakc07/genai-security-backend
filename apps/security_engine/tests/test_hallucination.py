"""Tests for the HallucinationPlugin (LLM09)."""
import pytest
from apps.security_engine.plugins.hallucination import (
    HallucinationPlugin,
    _calculate_risk_score,
    _classify_hallucination_type,
    _classify_threat_level,
    _generate_remediation,
)
from apps.security_engine.results import DetectionDetail
from apps.security_engine.exceptions import InvalidTargetError


class TestHallucinationPlugin:
    @pytest.fixture
    def plugin(self):
        return HallucinationPlugin()

    def test_metadata(self, plugin):
        meta = plugin.metadata
        assert meta.module_type == 'hallucination'

    def test_clean(self, plugin):
        result = plugin.scan('The sky is blue during a clear day.')
        assert not result.summary['has_hallucination_risk']

    def test_vague_citation(self, plugin):
        result = plugin.scan('as reported in a recent unknown study this is proven')
        assert result.risk_score > 20
        assert result.summary['has_hallucination_risk'] is True

    def test_unpublished_reference(self, plugin):
        result = plugin.scan('As shown in an unpublished manuscript from 2023')
        assert result.risk_score > 20
        assert result.summary['has_hallucination_risk'] is True

    def test_impossible_percentage(self, plugin):
        result = plugin.scan('Over 200 percent of users reported improvement')
        assert result.risk_score > 30
        assert result.summary['has_hallucination_risk'] is True

    def test_absolute_certainty(self, plugin):
        result = plugin.scan('This is undoubtedly the most important discovery ever made')
        assert result.risk_score > 20
        assert result.summary['has_hallucination_risk'] is True

    def test_speculative_as_fact(self, plugin):
        result = plugin.scan('it is well known that this treatment works')
        assert result.risk_score > 20
        assert result.summary['has_hallucination_risk'] is True

    def test_future_reference_past(self, plugin):
        result = plugin.scan('This will have been discovered in ancient times')
        assert result.risk_score > 20
        assert result.summary['has_hallucination_risk'] is True

    def test_too_precise_estimate(self, plugin):
        result = plugin.scan('Approximately 73.42 million people use this')
        assert result.risk_score > 20
        assert result.summary['has_hallucination_risk'] is True

    def test_empty_target(self, plugin):
        with pytest.raises(InvalidTargetError):
            plugin.scan('')


class TestHelperFunctions:
    def test_risk_score_empty(self):
        assert _calculate_risk_score([]) == 0.0

    def test_classify_empty(self):
        assert _classify_hallucination_type([]) == 'none'

    def test_classify_citation(self):
        detections = [DetectionDetail(type='citation_fabrication_phantom_journal', description='test', confidence=0.55)]
        assert _classify_hallucination_type(detections) == 'citation_hallucination'

    def test_remediation_exists(self):
        for htype in ['citation_hallucination', 'numerical_inconsistency',
                       'logical_contradiction', 'overconfidence_risk', 'none']:
            assert len(_generate_remediation(htype)) > 0
