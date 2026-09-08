from rest_framework import serializers
from apps.supply_chain.models import AISBOM, DependencyScan, SDKRiskAssessment


class AISBOMSerializer(serializers.ModelSerializer):
    """AI SBOM serializer."""

    class Meta:
        model = AISBOM
        fields = '__all__'
        read_only_fields = ['id', 'generated_at', 'created_at']


class DependencyScanSerializer(serializers.ModelSerializer):
    """Dependency scan serializer."""

    class Meta:
        model = DependencyScan
        fields = '__all__'
        read_only_fields = ['id', 'created_at']


class SDKRiskAssessmentSerializer(serializers.ModelSerializer):
    """SDK risk assessment serializer."""

    class Meta:
        model = SDKRiskAssessment
        fields = '__all__'
        read_only_fields = ['id', 'created_at']
