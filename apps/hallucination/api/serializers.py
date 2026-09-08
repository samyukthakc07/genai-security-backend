from rest_framework import serializers
from apps.hallucination.models import HallucinationFinding, CitationValidation, ResponseValidation


class HallucinationFindingSerializer(serializers.ModelSerializer):
    """Hallucination finding serializer."""

    class Meta:
        model = HallucinationFinding
        fields = '__all__'
        read_only_fields = ['id', 'created_at']


class CitationValidationSerializer(serializers.ModelSerializer):
    """Citation validation serializer."""

    class Meta:
        model = CitationValidation
        fields = '__all__'
        read_only_fields = ['id', 'created_at']


class ResponseValidationSerializer(serializers.ModelSerializer):
    """Response validation serializer."""

    class Meta:
        model = ResponseValidation
        fields = '__all__'
        read_only_fields = ['id', 'created_at']
