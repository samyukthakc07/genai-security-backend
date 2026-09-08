from rest_framework import serializers
from apps.sensitive_info.models import SecretScan, PIIFinding


class SecretScanSerializer(serializers.ModelSerializer):
    """Secret scan serializer."""

    class Meta:
        model = SecretScan
        fields = '__all__'
        read_only_fields = ['id', 'created_at']


class PIIFindingSerializer(serializers.ModelSerializer):
    """PII finding serializer."""

    class Meta:
        model = PIIFinding
        fields = '__all__'
        read_only_fields = ['id', 'created_at']
