from rest_framework import serializers
from apps.output_handling.models import OutputSanitization, XSSFinding, UnsafeCodeFinding


class OutputSanitizationSerializer(serializers.ModelSerializer):
    """Output sanitization serializer."""

    class Meta:
        model = OutputSanitization
        fields = '__all__'
        read_only_fields = ['id', 'created_at']


class XSSFindingSerializer(serializers.ModelSerializer):
    """XSS finding serializer."""

    class Meta:
        model = XSSFinding
        fields = '__all__'
        read_only_fields = ['id', 'created_at']


class UnsafeCodeFindingSerializer(serializers.ModelSerializer):
    """Unsafe code finding serializer."""

    class Meta:
        model = UnsafeCodeFinding
        fields = '__all__'
        read_only_fields = ['id', 'created_at']
