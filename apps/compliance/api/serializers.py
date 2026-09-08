from rest_framework import serializers
from apps.compliance.models import (
    ComplianceFramework, ComplianceControl, ComplianceMapping,
    ComplianceCheckResult, ComplianceReport
)


class ComplianceControlSerializer(serializers.ModelSerializer):
    """Compliance control serializer."""

    class Meta:
        model = ComplianceControl
        fields = '__all__'
        read_only_fields = ['id', 'created_at']


class ComplianceFrameworkSerializer(serializers.ModelSerializer):
    """Full framework serializer with controls."""
    controls = ComplianceControlSerializer(many=True, read_only=True)

    class Meta:
        model = ComplianceFramework
        fields = '__all__'
        read_only_fields = ['id', 'created_at']


class ComplianceFrameworkListSerializer(serializers.ModelSerializer):
    """Lightweight framework serializer."""

    class Meta:
        model = ComplianceFramework
        fields = ['id', 'name', 'short_name', 'version', 'total_controls', 'is_active']


class ComplianceMappingSerializer(serializers.ModelSerializer):
    """Compliance mapping serializer."""

    class Meta:
        model = ComplianceMapping
        fields = '__all__'
        read_only_fields = ['id', 'created_at']


class ComplianceCheckResultSerializer(serializers.ModelSerializer):
    """Compliance check result serializer."""

    class Meta:
        model = ComplianceCheckResult
        fields = '__all__'
        read_only_fields = ['id', 'checked_at']


class ComplianceReportSerializer(serializers.ModelSerializer):
    """Compliance report serializer."""

    class Meta:
        model = ComplianceReport
        fields = '__all__'
        read_only_fields = ['id', 'generated_at']


class ComplianceReportListSerializer(serializers.ModelSerializer):
    """Lightweight report serializer."""
    framework_name = serializers.CharField(source='framework.name', read_only=True)

    class Meta:
        model = ComplianceReport
        fields = ['id', 'name', 'report_type', 'framework', 'framework_name',
                  'overall_score', 'generated_at', 'created_by']
