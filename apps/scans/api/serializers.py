from rest_framework import serializers
from apps.scans.models import AIScan


class AIScanSerializer(serializers.ModelSerializer):
    """Full AIScan serializer."""
    findings_count = serializers.SerializerMethodField()

    class Meta:
        model = AIScan
        fields = '__all__'
        read_only_fields = ['id', 'created_at', 'updated_at']

    def get_findings_count(self, obj):
        return obj.findings.count()


class AIScanListSerializer(serializers.ModelSerializer):
    """Lightweight serializer for list views."""
    scan_type_display = serializers.CharField(source='get_scan_type_display', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    target_type_display = serializers.CharField(source='get_target_type_display', read_only=True)
    findings_count = serializers.SerializerMethodField()

    class Meta:
        model = AIScan
        fields = ['id', 'name', 'scan_type', 'scan_type_display', 'status', 'status_display',
                  'target_type', 'target_type_display', 'progress', 'started_at',
                  'completed_at', 'created_by', 'created_at', 'findings_count']

    def get_findings_count(self, obj):
        return obj.findings.count()


class AIScanCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating scans."""

    class Meta:
        model = AIScan
        fields = ['id', 'name', 'scan_type', 'target_type', 'target_id', 'config',
                  'organization', 'project']

    def create(self, validated_data):
        validated_data['created_by'] = self.context['request'].user
        return super().create(validated_data)
