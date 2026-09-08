from rest_framework import serializers
from apps.findings.models import Finding, FindingNote, FindingTrend


class FindingNoteSerializer(serializers.ModelSerializer):
    """Finding note serializer."""
    user_name = serializers.CharField(source='user.get_full_name', read_only=True)

    class Meta:
        model = FindingNote
        fields = ['id', 'finding', 'user', 'user_name', 'content', 'created_at']
        read_only_fields = ['id', 'user', 'created_at']


class FindingSerializer(serializers.ModelSerializer):
    """Full Finding serializer."""
    notes = FindingNoteSerializer(many=True, read_only=True)

    class Meta:
        model = Finding
        fields = '__all__'
        read_only_fields = ['id', 'discovered_at', 'created_at', 'updated_at']


class FindingListSerializer(serializers.ModelSerializer):
    """Lightweight serializer for list views."""
    module_type_display = serializers.CharField(source='get_module_type_display', read_only=True)
    severity_display = serializers.CharField(source='get_severity_display', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)

    class Meta:
        model = Finding
        fields = ['id', 'title', 'module_type', 'module_type_display', 'severity',
                  'severity_display', 'status', 'status_display', 'risk_score',
                  'assigned_to', 'discovered_at', 'created_at']


class FindingTrendSerializer(serializers.ModelSerializer):
    """Finding trend serializer."""

    class Meta:
        model = FindingTrend
        fields = '__all__'
        read_only_fields = ['id']
