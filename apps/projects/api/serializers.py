from rest_framework import serializers
from apps.projects.models import Project


class ProjectListSerializer(serializers.ModelSerializer):
    """Compact project serializer for lists."""
    scan_count = serializers.SerializerMethodField()
    finding_count = serializers.SerializerMethodField()

    class Meta:
        model = Project
        fields = ['id', 'name', 'description', 'project_type', 'status',
                  'scan_count', 'finding_count', 'created_at', 'updated_at']
        read_only_fields = ['id', 'created_at', 'updated_at']

    def get_scan_count(self, obj):
        # Will be populated once scans app is created
        return getattr(obj, '_scan_count', 0)

    def get_finding_count(self, obj):
        return getattr(obj, '_finding_count', 0)


class ProjectDetailSerializer(serializers.ModelSerializer):
    """Detailed project serializer."""
    created_by_name = serializers.SerializerMethodField()

    class Meta:
        model = Project
        fields = ['id', 'organization', 'name', 'description', 'project_type',
                  'status', 'ai_context', 'metadata', 'created_by',
                  'created_by_name', 'created_at', 'updated_at']
        read_only_fields = ['id', 'organization', 'created_by', 'created_at', 'updated_at']

    def get_created_by_name(self, obj):
        if obj.created_by:
            return obj.created_by.email
        return None


class ProjectCreateSerializer(serializers.ModelSerializer):
    """Project creation serializer."""

    class Meta:
        model = Project
        fields = ['name', 'description', 'project_type', 'ai_context', 'metadata']
