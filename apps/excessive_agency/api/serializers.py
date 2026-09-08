from rest_framework import serializers
from apps.excessive_agency.models import AgentPermission, ActionApproval, ToolAccessLog


class AgentPermissionSerializer(serializers.ModelSerializer):
    """Agent permission serializer."""

    class Meta:
        model = AgentPermission
        fields = '__all__'
        read_only_fields = ['id', 'created_at']


class ActionApprovalSerializer(serializers.ModelSerializer):
    """Action approval serializer."""

    class Meta:
        model = ActionApproval
        fields = '__all__'
        read_only_fields = ['id', 'created_at', 'updated_at']


class ToolAccessLogSerializer(serializers.ModelSerializer):
    """Tool access log serializer."""

    class Meta:
        model = ToolAccessLog
        fields = '__all__'
        read_only_fields = ['id', 'executed_at']
