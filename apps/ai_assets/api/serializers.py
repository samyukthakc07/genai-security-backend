from rest_framework import serializers
from apps.ai_assets.models import AIModel, AIAgent, RAGSystem, VectorDatabase


class AIModelSerializer(serializers.ModelSerializer):
    """AI Model serializer."""

    class Meta:
        model = AIModel
        fields = '__all__'
        read_only_fields = ['id', 'created_at', 'updated_at']


class AIModelListSerializer(serializers.ModelSerializer):
    """Lightweight serializer for list views."""
    model_type_display = serializers.CharField(source='get_model_type_display', read_only=True)

    class Meta:
        model = AIModel
        fields = ['id', 'name', 'model_type', 'model_type_display', 'model_family',
                  'version', 'risk_score', 'is_active', 'last_scanned_at', 'created_at']


class AIAgentSerializer(serializers.ModelSerializer):
    """AI Agent serializer."""

    class Meta:
        model = AIAgent
        fields = '__all__'
        read_only_fields = ['id', 'created_at', 'updated_at']


class AIAgentListSerializer(serializers.ModelSerializer):
    """Lightweight serializer for list views."""
    agent_type_display = serializers.CharField(source='get_agent_type_display', read_only=True)
    risk_level_display = serializers.CharField(source='get_risk_level_display', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)

    class Meta:
        model = AIAgent
        fields = ['id', 'name', 'agent_type', 'agent_type_display', 'risk_level',
                  'risk_level_display', 'status', 'status_display', 'human_approval_required', 'created_at']


class RAGSystemSerializer(serializers.ModelSerializer):
    """RAG System serializer."""

    class Meta:
        model = RAGSystem
        fields = '__all__'
        read_only_fields = ['id', 'created_at', 'updated_at']


class VectorDatabaseSerializer(serializers.ModelSerializer):
    """Vector Database serializer."""

    class Meta:
        model = VectorDatabase
        fields = '__all__'
        read_only_fields = ['id', 'created_at', 'updated_at']


class VectorDatabaseListSerializer(serializers.ModelSerializer):
    """Lightweight serializer for list views."""
    db_type_display = serializers.CharField(source='get_db_type_display', read_only=True)

    class Meta:
        model = VectorDatabase
        fields = ['id', 'name', 'db_type', 'db_type_display', 'tenant_id',
                  'dimension', 'risk_score', 'is_active', 'last_assessed_at', 'created_at']
