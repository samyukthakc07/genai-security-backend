from rest_framework import serializers
from apps.vector_security.models import (
    VectorDBSecurityAssessment, TenantIsolationCheck,
    EmbeddingExposureFinding, RAGSecurityAssessment
)


class VectorDBSecurityAssessmentSerializer(serializers.ModelSerializer):
    """Vector DB security assessment serializer."""

    class Meta:
        model = VectorDBSecurityAssessment
        fields = '__all__'
        read_only_fields = ['id', 'assessed_at', 'created_at']


class TenantIsolationCheckSerializer(serializers.ModelSerializer):
    """Tenant isolation check serializer."""

    class Meta:
        model = TenantIsolationCheck
        fields = '__all__'
        read_only_fields = ['id', 'created_at']


class EmbeddingExposureFindingSerializer(serializers.ModelSerializer):
    """Embedding exposure finding serializer."""

    class Meta:
        model = EmbeddingExposureFinding
        fields = '__all__'
        read_only_fields = ['id', 'created_at']


class RAGSecurityAssessmentSerializer(serializers.ModelSerializer):
    """RAG security assessment serializer."""

    class Meta:
        model = RAGSecurityAssessment
        fields = '__all__'
        read_only_fields = ['id', 'created_at']
