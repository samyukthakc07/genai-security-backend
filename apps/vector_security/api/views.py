from rest_framework import viewsets, permissions, filters
from django_filters.rest_framework import DjangoFilterBackend

from apps.vector_security.models import (
    VectorDBSecurityAssessment, TenantIsolationCheck,
    EmbeddingExposureFinding, RAGSecurityAssessment
)
from apps.vector_security.api.serializers import (
    VectorDBSecurityAssessmentSerializer, TenantIsolationCheckSerializer,
    EmbeddingExposureFindingSerializer, RAGSecurityAssessmentSerializer
)
from apps.core.permissions import IsOrganizationMember


class VectorDBSecurityAssessmentViewSet(viewsets.ModelViewSet):
    """CRUD for Vector DB Security Assessments."""
    queryset = VectorDBSecurityAssessment.objects.select_related('scan', 'vector_db').all()
    serializer_class = VectorDBSecurityAssessmentSerializer
    permission_classes = [permissions.IsAuthenticated, IsOrganizationMember]
    filter_backends = [DjangoFilterBackend, filters.OrderingFilter]
    filterset_fields = ['scan', 'vector_db', 'tenant_isolation_valid',
                        'encryption_at_rest', 'encryption_in_transit']
    ordering_fields = ['security_score', 'access_control_score', 'assessed_at']


class TenantIsolationCheckViewSet(viewsets.ModelViewSet):
    """CRUD for Tenant Isolation Checks."""
    queryset = TenantIsolationCheck.objects.select_related('assessment').all()
    serializer_class = TenantIsolationCheckSerializer
    permission_classes = [permissions.IsAuthenticated, IsOrganizationMember]
    filter_backends = [DjangoFilterBackend, filters.OrderingFilter]
    filterset_fields = ['assessment', 'status', 'cross_tenant_access_detected']
    ordering_fields = ['created_at']


class EmbeddingExposureFindingViewSet(viewsets.ModelViewSet):
    """CRUD for Embedding Exposure Findings."""
    queryset = EmbeddingExposureFinding.objects.select_related('assessment').all()
    serializer_class = EmbeddingExposureFindingSerializer
    permission_classes = [permissions.IsAuthenticated, IsOrganizationMember]
    filter_backends = [DjangoFilterBackend, filters.OrderingFilter]
    filterset_fields = ['assessment', 'risk_level']
    ordering_fields = ['created_at']


class RAGSecurityAssessmentViewSet(viewsets.ModelViewSet):
    """CRUD for RAG Security Assessments."""
    queryset = RAGSecurityAssessment.objects.select_related('assessment', 'rag_system').all()
    serializer_class = RAGSecurityAssessmentSerializer
    permission_classes = [permissions.IsAuthenticated, IsOrganizationMember]
    filter_backends = [DjangoFilterBackend, filters.OrderingFilter]
    filterset_fields = ['assessment', 'rag_system']
    ordering_fields = ['retrieval_security_score', 'prompt_injection_risk', 'data_exposure_risk', 'created_at']
