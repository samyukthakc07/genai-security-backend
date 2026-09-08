from rest_framework import viewsets, permissions, filters
from django_filters.rest_framework import DjangoFilterBackend

from apps.hallucination.models import HallucinationFinding, CitationValidation, ResponseValidation
from apps.hallucination.api.serializers import (
    HallucinationFindingSerializer, CitationValidationSerializer, ResponseValidationSerializer
)
from apps.core.permissions import IsOrganizationMember


class HallucinationFindingViewSet(viewsets.ModelViewSet):
    """CRUD for Hallucination Findings."""
    queryset = HallucinationFinding.objects.select_related('scan').all()
    serializer_class = HallucinationFindingSerializer
    permission_classes = [permissions.IsAuthenticated, IsOrganizationMember]
    filter_backends = [DjangoFilterBackend, filters.OrderingFilter]
    filterset_fields = ['scan', 'hallucination_type', 'severity', 'citations_valid']
    ordering_fields = ['hallucination_score', 'confidence_score', 'created_at']


class CitationValidationViewSet(viewsets.ModelViewSet):
    """CRUD for Citation Validations."""
    queryset = CitationValidation.objects.select_related('hallucination_finding').all()
    serializer_class = CitationValidationSerializer
    permission_classes = [permissions.IsAuthenticated, IsOrganizationMember]
    filter_backends = [DjangoFilterBackend, filters.OrderingFilter]
    filterset_fields = ['hallucination_finding', 'status']
    ordering_fields = ['created_at']


class ResponseValidationViewSet(viewsets.ModelViewSet):
    """CRUD for Response Validations."""
    queryset = ResponseValidation.objects.select_related('scan').all()
    serializer_class = ResponseValidationSerializer
    permission_classes = [permissions.IsAuthenticated, IsOrganizationMember]
    filter_backends = [DjangoFilterBackend, filters.OrderingFilter]
    filterset_fields = ['scan', 'status']
    ordering_fields = ['overall_validity_score', 'trust_score', 'created_at']
