from rest_framework import viewsets, permissions, filters
from django_filters.rest_framework import DjangoFilterBackend

from apps.supply_chain.models import AISBOM, DependencyScan, SDKRiskAssessment
from apps.supply_chain.api.serializers import (
    AISBOMSerializer, DependencyScanSerializer, SDKRiskAssessmentSerializer
)
from apps.core.permissions import IsOrganizationMember


class AISBOMViewSet(viewsets.ModelViewSet):
    """CRUD for AI SBOMs."""
    queryset = AISBOM.objects.select_related('organization', 'model').all()
    serializer_class = AISBOMSerializer
    permission_classes = [permissions.IsAuthenticated, IsOrganizationMember]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['organization', 'model', 'format']
    search_fields = ['sbom_version']
    ordering_fields = ['risk_score', 'generated_at']


class DependencyScanViewSet(viewsets.ModelViewSet):
    """CRUD for Dependency Scans."""
    queryset = DependencyScan.objects.select_related('scan').all()
    serializer_class = DependencyScanSerializer
    permission_classes = [permissions.IsAuthenticated, IsOrganizationMember]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['scan', 'risk_level', 'is_outdated', 'dependency_type']
    search_fields = ['dependency_name']
    ordering_fields = ['risk_level', 'created_at']


class SDKRiskAssessmentViewSet(viewsets.ModelViewSet):
    """CRUD for SDK Risk Assessments."""
    queryset = SDKRiskAssessment.objects.select_related('scan').all()
    serializer_class = SDKRiskAssessmentSerializer
    permission_classes = [permissions.IsAuthenticated, IsOrganizationMember]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['scan']
    search_fields = ['sdk_name', 'provider']
    ordering_fields = ['risk_score', 'security_score', 'created_at']
