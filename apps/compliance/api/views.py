from rest_framework import viewsets, permissions, filters
from django_filters.rest_framework import DjangoFilterBackend

from apps.compliance.models import (
    ComplianceFramework, ComplianceControl, ComplianceMapping,
    ComplianceCheckResult, ComplianceReport
)
from apps.compliance.api.serializers import (
    ComplianceFrameworkSerializer, ComplianceFrameworkListSerializer,
    ComplianceControlSerializer, ComplianceMappingSerializer,
    ComplianceCheckResultSerializer, ComplianceReportSerializer,
    ComplianceReportListSerializer
)
from apps.core.permissions import IsOrganizationMember


class ComplianceFrameworkViewSet(viewsets.ModelViewSet):
    """CRUD for Compliance Frameworks."""
    queryset = ComplianceFramework.objects.prefetch_related('controls').all()
    permission_classes = [permissions.IsAuthenticated, IsOrganizationMember]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['short_name', 'is_active']
    search_fields = ['name', 'description']
    ordering_fields = ['name', 'short_name', 'total_controls']

    def get_serializer_class(self):
        if self.action == 'list':
            return ComplianceFrameworkListSerializer
        return ComplianceFrameworkSerializer


class ComplianceControlViewSet(viewsets.ModelViewSet):
    """CRUD for Compliance Controls."""
    queryset = ComplianceControl.objects.select_related('framework').all()
    serializer_class = ComplianceControlSerializer
    permission_classes = [permissions.IsAuthenticated, IsOrganizationMember]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['framework', 'category', 'risk_category']
    search_fields = ['control_id', 'title', 'description']
    ordering_fields = ['framework', 'control_id']


class ComplianceMappingViewSet(viewsets.ModelViewSet):
    """CRUD for Compliance Mappings."""
    queryset = ComplianceMapping.objects.select_related(
        'organization', 'finding', 'control', 'framework'
    ).all()
    serializer_class = ComplianceMappingSerializer
    permission_classes = [permissions.IsAuthenticated, IsOrganizationMember]
    filter_backends = [DjangoFilterBackend, filters.OrderingFilter]
    filterset_fields = ['organization', 'finding', 'control', 'framework', 'mapping_type']


class ComplianceCheckResultViewSet(viewsets.ModelViewSet):
    """CRUD for Compliance Check Results."""
    queryset = ComplianceCheckResult.objects.select_related(
        'organization', 'project', 'scan', 'framework', 'control'
    ).all()
    serializer_class = ComplianceCheckResultSerializer
    permission_classes = [permissions.IsAuthenticated, IsOrganizationMember]
    filter_backends = [DjangoFilterBackend, filters.OrderingFilter]
    filterset_fields = ['organization', 'project', 'scan', 'framework', 'control', 'status']


class ComplianceReportViewSet(viewsets.ModelViewSet):
    """CRUD for Compliance Reports."""
    queryset = ComplianceReport.objects.select_related(
        'organization', 'project', 'framework', 'created_by'
    ).all()
    permission_classes = [permissions.IsAuthenticated, IsOrganizationMember]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['organization', 'framework', 'report_type']
    search_fields = ['name']
    ordering_fields = ['name', 'overall_score', '-generated_at']

    def get_serializer_class(self):
        if self.action == 'list':
            return ComplianceReportListSerializer
        return ComplianceReportSerializer
