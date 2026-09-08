from rest_framework import viewsets, permissions, filters
from django_filters.rest_framework import DjangoFilterBackend

from apps.sensitive_info.models import SecretScan, PIIFinding
from apps.sensitive_info.api.serializers import SecretScanSerializer, PIIFindingSerializer
from apps.core.permissions import IsOrganizationMember


class SecretScanViewSet(viewsets.ModelViewSet):
    """CRUD for Secret Scans."""
    queryset = SecretScan.objects.select_related('scan').all()
    serializer_class = SecretScanSerializer
    permission_classes = [permissions.IsAuthenticated, IsOrganizationMember]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['scan', 'secret_type', 'source', 'risk_level', 'is_validated']
    search_fields = ['context_snippet']
    ordering_fields = ['severity_score', 'created_at']


class PIIFindingViewSet(viewsets.ModelViewSet):
    """CRUD for PII Findings."""
    queryset = PIIFinding.objects.select_related('secret_scan').all()
    serializer_class = PIIFindingSerializer
    permission_classes = [permissions.IsAuthenticated, IsOrganizationMember]
    filter_backends = [DjangoFilterBackend, filters.OrderingFilter]
    filterset_fields = ['secret_scan', 'pii_type', 'risk_level']
    ordering_fields = ['count', 'created_at']
