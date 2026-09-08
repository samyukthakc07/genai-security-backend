from rest_framework import viewsets, permissions, filters
from django_filters.rest_framework import DjangoFilterBackend

from apps.output_handling.models import OutputSanitization, XSSFinding, UnsafeCodeFinding
from apps.output_handling.api.serializers import (
    OutputSanitizationSerializer, XSSFindingSerializer, UnsafeCodeFindingSerializer
)
from apps.core.permissions import IsOrganizationMember


class OutputSanitizationViewSet(viewsets.ModelViewSet):
    """CRUD for Output Sanitizations."""
    queryset = OutputSanitization.objects.select_related('scan').all()
    serializer_class = OutputSanitizationSerializer
    permission_classes = [permissions.IsAuthenticated, IsOrganizationMember]
    filter_backends = [DjangoFilterBackend, filters.OrderingFilter]
    filterset_fields = ['scan', 'output_type', 'severity', 'is_sanitized']
    ordering_fields = ['risk_score', 'created_at']


class XSSFindingViewSet(viewsets.ModelViewSet):
    """CRUD for XSS Findings."""
    queryset = XSSFinding.objects.select_related('sanitization').all()
    serializer_class = XSSFindingSerializer
    permission_classes = [permissions.IsAuthenticated, IsOrganizationMember]
    filter_backends = [DjangoFilterBackend, filters.OrderingFilter]
    filterset_fields = ['sanitization', 'xss_type', 'risk_level']
    ordering_fields = ['created_at']


class UnsafeCodeFindingViewSet(viewsets.ModelViewSet):
    """CRUD for Unsafe Code Findings."""
    queryset = UnsafeCodeFinding.objects.select_related('sanitization').all()
    serializer_class = UnsafeCodeFindingSerializer
    permission_classes = [permissions.IsAuthenticated, IsOrganizationMember]
    filter_backends = [DjangoFilterBackend, filters.OrderingFilter]
    filterset_fields = ['sanitization', 'code_language', 'vulnerability_type', 'risk_level']
    ordering_fields = ['created_at']
