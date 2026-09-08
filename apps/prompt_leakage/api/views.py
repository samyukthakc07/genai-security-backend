from rest_framework import viewsets, permissions, filters
from django_filters.rest_framework import DjangoFilterBackend

from apps.prompt_leakage.models import PromptLeakageScan, PromptExposureTest, SecretInPrompt
from apps.prompt_leakage.api.serializers import (
    PromptLeakageScanSerializer, PromptExposureTestSerializer, SecretInPromptSerializer
)
from apps.core.permissions import IsOrganizationMember


class PromptLeakageScanViewSet(viewsets.ModelViewSet):
    """CRUD for Prompt Leakage Scans."""
    queryset = PromptLeakageScan.objects.select_related('scan').all()
    serializer_class = PromptLeakageScanSerializer
    permission_classes = [permissions.IsAuthenticated, IsOrganizationMember]
    filter_backends = [DjangoFilterBackend, filters.OrderingFilter]
    filterset_fields = ['scan', 'exposure_type', 'leakage_found']
    ordering_fields = ['risk_score', 'prompt_hardening_score', 'created_at']


class PromptExposureTestViewSet(viewsets.ModelViewSet):
    """CRUD for Prompt Exposure Tests."""
    queryset = PromptExposureTest.objects.select_related('leakage_scan').all()
    serializer_class = PromptExposureTestSerializer
    permission_classes = [permissions.IsAuthenticated, IsOrganizationMember]
    filter_backends = [DjangoFilterBackend, filters.OrderingFilter]
    filterset_fields = ['leakage_scan', 'test_type', 'is_successful']
    ordering_fields = ['confidence', 'created_at']


class SecretInPromptViewSet(viewsets.ModelViewSet):
    """CRUD for Secrets in Prompts."""
    queryset = SecretInPrompt.objects.select_related('leakage_scan').all()
    serializer_class = SecretInPromptSerializer
    permission_classes = [permissions.IsAuthenticated, IsOrganizationMember]
    filter_backends = [DjangoFilterBackend, filters.OrderingFilter]
    filterset_fields = ['leakage_scan', 'secret_type', 'risk_level']
    ordering_fields = ['created_at']
