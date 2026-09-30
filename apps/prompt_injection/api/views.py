import json
import logging

from rest_framework import viewsets, permissions, status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.views import APIView
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import filters

from apps.prompt_injection.models import PromptScan, PromptScanBatch
from apps.prompt_injection.api.serializers import (
    PromptScanSerializer, PromptScanBatchSerializer
)
from apps.core.permissions import IsOrganizationMember
from apps.security_engine.registry import plugin_registry

logger = logging.getLogger(__name__)


class PromptScanViewSet(viewsets.ModelViewSet):
    """CRUD for Prompt Scans."""
    queryset = PromptScan.objects.select_related('scan').all()
    serializer_class = PromptScanSerializer
    permission_classes = [permissions.IsAuthenticated, IsOrganizationMember]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['scan', 'injection_type', 'is_malicious']
    search_fields = ['prompt_text']
    ordering_fields = ['risk_score', 'created_at']


class PromptScanBatchViewSet(viewsets.ModelViewSet):
    """CRUD for Prompt Scan Batches."""
    queryset = PromptScanBatch.objects.select_related('scan').all()
    serializer_class = PromptScanBatchSerializer
    permission_classes = [permissions.IsAuthenticated, IsOrganizationMember]
    filter_backends = [DjangoFilterBackend, filters.OrderingFilter]
    filterset_fields = ['scan']
    ordering_fields = ['created_at']


