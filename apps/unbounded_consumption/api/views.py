from rest_framework import viewsets, permissions, filters
from django_filters.rest_framework import DjangoFilterBackend

from apps.unbounded_consumption.models import (
    TokenUsageRecord, CostMonitor, DoSEvent, RateLimitAssessment
)
from apps.unbounded_consumption.api.serializers import (
    TokenUsageRecordSerializer, CostMonitorSerializer,
    DoSEventSerializer, RateLimitAssessmentSerializer
)
from apps.core.permissions import IsOrganizationMember


class TokenUsageRecordViewSet(viewsets.ModelViewSet):
    """CRUD for Token Usage Records."""
    queryset = TokenUsageRecord.objects.select_related('organization', 'model', 'agent').all()
    serializer_class = TokenUsageRecordSerializer
    permission_classes = [permissions.IsAuthenticated, IsOrganizationMember]
    filter_backends = [DjangoFilterBackend, filters.OrderingFilter]
    filterset_fields = ['organization', 'model', 'agent', 'usage_type', 'is_anomalous']
    ordering_fields = ['tokens_used', 'cost', '-recorded_at']


class CostMonitorViewSet(viewsets.ModelViewSet):
    """CRUD for Cost Monitors."""
    queryset = CostMonitor.objects.select_related('organization', 'model').all()
    serializer_class = CostMonitorSerializer
    permission_classes = [permissions.IsAuthenticated, IsOrganizationMember]
    filter_backends = [DjangoFilterBackend, filters.OrderingFilter]
    filterset_fields = ['organization', 'model', 'period_type', 'budget_exceeded']
    ordering_fields = ['total_cost', 'total_tokens', 'period_start']


class DoSEventViewSet(viewsets.ModelViewSet):
    """CRUD for DoS Events."""
    queryset = DoSEvent.objects.select_related('organization', 'model').all()
    serializer_class = DoSEventSerializer
    permission_classes = [permissions.IsAuthenticated, IsOrganizationMember]
    filter_backends = [DjangoFilterBackend, filters.OrderingFilter]
    filterset_fields = ['organization', 'event_type', 'severity', 'status', 'model']
    ordering_fields = ['-detected_at']


class RateLimitAssessmentViewSet(viewsets.ModelViewSet):
    """CRUD for Rate Limit Assessments."""
    queryset = RateLimitAssessment.objects.select_related('scan', 'model').all()
    serializer_class = RateLimitAssessmentSerializer
    permission_classes = [permissions.IsAuthenticated, IsOrganizationMember]
    filter_backends = [DjangoFilterBackend, filters.OrderingFilter]
    filterset_fields = ['scan', 'model', 'rate_limiting_active']
    ordering_fields = ['effectiveness_score', 'created_at']
