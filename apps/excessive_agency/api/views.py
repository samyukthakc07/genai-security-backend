from rest_framework import viewsets, permissions, filters
from django_filters.rest_framework import DjangoFilterBackend

from apps.excessive_agency.models import AgentPermission, ActionApproval, ToolAccessLog
from apps.excessive_agency.api.serializers import (
    AgentPermissionSerializer, ActionApprovalSerializer, ToolAccessLogSerializer
)
from apps.core.permissions import IsOrganizationMember


class AgentPermissionViewSet(viewsets.ModelViewSet):
    """CRUD for Agent Permissions."""
    queryset = AgentPermission.objects.select_related('agent').all()
    serializer_class = AgentPermissionSerializer
    permission_classes = [permissions.IsAuthenticated, IsOrganizationMember]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['agent', 'resource_type', 'action', 'is_granted', 'requires_human_approval']
    search_fields = ['permission_name']
    ordering_fields = ['risk_score', 'created_at']


class ActionApprovalViewSet(viewsets.ModelViewSet):
    """CRUD for Action Approvals."""
    queryset = ActionApproval.objects.select_related('agent', 'requestor', 'approved_by').all()
    serializer_class = ActionApprovalSerializer
    permission_classes = [permissions.IsAuthenticated, IsOrganizationMember]
    filter_backends = [DjangoFilterBackend, filters.OrderingFilter]
    filterset_fields = ['agent', 'status']
    ordering_fields = ['created_at']


class ToolAccessLogViewSet(viewsets.ModelViewSet):
    """CRUD for Tool Access Logs."""
    queryset = ToolAccessLog.objects.select_related('agent', 'reviewed_by').all()
    serializer_class = ToolAccessLogSerializer
    permission_classes = [permissions.IsAuthenticated, IsOrganizationMember]
    filter_backends = [DjangoFilterBackend, filters.OrderingFilter]
    filterset_fields = ['agent', 'status', 'risk_level']
    ordering_fields = ['-executed_at']
