from rest_framework import viewsets, permissions, filters, status
from rest_framework.decorators import action
from rest_framework.response import Response
from django_filters.rest_framework import DjangoFilterBackend

from apps.findings.models import Finding, FindingNote, FindingTrend
from apps.findings.api.serializers import (
    FindingSerializer, FindingListSerializer,
    FindingNoteSerializer, FindingTrendSerializer
)
from django.contrib.auth import get_user_model

from apps.core.permissions import IsOrganizationMember

User = get_user_model()


class FindingViewSet(viewsets.ModelViewSet):
    """CRUD for Findings."""
    queryset = Finding.objects.select_related(
        'organization', 'project', 'scan', 'assigned_to', 'resolved_by'
    ).all()
    permission_classes = [permissions.IsAuthenticated, IsOrganizationMember]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['organization', 'project', 'scan', 'module_type',
                        'severity', 'status', 'assigned_to']
    search_fields = ['title', 'description', 'finding_type']
    ordering_fields = ['title', 'severity', 'risk_score', 'discovered_at', 'created_at']

    def get_serializer_class(self):
        if self.action == 'list':
            return FindingListSerializer
        return FindingSerializer

    @action(detail=True, methods=['post'])
    def resolve(self, request, pk=None):
        """Resolve a finding."""
        finding = self.get_object()
        if finding.status == 'resolved':
            return Response(
                {'detail': 'Finding is already resolved.'},
                status=status.HTTP_400_BAD_REQUEST
            )
        finding.status = 'resolved'
        finding.resolved_by = request.user
        if 'resolved_at' in request.data:
            finding.resolved_at = request.data['resolved_at']
        else:
            from django.utils import timezone
            finding.resolved_at = timezone.now()
        finding.save(update_fields=['status', 'resolved_by', 'resolved_at'])
        return Response(FindingSerializer(finding).data)

    @action(detail=True, methods=['post'])
    def assign(self, request, pk=None):
        """Assign a finding to a user."""
        finding = self.get_object()
        user_id = request.data.get('assigned_to')
        if not user_id:
            return Response(
                {'detail': 'assigned_to is required.'},
                status=status.HTTP_400_BAD_REQUEST
            )
        try:
            user = User.objects.get(id=user_id)
            finding.assigned_to = user
            finding.save(update_fields=['assigned_to'])
            return Response(FindingSerializer(finding).data)
        except User.DoesNotExist:
            return Response(
                {'detail': 'User not found.'},
                status=status.HTTP_404_NOT_FOUND
            )


class FindingNoteViewSet(viewsets.ModelViewSet):
    """CRUD for Finding Notes."""
    queryset = FindingNote.objects.select_related('finding', 'user').all()
    serializer_class = FindingNoteSerializer
    permission_classes = [permissions.IsAuthenticated, IsOrganizationMember]
    filterset_fields = ['finding']

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)


class FindingTrendViewSet(viewsets.ReadOnlyModelViewSet):
    """Read-only view for finding trends."""
    queryset = FindingTrend.objects.select_related('organization').all()
    serializer_class = FindingTrendSerializer
    permission_classes = [permissions.IsAuthenticated, IsOrganizationMember]
    filter_backends = [DjangoFilterBackend, filters.OrderingFilter]
    filterset_fields = ['organization', 'module_type', 'date']
    ordering_fields = ['-date']
