from rest_framework import generics, permissions
from apps.projects.models import Project
from apps.projects.api.serializers import (
    ProjectListSerializer, ProjectDetailSerializer, ProjectCreateSerializer
)
from apps.core.permissions import IsOrganizationMember


class ProjectListView(generics.ListCreateAPIView):
    """List projects for an organization or create new."""

    def get_serializer_class(self):
        if self.request.method == 'POST':
            return ProjectCreateSerializer
        return ProjectListSerializer

    def get_queryset(self):
        org_id = self.request.query_params.get('organization')
        if org_id:
            queryset = Project.objects.filter(organization_id=org_id)
        else:
            queryset = Project.objects.filter(organization__memberships__user=self.request.user).distinct()
        status = self.request.query_params.get('status')
        if status:
            queryset = queryset.filter(status=status)
        return queryset.select_related('created_by')

    def perform_create(self, serializer):
        org_id = self.request.data.get('organization')
        serializer.save(
            organization_id=org_id,
            created_by=self.request.user
        )


class ProjectDetailView(generics.RetrieveUpdateDestroyAPIView):
    """Get/update/delete project details."""
    queryset = Project.objects.all()
    serializer_class = ProjectDetailSerializer
    permission_classes = [permissions.IsAuthenticated, IsOrganizationMember]
