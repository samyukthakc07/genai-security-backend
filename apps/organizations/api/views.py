from rest_framework import generics, permissions, status
from rest_framework.response import Response
from rest_framework.views import APIView
from django.db import transaction

from apps.organizations.models import Organization, Membership
from apps.organizations.api.serializers import (
    OrganizationListSerializer, OrganizationDetailSerializer,
    OrganizationCreateSerializer, MembershipSerializer,
    InviteMemberSerializer
)
from apps.core.models import User, AuditLog
from apps.core.permissions import IsOrganizationAdmin


class OrganizationListView(generics.ListCreateAPIView):
    """List organizations (user's orgs) or create new one."""

    def get_serializer_class(self):
        if self.request.method == 'POST':
            return OrganizationCreateSerializer
        return OrganizationListSerializer

    def get_queryset(self):
        return Organization.objects.filter(
            memberships__user=self.request.user
        ).distinct()

    def perform_create(self, serializer):
        serializer.save()


class OrganizationDetailView(generics.RetrieveUpdateDestroyAPIView):
    """Get/update/delete organization details."""
    queryset = Organization.objects.all()
    serializer_class = OrganizationDetailSerializer
    permission_classes = [permissions.IsAuthenticated, IsOrganizationAdmin]


class OrganizationMembersView(generics.ListAPIView):
    """List organization members."""
    serializer_class = MembershipSerializer

    def get_queryset(self):
        return Membership.objects.filter(
            organization_id=self.kwargs['pk']
        ).select_related('user')


class InviteMemberView(APIView):
    """Invite a member to the organization."""

    def post(self, request, pk=None):
        serializer = InviteMemberSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        org = generics.get_object_or_404(Organization, pk=pk)

        # Check admin permission
        membership = org.memberships.filter(user=request.user).first()
        if not membership or membership.role not in ['owner', 'admin']:
            return Response({'detail': 'Not authorized to invite members.'},
                          status=status.HTTP_403_FORBIDDEN)

        email = serializer.validated_data['email']
        role = serializer.validated_data['role']
        user = User.objects.filter(email=email).first()

        if not user:
            return Response({'email': 'User with this email not found.'},
                          status=status.HTTP_404_NOT_FOUND)

        # Check if already a member
        if org.memberships.filter(user=user).exists():
            return Response({'email': 'User is already a member.'},
                          status=status.HTTP_400_BAD_REQUEST)

        Membership.objects.create(organization=org, user=user, role=role)

        AuditLog.objects.create(
            organization=org,
            user=request.user,
            action='create',
            resource_type='membership',
            resource_id=user.id,
            details={'invited_email': email, 'role': role},
        )

        return Response({'detail': f'Member invited with role {role}.'},
                       status=status.HTTP_201_CREATED)


class RemoveMemberView(APIView):
    """Remove a member from the organization."""

    def delete(self, request, pk=None, member_id=None):
        org = generics.get_object_or_404(Organization, pk=pk)
        membership = generics.get_object_or_404(Membership, pk=member_id, organization=org)

        # Cannot remove owner
        if membership.role == 'owner':
            return Response({'detail': 'Cannot remove the owner.'},
                          status=status.HTTP_400_BAD_REQUEST)

        membership.delete()

        AuditLog.objects.create(
            organization=org,
            user=request.user,
            action='delete',
            resource_type='membership',
            resource_id=membership.user_id,
        )

        return Response(status=status.HTTP_204_NO_CONTENT)


class UpdateMemberRoleView(APIView):
    """Update a member's role."""

    def patch(self, request, pk=None, member_id=None):
        org = generics.get_object_or_404(Organization, pk=pk)
        membership = generics.get_object_or_404(Membership, pk=member_id, organization=org)

        new_role = request.data.get('role')
        if new_role not in dict(Membership.ROLE_CHOICES):
            return Response({'role': 'Invalid role.'}, status=status.HTTP_400_BAD_REQUEST)

        # Cannot change owner role
        if membership.role == 'owner':
            return Response({'detail': 'Cannot change the owner role.'},
                          status=status.HTTP_400_BAD_REQUEST)

        membership.role = new_role
        membership.save()

        AuditLog.objects.create(
            organization=org,
            user=request.user,
            action='update',
            resource_type='membership_role',
            resource_id=membership.user_id,
            details={'new_role': new_role},
        )

        return Response(MembershipSerializer(membership).data)
