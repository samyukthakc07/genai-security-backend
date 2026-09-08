from django.urls import path
from apps.organizations.api.views import (
    OrganizationListView, OrganizationDetailView, OrganizationMembersView,
    InviteMemberView, RemoveMemberView, UpdateMemberRoleView
)

urlpatterns = [
    path('', OrganizationListView.as_view(), name='organization-list'),
    path('<uuid:pk>/', OrganizationDetailView.as_view(), name='organization-detail'),
    path('<uuid:pk>/members/', OrganizationMembersView.as_view(), name='organization-members'),
    path('<uuid:pk>/members/invite/', InviteMemberView.as_view(), name='organization-invite'),
    path('<uuid:pk>/members/<uuid:member_id>/remove/', RemoveMemberView.as_view(), name='organization-remove-member'),
    path('<uuid:pk>/members/<uuid:member_id>/role/', UpdateMemberRoleView.as_view(), name='organization-update-role'),
]
