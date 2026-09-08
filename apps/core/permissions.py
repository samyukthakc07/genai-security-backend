"""
RBAC Permission Configuration for GenAI Security Platform.
"""

from rest_framework.permissions import BasePermission, SAFE_METHODS


class IsAdminUser(BasePermission):
    """Admin-level access."""

    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated and (
            request.user.is_superuser or
            request.user.is_staff or
            request.user.groups.filter(name='admin').exists()
        )


class IsOrganizationAdmin(BasePermission):
    """Organization admin access - checks membership role."""

    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False
        # Superusers have access to everything
        if request.user.is_superuser:
            return True
        return True  # Further filtering done in views

    def has_object_permission(self, request, view, obj):
        if request.user.is_superuser:
            return True
        # Check if user is admin of the organization
        membership = obj.memberships.filter(
            user=request.user,
            role__in=['admin', 'owner']
        ).first()
        return membership is not None


class IsOrganizationMember(BasePermission):
    """Organization member access."""

    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated

    def has_object_permission(self, request, view, obj):
        if request.user.is_superuser:
            return True
        membership = obj.memberships.filter(user=request.user).first()
        return membership is not None


class ReadOnly(BasePermission):
    """Read-only access."""

    def has_permission(self, request, view):
        return request.method in SAFE_METHODS


# =============================================
# AI Shield Specific Permissions
# =============================================

class CanManageAIAssets(BasePermission):
    """Can create, edit, delete AI assets."""

    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False
        if request.user.is_superuser:
            return True
        if request.method in SAFE_METHODS:
            return True
        return request.user.has_perm('ai_assets.manage_ai_assets')


class CanInitiateScan(BasePermission):
    """Can start AI security scans."""

    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False
        if request.user.is_superuser:
            return True
        if request.method in SAFE_METHODS:
            return True
        return request.user.has_perm('scans.initiate_scan')


class CanViewFindings(BasePermission):
    """Can view security findings."""

    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False
        if request.user.is_superuser:
            return True
        return request.method in SAFE_METHODS or request.user.has_perm('findings.manage_findings')
