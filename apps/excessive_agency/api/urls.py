from django.urls import path, include
from rest_framework.routers import DefaultRouter

from apps.excessive_agency.api.views import (
    AgentPermissionViewSet, ActionApprovalViewSet, ToolAccessLogViewSet
)

router = DefaultRouter()
router.register(r'permissions', AgentPermissionViewSet, basename='agent-permission')
router.register(r'approvals', ActionApprovalViewSet, basename='action-approval')
router.register(r'tool-logs', ToolAccessLogViewSet, basename='tool-access-log')

urlpatterns = [
    path('', include(router.urls)),
]
