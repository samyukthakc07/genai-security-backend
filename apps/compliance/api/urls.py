from django.urls import path, include
from rest_framework.routers import DefaultRouter

from apps.compliance.api.views import (
    ComplianceFrameworkViewSet, ComplianceControlViewSet,
    ComplianceMappingViewSet, ComplianceCheckResultViewSet,
    ComplianceReportViewSet
)

router = DefaultRouter()
router.register(r'frameworks', ComplianceFrameworkViewSet, basename='compliance-framework')
router.register(r'controls', ComplianceControlViewSet, basename='compliance-control')
router.register(r'mappings', ComplianceMappingViewSet, basename='compliance-mapping')
router.register(r'check-results', ComplianceCheckResultViewSet, basename='compliance-check-result')
router.register(r'reports', ComplianceReportViewSet, basename='compliance-report')

urlpatterns = [
    path('', include(router.urls)),
]
