from django.urls import path, include
from rest_framework.routers import DefaultRouter

from apps.supply_chain.api.views import AISBOMViewSet, DependencyScanViewSet, SDKRiskAssessmentViewSet

router = DefaultRouter()
router.register(r'sboms', AISBOMViewSet, basename='ai-sbom')
router.register(r'dependencies', DependencyScanViewSet, basename='dependency-scan')
router.register(r'sdk-assessments', SDKRiskAssessmentViewSet, basename='sdk-assessment')

urlpatterns = [
    path('', include(router.urls)),
]
