from django.urls import path, include
from rest_framework.routers import DefaultRouter

from apps.vector_security.api.views import (
    VectorDBSecurityAssessmentViewSet, TenantIsolationCheckViewSet,
    EmbeddingExposureFindingViewSet, RAGSecurityAssessmentViewSet
)

router = DefaultRouter()
router.register(r'assessments', VectorDBSecurityAssessmentViewSet, basename='vector-db-assessment')
router.register(r'tenant-isolation', TenantIsolationCheckViewSet, basename='tenant-isolation-check')
router.register(r'embedding-exposures', EmbeddingExposureFindingViewSet, basename='embedding-exposure')
router.register(r'rag-assessments', RAGSecurityAssessmentViewSet, basename='rag-security-assessment')

urlpatterns = [
    path('', include(router.urls)),
]
