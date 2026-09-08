from django.urls import path, include
from rest_framework.routers import DefaultRouter

from apps.hallucination.api.views import (
    HallucinationFindingViewSet, CitationValidationViewSet, ResponseValidationViewSet
)

router = DefaultRouter()
router.register(r'findings', HallucinationFindingViewSet, basename='hallucination-finding')
router.register(r'citations', CitationValidationViewSet, basename='citation-validation')
router.register(r'response-validations', ResponseValidationViewSet, basename='response-validation')

urlpatterns = [
    path('', include(router.urls)),
]
