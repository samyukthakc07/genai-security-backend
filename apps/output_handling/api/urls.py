from django.urls import path, include
from rest_framework.routers import DefaultRouter

from apps.output_handling.api.views import (
    OutputSanitizationViewSet, XSSFindingViewSet, UnsafeCodeFindingViewSet
)

router = DefaultRouter()
router.register(r'sanitizations', OutputSanitizationViewSet, basename='output-sanitization')
router.register(r'xss', XSSFindingViewSet, basename='xss-finding')
router.register(r'unsafe-code', UnsafeCodeFindingViewSet, basename='unsafe-code-finding')

urlpatterns = [
    path('', include(router.urls)),
]
