from django.urls import path, include
from rest_framework.routers import DefaultRouter

from apps.sensitive_info.api.views import SecretScanViewSet, PIIFindingViewSet

router = DefaultRouter()
router.register(r'secrets', SecretScanViewSet, basename='secret-scan')
router.register(r'pii', PIIFindingViewSet, basename='pii-finding')

urlpatterns = [
    path('', include(router.urls)),
]
