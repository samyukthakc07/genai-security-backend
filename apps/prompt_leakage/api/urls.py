from django.urls import path, include
from rest_framework.routers import DefaultRouter

from apps.prompt_leakage.api.views import (
    PromptLeakageScanViewSet, PromptExposureTestViewSet, SecretInPromptViewSet
)

router = DefaultRouter()
router.register(r'scans', PromptLeakageScanViewSet, basename='prompt-leakage-scan')
router.register(r'exposure-tests', PromptExposureTestViewSet, basename='prompt-exposure-test')
router.register(r'secrets', SecretInPromptViewSet, basename='secret-in-prompt')

urlpatterns = [
    path('', include(router.urls)),
]
