from django.urls import path, include
from rest_framework.routers import DefaultRouter

from apps.prompt_injection.api.views import PromptScanViewSet, PromptScanBatchViewSet
from apps.prompt_injection.api.pattern_explorer import PatternsListView, PatternsMatchView

router = DefaultRouter()
router.register(r'scans', PromptScanViewSet, basename='prompt-scan')
router.register(r'batches', PromptScanBatchViewSet, basename='prompt-scan-batch')

urlpatterns = [
    path('', include(router.urls)),
    path('patterns/', PatternsListView.as_view(), name='prompt-patterns-list'),
    path('patterns/match/', PatternsMatchView.as_view(), name='prompt-patterns-match'),
]

