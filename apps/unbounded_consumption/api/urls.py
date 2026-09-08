from django.urls import path, include
from rest_framework.routers import DefaultRouter

from apps.unbounded_consumption.api.views import (
    TokenUsageRecordViewSet, CostMonitorViewSet,
    DoSEventViewSet, RateLimitAssessmentViewSet
)

router = DefaultRouter()
router.register(r'token-usage', TokenUsageRecordViewSet, basename='token-usage')
router.register(r'cost-monitors', CostMonitorViewSet, basename='cost-monitor')
router.register(r'dos-events', DoSEventViewSet, basename='dos-event')
router.register(r'rate-limits', RateLimitAssessmentViewSet, basename='rate-limit-assessment')

urlpatterns = [
    path('', include(router.urls)),
]
