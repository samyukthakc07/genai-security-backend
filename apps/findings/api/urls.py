from django.urls import path, include
from rest_framework.routers import DefaultRouter

from apps.findings.api.views import FindingViewSet, FindingNoteViewSet, FindingTrendViewSet

router = DefaultRouter()
router.register(r'', FindingViewSet, basename='finding')
router.register(r'notes', FindingNoteViewSet, basename='finding-note')
router.register(r'trends', FindingTrendViewSet, basename='finding-trend')

urlpatterns = [
    path('', include(router.urls)),
]
