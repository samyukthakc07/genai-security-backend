from django.urls import path, include
from rest_framework.routers import DefaultRouter

from apps.scans.api.views import AIScanViewSet

router = DefaultRouter()
router.register(r'', AIScanViewSet, basename='scan')

urlpatterns = [
    path('', include(router.urls)),
]
