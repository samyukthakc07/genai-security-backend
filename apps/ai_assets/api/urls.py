from django.urls import path, include
from rest_framework.routers import DefaultRouter

from apps.ai_assets.api.views import (
    AIModelViewSet, AIAgentViewSet, RAGSystemViewSet, VectorDatabaseViewSet
)

router = DefaultRouter()
router.register(r'models', AIModelViewSet, basename='ai-model')
router.register(r'agents', AIAgentViewSet, basename='ai-agent')
router.register(r'rag-systems', RAGSystemViewSet, basename='rag-system')
router.register(r'vector-databases', VectorDatabaseViewSet, basename='vector-database')

urlpatterns = [
    path('', include(router.urls)),
]
