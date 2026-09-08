from django.urls import path, include
from rest_framework.routers import DefaultRouter

from apps.data_poisoning.api.views import (
    TrainingDataValidationViewSet, RAGDocumentValidationViewSet,
    DatasetIntegrityCheckViewSet
)

router = DefaultRouter()
router.register(r'validations', TrainingDataValidationViewSet, basename='data-validation')
router.register(r'rag-documents', RAGDocumentValidationViewSet, basename='rag-document-validation')
router.register(r'integrity-checks', DatasetIntegrityCheckViewSet, basename='integrity-check')

urlpatterns = [
    path('', include(router.urls)),
]
