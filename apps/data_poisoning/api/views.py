from rest_framework import viewsets, permissions, filters
from django_filters.rest_framework import DjangoFilterBackend

from apps.data_poisoning.models import TrainingDataValidation, RAGDocumentValidation, DatasetIntegrityCheck
from apps.data_poisoning.api.serializers import (
    TrainingDataValidationSerializer, RAGDocumentValidationSerializer,
    DatasetIntegrityCheckSerializer
)
from apps.core.permissions import IsOrganizationMember


class TrainingDataValidationViewSet(viewsets.ModelViewSet):
    """CRUD for Training Data Validations."""
    queryset = TrainingDataValidation.objects.select_related('scan').all()
    serializer_class = TrainingDataValidationSerializer
    permission_classes = [permissions.IsAuthenticated, IsOrganizationMember]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['scan', 'data_source', 'validation_status']
    search_fields = ['data_fingerprint']
    ordering_fields = ['integrity_score', 'trust_score', 'created_at']


class RAGDocumentValidationViewSet(viewsets.ModelViewSet):
    """CRUD for RAG Document Validations."""
    queryset = RAGDocumentValidation.objects.select_related('validation').all()
    serializer_class = RAGDocumentValidationSerializer
    permission_classes = [permissions.IsAuthenticated, IsOrganizationMember]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['validation', 'is_poisoned']
    search_fields = ['document_name', 'document_id']
    ordering_fields = ['confidence_score', 'created_at']


class DatasetIntegrityCheckViewSet(viewsets.ModelViewSet):
    """CRUD for Dataset Integrity Checks."""
    queryset = DatasetIntegrityCheck.objects.select_related('validation').all()
    serializer_class = DatasetIntegrityCheckSerializer
    permission_classes = [permissions.IsAuthenticated, IsOrganizationMember]
    filter_backends = [DjangoFilterBackend, filters.OrderingFilter]
    filterset_fields = ['validation', 'check_type', 'is_passed']
    ordering_fields = ['score', 'created_at']
