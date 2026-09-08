from rest_framework import viewsets, permissions, filters
from django_filters.rest_framework import DjangoFilterBackend

from apps.ai_assets.models import AIModel, AIAgent, RAGSystem, VectorDatabase
from apps.ai_assets.api.serializers import (
    AIModelSerializer, AIModelListSerializer,
    AIAgentSerializer, AIAgentListSerializer,
    RAGSystemSerializer,
    VectorDatabaseSerializer, VectorDatabaseListSerializer
)
from apps.core.permissions import IsOrganizationMember


class AIModelViewSet(viewsets.ModelViewSet):
    """CRUD for AI Models."""
    queryset = AIModel.objects.select_related('organization', 'project').all()
    permission_classes = [permissions.IsAuthenticated, IsOrganizationMember]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['organization', 'model_type', 'model_family', 'is_active']
    search_fields = ['name', 'model_family', 'version']
    ordering_fields = ['name', 'risk_score', 'created_at', 'last_scanned_at']

    def get_serializer_class(self):
        if self.action == 'list':
            return AIModelListSerializer
        return AIModelSerializer


class AIAgentViewSet(viewsets.ModelViewSet):
    """CRUD for AI Agents."""
    queryset = AIAgent.objects.select_related('organization', 'project', 'model').all()
    permission_classes = [permissions.IsAuthenticated, IsOrganizationMember]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['organization', 'agent_type', 'risk_level', 'status']
    search_fields = ['name', 'description']
    ordering_fields = ['name', 'risk_level', 'created_at']

    def get_serializer_class(self):
        if self.action == 'list':
            return AIAgentListSerializer
        return AIAgentSerializer


class RAGSystemViewSet(viewsets.ModelViewSet):
    """CRUD for RAG Systems."""
    queryset = RAGSystem.objects.select_related('organization', 'project', 'vector_db', 'embedding_model').all()
    permission_classes = [permissions.IsAuthenticated, IsOrganizationMember]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['organization', 'chunking_strategy', 'is_active']
    search_fields = ['name']
    ordering_fields = ['name', 'risk_score', 'created_at']

    def get_serializer_class(self):
        return RAGSystemSerializer


class VectorDatabaseViewSet(viewsets.ModelViewSet):
    """CRUD for Vector Databases."""
    queryset = VectorDatabase.objects.select_related('organization').all()
    permission_classes = [permissions.IsAuthenticated, IsOrganizationMember]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['organization', 'db_type', 'is_active']
    search_fields = ['name']
    ordering_fields = ['name', 'risk_score', 'dimension', 'created_at']

    def get_serializer_class(self):
        if self.action == 'list':
            return VectorDatabaseListSerializer
        return VectorDatabaseSerializer
