from django.contrib import admin
from .models import AIModel, AIAgent, RAGSystem, VectorDatabase


@admin.register(AIModel)
class AIModelAdmin(admin.ModelAdmin):
    list_display = ('name', 'model_type', 'model_family', 'is_active', 'risk_score', 'created_at')
    list_filter = ('model_type', 'is_active', 'model_family')
    search_fields = ('name', 'model_family', 'version')
    readonly_fields = ('created_at', 'updated_at')


@admin.register(AIAgent)
class AIAgentAdmin(admin.ModelAdmin):
    list_display = ('name', 'agent_type', 'risk_level', 'status', 'human_approval_required')
    list_filter = ('agent_type', 'risk_level', 'status')
    search_fields = ('name', 'description')


@admin.register(RAGSystem)
class RAGSystemAdmin(admin.ModelAdmin):
    list_display = ('name', 'chunking_strategy', 'chunk_size', 'is_active')
    list_filter = ('chunking_strategy', 'is_active')


@admin.register(VectorDatabase)
class VectorDatabaseAdmin(admin.ModelAdmin):
    list_display = ('name', 'db_type', 'dimension', 'is_active', 'risk_score')
    list_filter = ('db_type', 'is_active')
