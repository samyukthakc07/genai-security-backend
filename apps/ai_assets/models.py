import uuid
from django.db import models


class AIModel(models.Model):
    """LLM/GenAI Model inventory - tracks all AI models under management."""

    MODEL_TYPES = [
        ('ollama', 'Ollama'),
        ('openai', 'OpenAI'),
        ('gemini', 'Gemini'),
        ('claude', 'Claude'),
        ('huggingface', 'HuggingFace'),
        ('custom', 'Custom'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(
        'organizations.Organization', on_delete=models.CASCADE, related_name='ai_models'
    )
    project = models.ForeignKey(
        'projects.Project', on_delete=models.SET_NULL, null=True, blank=True, related_name='ai_models'
    )
    name = models.CharField(max_length=255)
    model_type = models.CharField(max_length=50, choices=MODEL_TYPES)
    model_family = models.CharField(max_length=100, blank=True, help_text='e.g., gpt-4, llama-3, claude-3')
    version = models.CharField(max_length=100, blank=True)
    endpoint_url = models.URLField(max_length=500, blank=True)
    api_key_ref = models.CharField(max_length=255, blank=True, help_text='Reference to encrypted API key')
    context_window = models.IntegerField(default=4096, help_text='Max context window in tokens')
    capabilities = models.JSONField(default=list, blank=True, help_text='e.g., ["chat", "completion", "embedding", "vision"]')
    risk_score = models.DecimalField(max_digits=5, decimal_places=2, default=0)
    discovery_method = models.CharField(max_length=50, default='manual', choices=[
        ('manual', 'Manual'),
        ('auto_discovered', 'Auto Discovered'),
        ('api_scan', 'API Scan'),
        ('integration', 'Integration'),
    ])
    metadata = models.JSONField(default=dict, blank=True)
    is_active = models.BooleanField(default=True)
    last_scanned_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'ai_assets_ai_model'
        verbose_name = 'AI Model'
        verbose_name_plural = 'AI Models'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['organization', 'model_type']),
            models.Index(fields=['organization', 'is_active']),
            models.Index(fields=['model_family']),
        ]

    def __str__(self):
        return f'{self.name} ({self.get_model_type_display()})'


class AIAgent(models.Model):
    """AI Agent tracking - for monitoring permissions, tools, and behavior."""

    AGENT_TYPES = [
        ('autonomous', 'Autonomous Agent'),
        ('assistant', 'Assistant'),
        ('workflow', 'Workflow Agent'),
        ('custom', 'Custom'),
    ]

    RISK_LEVELS = [
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical'),
    ]

    STATUS_CHOICES = [
        ('active', 'Active'),
        ('inactive', 'Inactive'),
        ('suspended', 'Suspended'),
        ('retired', 'Retired'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(
        'organizations.Organization', on_delete=models.CASCADE, related_name='ai_agents'
    )
    project = models.ForeignKey(
        'projects.Project', on_delete=models.SET_NULL, null=True, blank=True, related_name='ai_agents'
    )
    model = models.ForeignKey(
        AIModel, on_delete=models.SET_NULL, null=True, blank=True, related_name='agents'
    )
    name = models.CharField(max_length=255)
    agent_type = models.CharField(max_length=50, choices=AGENT_TYPES)
    description = models.TextField(blank=True)
    permissions = models.JSONField(default=dict, blank=True, help_text='Agent permissions/scope')
    tools = models.JSONField(default=list, blank=True, help_text='Available tools/plugins')
    allowed_actions = models.JSONField(default=list, blank=True)
    disallowed_actions = models.JSONField(default=list, blank=True)
    human_approval_required = models.BooleanField(default=False)
    risk_level = models.CharField(max_length=50, choices=RISK_LEVELS, default='medium')
    status = models.CharField(max_length=50, choices=STATUS_CHOICES, default='active')
    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'ai_assets_ai_agent'
        verbose_name = 'AI Agent'
        verbose_name_plural = 'AI Agents'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['organization', 'status']),
            models.Index(fields=['risk_level']),
        ]

    def __str__(self):
        return f'{self.name} ({self.get_agent_type_display()})'


class RAGSystem(models.Model):
    """RAG (Retrieval-Augmented Generation) System inventory."""

    CHUNKING_STRATEGIES = [
        ('fixed', 'Fixed Size'),
        ('semantic', 'Semantic'),
        ('recursive', 'Recursive Character'),
        ('sentence', 'Sentence Split'),
        ('custom', 'Custom'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(
        'organizations.Organization', on_delete=models.CASCADE, related_name='rag_systems'
    )
    project = models.ForeignKey(
        'projects.Project', on_delete=models.SET_NULL, null=True, blank=True, related_name='rag_systems'
    )
    name = models.CharField(max_length=255)
    vector_db = models.ForeignKey(
        'ai_assets.VectorDatabase', on_delete=models.SET_NULL,
        null=True, blank=True, related_name='rag_systems'
    )
    embedding_model = models.ForeignKey(
        AIModel, on_delete=models.SET_NULL, null=True, blank=True, related_name='rag_systems'
    )
    chunking_strategy = models.CharField(max_length=50, choices=CHUNKING_STRATEGIES, default='fixed')
    chunk_size = models.IntegerField(default=1000)
    chunk_overlap = models.IntegerField(default=200)
    retrieval_config = models.JSONField(default=dict, blank=True, help_text='Top-K, similarity threshold, etc.')
    security_config = models.JSONField(default=dict, blank=True, help_text='Access controls, isolation config')
    risk_score = models.DecimalField(max_digits=5, decimal_places=2, default=0)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'ai_assets_rag_system'
        verbose_name = 'RAG System'
        verbose_name_plural = 'RAG Systems'
        ordering = ['-created_at']

    def __str__(self):
        return self.name


class VectorDatabase(models.Model):
    """Vector Database inventory for embedding storage security."""

    DB_TYPES = [
        ('pinecone', 'Pinecone'),
        ('weaviate', 'Weaviate'),
        ('qdrant', 'Qdrant'),
        ('chroma', 'Chroma'),
        ('pgvector', 'pgvector'),
        ('milvus', 'Milvus'),
        ('elasticsearch', 'Elasticsearch'),
        ('custom', 'Custom'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(
        'organizations.Organization', on_delete=models.CASCADE, related_name='vector_databases'
    )
    name = models.CharField(max_length=255)
    db_type = models.CharField(max_length=50, choices=DB_TYPES)
    endpoint_url = models.URLField(max_length=500, blank=True)
    tenant_id = models.CharField(max_length=255, blank=True, help_text='Multi-tenant isolation ID')
    dimension = models.IntegerField(default=1536, help_text='Vector dimension')
    indexing_method = models.CharField(max_length=100, blank=True)
    security_config = models.JSONField(default=dict, blank=True, help_text='Encryption, access controls')
    risk_score = models.DecimalField(max_digits=5, decimal_places=2, default=0)
    is_active = models.BooleanField(default=True)
    last_assessed_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'ai_assets_vector_database'
        verbose_name = 'Vector Database'
        verbose_name_plural = 'Vector Databases'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['organization', 'db_type']),
        ]

    def __str__(self):
        return f'{self.name} ({self.get_db_type_display()})'
