from django.contrib import admin
from .models import VectorDBSecurityAssessment, TenantIsolationCheck, EmbeddingExposureFinding, RAGSecurityAssessment


@admin.register(VectorDBSecurityAssessment)
class VectorDBSecurityAssessmentAdmin(admin.ModelAdmin):
    list_display = ('vector_db', 'security_score', 'tenant_isolation_valid', 'assessed_at')
    list_filter = ('tenant_isolation_valid',)


@admin.register(TenantIsolationCheck)
class TenantIsolationCheckAdmin(admin.ModelAdmin):
    list_display = ('assessment', 'tenant_a_id', 'tenant_b_id', 'cross_tenant_access_detected', 'status')
    list_filter = ('status', 'cross_tenant_access_detected')


@admin.register(EmbeddingExposureFinding)
class EmbeddingExposureFindingAdmin(admin.ModelAdmin):
    list_display = ('embedding_id', 'sensitive_data_type', 'risk_level')
    list_filter = ('risk_level',)


@admin.register(RAGSecurityAssessment)
class RAGSecurityAssessmentAdmin(admin.ModelAdmin):
    list_display = ('rag_system', 'retrieval_security_score', 'prompt_injection_risk', 'data_exposure_risk')
