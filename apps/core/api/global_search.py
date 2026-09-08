"""
Global Search API - Search across all 10 OWASP module models simultaneously.
"""
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from django.db.models import Q, Model
from django.apps import apps

# Module search configuration: (model, label, search_fields, result_fields, url_pattern)
SEARCH_MODULES = [
    {
        'id': 'llm01',
        'number': 'LLM01',
        'name': 'Prompt Injection',
        'model_path': 'prompt_injection.PromptScan',
        'search_fields': ['prompt_text', 'injection_type', 'techniques_detected'],
        'result_label': lambda obj: obj.prompt_text[:100],
        'result_detail': lambda obj: f"Type: {obj.injection_type} | Risk: {obj.risk_score}",
        'detail_url': '/modules/prompt-injection',
    },
    {
        'id': 'llm02',
        'number': 'LLM02',
        'name': 'Sensitive Information Disclosure',
        'model_path': 'sensitive_info.SecretScan',
        'search_fields': ['secret_type', 'source', 'detected_value_hash'],
        'result_label': lambda obj: f"{obj.secret_type} found in {obj.source}",
        'result_detail': lambda obj: f"Risk: {obj.risk_level} | Score: {obj.severity_score}",
        'detail_url': '/modules/sensitive-info',
    },
    {
        'id': 'llm03',
        'number': 'LLM03',
        'name': 'Supply Chain Security',
        'model_path': 'supply_chain.DependencyScan',
        'search_fields': ['dependency_name', 'dependency_version', 'dependency_type', 'risk_level'],
        'result_label': lambda obj: f"{obj.dependency_name} v{obj.dependency_version}",
        'result_detail': lambda obj: f"Type: {obj.dependency_type} | Risk: {obj.risk_level}",
        'detail_url': '/modules/supply-chain',
    },
    {
        'id': 'llm04',
        'number': 'LLM04',
        'name': 'Data & Model Poisoning',
        'model_path': 'data_poisoning.TrainingDataValidation',
        'search_fields': ['data_source', 'validation_status'],
        'result_label': lambda obj: f"Data validation: {obj.data_source}",
        'result_detail': lambda obj: f"Integrity: {obj.integrity_score}% | Trust: {obj.trust_score}%",
        'detail_url': '/modules/data-poisoning',
    },
    {
        'id': 'llm05',
        'number': 'LLM05',
        'name': 'Improper Output Handling',
        'model_path': 'output_handling.OutputSanitization',
        'search_fields': ['output_type', 'severity'],
        'result_label': lambda obj: f"Output sanitization: {obj.output_type}",
        'result_detail': lambda obj: f"Severity: {obj.severity} | Risk: {obj.risk_score}",
        'detail_url': '/modules/output-handling',
    },
    {
        'id': 'llm06',
        'number': 'LLM06',
        'name': 'Excessive Agency',
        'model_path': 'excessive_agency.AgentPermission',
        'search_fields': ['permission_name', 'resource_type', 'action'],
        'result_label': lambda obj: f"Permission: {obj.permission_name}",
        'result_detail': lambda obj: f"Resource: {obj.resource_type} | Action: {obj.action}",
        'detail_url': '/modules/excessive-agency',
    },
    {
        'id': 'llm07',
        'number': 'LLM07',
        'name': 'System Prompt Leakage',
        'model_path': 'prompt_leakage.PromptLeakageScan',
        'search_fields': ['exposure_type'],
        'result_label': lambda obj: f"Leakage scan: {obj.exposure_type}",
        'result_detail': lambda obj: f"Leakage: {'Yes' if obj.leakage_found else 'No'} | Risk: {obj.risk_score}",
        'detail_url': '/modules/prompt-leakage',
    },
    {
        'id': 'llm08',
        'number': 'LLM08',
        'name': 'Vector & Embedding Security',
        'model_path': 'vector_security.VectorDBSecurityAssessment',
        'search_fields': ['vector_db__name', 'security_score'],
        'result_label': lambda obj: f"DB Assessment: {obj.vector_db.name}",
        'result_detail': lambda obj: f"Security Score: {obj.security_score:.1f}",
        'detail_url': '/modules/vector-security',
    },
    {
        'id': 'llm09',
        'number': 'LLM09',
        'name': 'Misinformation & Hallucination',
        'model_path': 'hallucination.HallucinationFinding',
        'search_fields': ['output_text', 'hallucination_type', 'severity'],
        'result_label': lambda obj: obj.output_text[:100],
        'result_detail': lambda obj: f"Type: {obj.hallucination_type} | Score: {obj.hallucination_score}",
        'detail_url': '/modules/hallucination',
    },
    {
        'id': 'llm10',
        'number': 'LLM10',
        'name': 'Unbounded Consumption',
        'model_path': 'unbounded_consumption.TokenUsageRecord',
        'search_fields': ['usage_type'],
        'result_label': lambda obj: f"Token usage record",
        'result_detail': lambda obj: f"Tokens: {obj.tokens_used} | Cost: ${obj.cost:.2f}",
        'detail_url': '/modules/unbounded-consumption',
    },
]


class GlobalSearchView(APIView):
    """Search across all 10 OWASP module tables simultaneously."""
    permission_classes = [IsAuthenticated]

    def get(self, request):
        query = request.query_params.get('q', '').strip()
        if not query or len(query) < 2:
            return Response({
                'query': query,
                'total_results': 0,
                'results': [],
            })

        q_lower = query.lower()
        results = []

        for mod_config in SEARCH_MODULES:
            try:
                model = apps.get_model(mod_config['model_path'])
            except LookupError:
                continue

            # Build search filter across all search_fields
            filter_q = Q()
            for field in mod_config['search_fields']:
                filter_q |= Q(**{f'{field}__icontains': q_lower})

            try:
                objects = model.objects.filter(filter_q)[:5]  # Max 5 per module
            except Exception:
                continue

            for obj in objects:
                try:
                    label = mod_config['result_label'](obj)
                    detail = mod_config['result_detail'](obj)
                except Exception:
                    label = str(obj)[:100]
                    detail = ''

                results.append({
                    'module_id': mod_config['id'],
                    'module_number': mod_config['number'],
                    'module_name': mod_config['name'],
                    'label': str(label)[:150],
                    'detail': str(detail)[:200],
                    'detail_url': mod_config['detail_url'],
                    'created_at': str(getattr(obj, 'created_at', '') or ''),
                    'id': str(obj.id),
                })

        # Sort: prompt injection results first, then by module number
        results.sort(key=lambda r: (r['module_id'], r['created_at']))

        return Response({
            'query': query,
            'total_results': len(results),
            'results': results,
        })
