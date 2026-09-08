"""
Module Stats API - Aggregated counts across all 10 OWASP modules.
"""
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.prompt_injection.models import PromptScan
from apps.sensitive_info.models import SecretScan
from apps.supply_chain.models import DependencyScan
from apps.data_poisoning.models import TrainingDataValidation
from apps.output_handling.models import OutputSanitization
from apps.excessive_agency.models import AgentPermission
from apps.prompt_leakage.models import PromptLeakageScan
from apps.vector_security.models import VectorDBSecurityAssessment
from apps.hallucination.models import HallucinationFinding
from apps.unbounded_consumption.models import TokenUsageRecord


MODULE_ENDPOINTS = [
    {
        'id': 'llm01',
        'number': 'LLM01',
        'name': 'Prompt Injection',
        'model': PromptScan,
        'slug': 'prompt-injection',
        'category': 'high_risk',
    },
    {
        'id': 'llm02',
        'number': 'LLM02',
        'name': 'Sensitive Information Disclosure',
        'model': SecretScan,
        'slug': 'sensitive-info',
        'category': 'high_risk',
    },
    {
        'id': 'llm03',
        'number': 'LLM03',
        'name': 'Supply Chain Security',
        'model': DependencyScan,
        'slug': 'supply-chain',
        'category': 'medium',
    },
    {
        'id': 'llm04',
        'number': 'LLM04',
        'name': 'Data and Model Poisoning',
        'model': TrainingDataValidation,
        'slug': 'data-poisoning',
        'category': 'medium',
    },
    {
        'id': 'llm05',
        'number': 'LLM05',
        'name': 'Improper Output Handling',
        'model': OutputSanitization,
        'slug': 'output-handling',
        'category': 'high_risk',
    },
    {
        'id': 'llm06',
        'number': 'LLM06',
        'name': 'Excessive Agency',
        'model': AgentPermission,
        'slug': 'excessive-agency',
        'category': 'high_risk',
    },
    {
        'id': 'llm07',
        'number': 'LLM07',
        'name': 'System Prompt Leakage',
        'model': PromptLeakageScan,
        'slug': 'prompt-leakage',
        'category': 'medium',
    },
    {
        'id': 'llm08',
        'number': 'LLM08',
        'name': 'Vector and Embedding Security',
        'model': VectorDBSecurityAssessment,
        'slug': 'vector-security',
        'category': 'medium',
    },
    {
        'id': 'llm09',
        'number': 'LLM09',
        'name': 'Misinformation & Hallucination',
        'model': HallucinationFinding,
        'slug': 'hallucination',
        'category': 'medium',
    },
    {
        'id': 'llm10',
        'number': 'LLM10',
        'name': 'Unbounded Consumption',
        'model': TokenUsageRecord,
        'slug': 'unbounded-consumption',
        'category': 'low_risk',
    },
]

# Modules that have scan/create forms (actionable)
SCAN_ACTION_MODULES = {'llm01', 'llm02', 'llm04', 'llm05', 'llm07', 'llm09', 'llm10'}
# Modules that are monitoring/observation based
ACTIVE_MONITOR_MODULES = {'llm06', 'llm08'}


class ModuleStatsView(APIView):
    """Return live aggregated stats across all OWASP modules."""
    permission_classes = [IsAuthenticated]

    def get(self, request):
        per_module = []
        total_records = 0

        for mod in MODULE_ENDPOINTS:
            count = mod['model'].objects.count()
            total_records += count

            per_module.append({
                'id': mod['id'],
                'number': mod['number'],
                'name': mod['name'],
                'slug': mod['slug'],
                'category': mod['category'],
                'record_count': count,
                'has_data': count > 0,
            })

        # Derived stats
        modules_with_data = sum(1 for m in per_module if m['has_data'])
        high_risk_with_data = sum(
            1 for m in per_module
            if m['category'] == 'high_risk' and m['has_data']
        )
        scan_actions = sum(
            1 for m in per_module
            if m['id'] in SCAN_ACTION_MODULES and m['has_data']
        )

        return Response({
            'total_modules': len(MODULE_ENDPOINTS),
            'total_records': total_records,
            'modules_with_data': modules_with_data,
            'high_risk_with_data': high_risk_with_data,
            'scan_actions_count': scan_actions,
            'active_monitors': len(ACTIVE_MONITOR_MODULES),
            'owasp_coverage': 100,
            'modules': per_module,
        })
