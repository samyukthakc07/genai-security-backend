import json
import logging

from rest_framework import viewsets, permissions, status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.views import APIView
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import filters

from apps.prompt_injection.models import PromptScan, PromptScanBatch
from apps.prompt_injection.api.serializers import (
    PromptScanSerializer, PromptScanBatchSerializer
)
from apps.core.permissions import IsOrganizationMember
from apps.security_engine.registry import plugin_registry

logger = logging.getLogger(__name__)


class PromptScanViewSet(viewsets.ModelViewSet):
    """CRUD for Prompt Scans."""
    queryset = PromptScan.objects.select_related('scan').all()
    serializer_class = PromptScanSerializer
    permission_classes = [permissions.IsAuthenticated, IsOrganizationMember]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['scan', 'injection_type', 'is_malicious']
    search_fields = ['prompt_text']
    ordering_fields = ['risk_score', 'created_at']


class PromptScanBatchViewSet(viewsets.ModelViewSet):
    """CRUD for Prompt Scan Batches."""
    queryset = PromptScanBatch.objects.select_related('scan').all()
    serializer_class = PromptScanBatchSerializer
    permission_classes = [permissions.IsAuthenticated, IsOrganizationMember]
    filter_backends = [DjangoFilterBackend, filters.OrderingFilter]
    filterset_fields = ['scan']
    ordering_fields = ['created_at']


class QuickScanView(APIView):
    """
    Quick prompt injection scan that sends a prompt to an Ollama model
    and analyzes the response using the platform's built-in injection detector.

    POST /api/v1/prompt-injection/quick-scan/
    {
        "prompt_text": "Your prompt here",
        "model_name": "tinyllama"
    }
    """
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        prompt_text = request.data.get('prompt_text', '').strip()
        model_name = request.data.get('model_name', '').strip()

        if not prompt_text:
            return Response(
                {'error': 'prompt_text is required'},
                status=status.HTTP_400_BAD_REQUEST
            )

        if not model_name:
            return Response(
                {'error': 'model_name is required'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Step 1: Send prompt to Ollama model
        try:
            model_response = self._query_ollama(model_name, prompt_text)
        except RuntimeError as e:
            return Response(
                {'error': str(e), 'status': 'failed'},
                status=status.HTTP_502_BAD_GATEWAY
            )

        # Step 2: Run the prompt injection detector on the model's response
        injection_result = self._run_injection_detection(model_response)

        # Step 3: Also check the original prompt for injection patterns
        prompt_result = self._run_injection_detection(prompt_text)

        return Response({
            'status': 'completed',
            'model_name': model_name,
            'prompt_text': prompt_text,
            'model_response': model_response,
            'prompt_scan': {
                'is_malicious': prompt_result.get('is_malicious', False),
                'risk_score': prompt_result.get('risk_score', 0),
                'injection_type': prompt_result.get('injection_type', 'none'),
                'techniques_detected': prompt_result.get('techniques_detected', []),
                'detection_count': prompt_result.get('detection_count', 0),
            },
            'response_scan': {
                'is_malicious': injection_result.get('is_malicious', False),
                'risk_score': injection_result.get('risk_score', 0),
                'injection_type': injection_result.get('injection_type', 'none'),
                'techniques_detected': injection_result.get('techniques_detected', []),
                'detection_count': injection_result.get('detection_count', 0),
            },
        })

    def _query_ollama(self, model_name: str, prompt: str) -> str:
        """Send a prompt to an Ollama model and return the response."""
        # Normalize model name from formats like ollama:chat:tinyllama or ollama:tinyllama
        if model_name.startswith('ollama:chat:'):
            model_name = model_name[len('ollama:chat:'):]
        elif model_name.startswith('ollama:generate:'):
            model_name = model_name[len('ollama:generate:'):]
        elif model_name.startswith('ollama:'):
            model_name = model_name[len('ollama:'):]

        try:
            import ollama
            client = ollama.Client()
            response = client.generate(model=model_name, prompt=prompt)
            return response.get('response', '')
        except ImportError:
            raise RuntimeError("Ollama Python package not installed. Run: pip install ollama")
        except Exception as e:
            raise RuntimeError(f"Failed to query Ollama model '{model_name}': {e}")

    def _run_injection_detection(self, text: str) -> dict:
        """Run the platform's prompt injection detector on text."""
        if not text:
            return {
                'is_malicious': False,
                'risk_score': 0,
                'injection_type': 'none',
                'techniques_detected': [],
                'detection_count': 0,
            }

        try:
            plugin_registry.discover_plugins()
            plugin = plugin_registry.get_plugin('prompt_injection')
            result = plugin.scan_with_metrics(text)

            if result.status != 'completed':
                return {
                    'is_malicious': False,
                    'risk_score': 0,
                    'injection_type': 'none',
                    'techniques_detected': [],
                    'detection_count': 0,
                }

            findings = result.findings[0] if result.findings else None
            return {
                'is_malicious': result.summary.get('is_malicious', False) if result.summary else False,
                'risk_score': result.risk_score,
                'injection_type': result.summary.get('injection_type', 'none') if result.summary else 'none',
                'techniques_detected': result.summary.get('techniques_detected', []) if result.summary else [],
                'detection_count': result.metrics.get('detections_found', 0) if result.metrics else 0,
            }
        except Exception as e:
            logger.warning('Injection detection failed: %s', e)
            return {
                'is_malicious': False,
                'risk_score': 0,
                'injection_type': 'error',
                'techniques_detected': [],
                'detection_count': 0,
            }
