from django.http import JsonResponse
from django.urls import path


def health_check(request):
    return JsonResponse({
        'status': 'healthy',
        'service': 'GenAI Security Platform',
        'version': '1.0.0'
    })


urlpatterns = [
    path('', health_check, name='health-check'),
]
