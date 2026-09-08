"""
GenAI Security Platform - Root URL Configuration
"""
from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.views.generic.base import RedirectView
from django.conf.urls.static import static

# API version prefix
API_PREFIX = 'api/v1/'

urlpatterns = [
    # Redirect root to frontend dev server when developing
    path('', RedirectView.as_view(url='http://localhost:5178/')),
    # Admin
    path('admin/', admin.site.urls),

    # Health check
    path('health/', include('apps.core.api.health_urls')),

    # API v1
    path(API_PREFIX, include('apps.core.api.urls')),          # Auth, Users
    path(f'{API_PREFIX}organizations/', include('apps.organizations.api.urls')),
    path(f'{API_PREFIX}projects/', include('apps.projects.api.urls')),

    # AI Assets
    path(f'{API_PREFIX}ai-assets/', include('apps.ai_assets.api.urls')),

    # Scans
    path(f'{API_PREFIX}scans/', include('apps.scans.api.urls')),

    # Findings
    path(f'{API_PREFIX}findings/', include('apps.findings.api.urls')),

    # Compliance
    path(f'{API_PREFIX}compliance/', include('apps.compliance.api.urls')),

    # OWASP LLM01 - Prompt Injection
    path(f'{API_PREFIX}prompt-injection/', include('apps.prompt_injection.api.urls')),

    # OWASP LLM02 - Sensitive Information Disclosure
    path(f'{API_PREFIX}sensitive-info/', include('apps.sensitive_info.api.urls')),

    # OWASP LLM03 - Supply Chain Security
    path(f'{API_PREFIX}supply-chain/', include('apps.supply_chain.api.urls')),

    # OWASP LLM04 - Data and Model Poisoning
    path(f'{API_PREFIX}data-poisoning/', include('apps.data_poisoning.api.urls')),

    # OWASP LLM05 - Improper Output Handling
    path(f'{API_PREFIX}output-handling/', include('apps.output_handling.api.urls')),

    # OWASP LLM06 - Excessive Agency
    path(f'{API_PREFIX}excessive-agency/', include('apps.excessive_agency.api.urls')),

    # OWASP LLM07 - System Prompt Leakage
    path(f'{API_PREFIX}prompt-leakage/', include('apps.prompt_leakage.api.urls')),

    # OWASP LLM08 - Vector and Embedding Security
    path(f'{API_PREFIX}vector-security/', include('apps.vector_security.api.urls')),

    # OWASP LLM09 - Misinformation and Hallucination
    path(f'{API_PREFIX}hallucination/', include('apps.hallucination.api.urls')),

    # OWASP LLM10 - Unbounded Consumption
    path(f'{API_PREFIX}unbounded-consumption/', include('apps.unbounded_consumption.api.urls')),

    # Mock LLM endpoint
    path(f'{API_PREFIX}llm/', include('apps.core.api.llm_urls')),
]

# Serve media files in development
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
