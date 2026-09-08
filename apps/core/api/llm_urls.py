from django.urls import path
from apps.core.api import views as core_views

urlpatterns = [
    path('generate/', core_views.MockLLMGenerateView.as_view(), name='llm-generate'),
]