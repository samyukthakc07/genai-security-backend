from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView, TokenBlacklistView

from apps.core.api.views import (
    RegisterView, UserProfileView, UpdateProfileView,
    ChangePasswordView, AuditLogListView, UserListView,
    OllamaModelsView
)
from apps.core.api.module_stats import ModuleStatsView
from apps.core.api.global_search import GlobalSearchView
from apps.core.authentication import CustomTokenObtainPairView

urlpatterns = [
    # Authentication
    path('auth/login/', CustomTokenObtainPairView.as_view(), name='auth-login'),
    path('auth/register/', RegisterView.as_view(), name='auth-register'),
    path('auth/refresh/', TokenRefreshView.as_view(), name='auth-refresh'),
    path('auth/logout/', TokenBlacklistView.as_view(), name='auth-logout'),

    # User Profile
    path('auth/me/', UserProfileView.as_view(), name='user-profile'),
    path('auth/me/update/', UpdateProfileView.as_view(), name='user-profile-update'),
    path('auth/me/change-password/', ChangePasswordView.as_view(), name='change-password'),

    # Admin
    path('users/', UserListView.as_view(), name='user-list'),
    path('audit-logs/', AuditLogListView.as_view(), name='audit-log-list'),

    # Module Stats
    path('module-stats/', ModuleStatsView.as_view(), name='module-stats'),

    # Global Search
    path('search/', GlobalSearchView.as_view(), name='global-search'),

    # Ollama Models (for quick scan)
    path('ollama-models/', OllamaModelsView.as_view(), name='ollama-models'),
]
