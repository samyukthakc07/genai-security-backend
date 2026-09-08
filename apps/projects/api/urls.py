from django.urls import path
from apps.projects.api.views import ProjectListView, ProjectDetailView

urlpatterns = [
    path('', ProjectListView.as_view(), name='project-list'),
    path('<uuid:pk>/', ProjectDetailView.as_view(), name='project-detail'),
]
