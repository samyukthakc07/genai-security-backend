from django.contrib import admin
from .models import AIScan


@admin.register(AIScan)
class AIScanAdmin(admin.ModelAdmin):
    list_display = ('name', 'scan_type', 'status', 'project', 'progress', 'created_at')
    list_filter = ('scan_type', 'status', 'created_at')
    search_fields = ('name',)
    readonly_fields = ('created_at', 'updated_at')
