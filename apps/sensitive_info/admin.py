from django.contrib import admin
from .models import SecretScan, PIIFinding


@admin.register(SecretScan)
class SecretScanAdmin(admin.ModelAdmin):
    list_display = ('secret_type', 'source', 'risk_level', 'is_validated', 'created_at')
    list_filter = ('secret_type', 'risk_level', 'source')


@admin.register(PIIFinding)
class PIIFindingAdmin(admin.ModelAdmin):
    list_display = ('pii_type', 'count', 'risk_level')
    list_filter = ('pii_type', 'risk_level')
