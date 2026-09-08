from rest_framework import serializers
from apps.prompt_injection.models import PromptScan, PromptScanBatch


class PromptScanSerializer(serializers.ModelSerializer):
    """Prompt scan serializer."""

    class Meta:
        model = PromptScan
        fields = '__all__'
        read_only_fields = ['id', 'created_at']


class PromptScanBatchSerializer(serializers.ModelSerializer):
    """Prompt scan batch serializer."""

    class Meta:
        model = PromptScanBatch
        fields = '__all__'
        read_only_fields = ['id', 'created_at']
