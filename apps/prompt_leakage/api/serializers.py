from rest_framework import serializers
from apps.prompt_leakage.models import PromptLeakageScan, PromptExposureTest, SecretInPrompt


class PromptLeakageScanSerializer(serializers.ModelSerializer):
    """Prompt leakage scan serializer."""

    class Meta:
        model = PromptLeakageScan
        fields = '__all__'
        read_only_fields = ['id', 'created_at']


class PromptExposureTestSerializer(serializers.ModelSerializer):
    """Prompt exposure test serializer."""

    class Meta:
        model = PromptExposureTest
        fields = '__all__'
        read_only_fields = ['id', 'created_at']


class SecretInPromptSerializer(serializers.ModelSerializer):
    """Secret in prompt serializer."""

    class Meta:
        model = SecretInPrompt
        fields = '__all__'
        read_only_fields = ['id', 'created_at']
