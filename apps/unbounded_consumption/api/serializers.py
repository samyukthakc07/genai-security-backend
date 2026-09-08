from rest_framework import serializers
from apps.unbounded_consumption.models import (
    TokenUsageRecord, CostMonitor, DoSEvent, RateLimitAssessment
)


class TokenUsageRecordSerializer(serializers.ModelSerializer):
    """Token usage record serializer."""

    class Meta:
        model = TokenUsageRecord
        fields = '__all__'
        read_only_fields = ['id', 'recorded_at']


class CostMonitorSerializer(serializers.ModelSerializer):
    """Cost monitor serializer."""

    class Meta:
        model = CostMonitor
        fields = '__all__'
        read_only_fields = ['id', 'created_at']


class DoSEventSerializer(serializers.ModelSerializer):
    """DoS event serializer."""

    class Meta:
        model = DoSEvent
        fields = '__all__'
        read_only_fields = ['id', 'detected_at']


class RateLimitAssessmentSerializer(serializers.ModelSerializer):
    """Rate limit assessment serializer."""

    class Meta:
        model = RateLimitAssessment
        fields = '__all__'
        read_only_fields = ['id', 'created_at']
