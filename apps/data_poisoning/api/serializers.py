from rest_framework import serializers
from apps.data_poisoning.models import TrainingDataValidation, RAGDocumentValidation, DatasetIntegrityCheck


class TrainingDataValidationSerializer(serializers.ModelSerializer):
    """Training data validation serializer."""

    class Meta:
        model = TrainingDataValidation
        fields = '__all__'
        read_only_fields = ['id', 'created_at']


class RAGDocumentValidationSerializer(serializers.ModelSerializer):
    """RAG document validation serializer."""

    class Meta:
        model = RAGDocumentValidation
        fields = '__all__'
        read_only_fields = ['id', 'created_at']


class DatasetIntegrityCheckSerializer(serializers.ModelSerializer):
    """Dataset integrity check serializer."""

    class Meta:
        model = DatasetIntegrityCheck
        fields = '__all__'
        read_only_fields = ['id', 'created_at']
