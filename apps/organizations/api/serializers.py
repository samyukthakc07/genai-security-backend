from rest_framework import serializers
from apps.core.api.serializers import UserSerializer
from apps.organizations.models import Organization, Membership


class MembershipSerializer(serializers.ModelSerializer):
    """Membership serializer."""
    user = UserSerializer(read_only=True)
    user_id = serializers.UUIDField(write_only=True)

    class Meta:
        model = Membership
        fields = ['id', 'organization', 'user', 'user_id', 'role',
                  'is_default', 'joined_at']
        read_only_fields = ['id', 'organization', 'joined_at']


class OrganizationListSerializer(serializers.ModelSerializer):
    """Compact organization serializer for lists."""
    member_count = serializers.SerializerMethodField()
    role = serializers.SerializerMethodField()

    class Meta:
        model = Organization
        fields = ['id', 'name', 'slug', 'description', 'logo_url',
                  'is_active', 'subscription_tier', 'member_count',
                  'role', 'created_at']

    def get_member_count(self, obj):
        return obj.memberships.count()

    def get_role(self, obj):
        request = self.context.get('request')
        if request and request.user:
            membership = obj.memberships.filter(user=request.user).first()
            return membership.role if membership else None
        return None


class OrganizationDetailSerializer(serializers.ModelSerializer):
    """Detailed organization serializer."""
    members = MembershipSerializer(source='memberships', many=True, read_only=True)
    member_count = serializers.SerializerMethodField()

    class Meta:
        model = Organization
        fields = ['id', 'name', 'slug', 'description', 'logo_url',
                  'industry', 'website', 'is_active', 'subscription_tier',
                  'settings', 'members', 'member_count', 'created_at', 'updated_at']
        read_only_fields = ['id', 'created_at', 'updated_at']

    def get_member_count(self, obj):
        return obj.memberships.count()


class OrganizationCreateSerializer(serializers.ModelSerializer):
    """Organization creation serializer."""

    class Meta:
        model = Organization
        fields = ['name', 'description', 'logo_url', 'industry', 'website']

    def create(self, validated_data):
        org = super().create(validated_data)
        # Add creator as owner
        request = self.context.get('request')
        if request and request.user:
            Membership.objects.create(
                organization=org,
                user=request.user,
                role='owner',
                is_default=True
            )
        return org


class InviteMemberSerializer(serializers.Serializer):
    """Invite member to organization."""
    email = serializers.EmailField()
    role = serializers.ChoiceField(choices=Membership.ROLE_CHOICES, default='member')
