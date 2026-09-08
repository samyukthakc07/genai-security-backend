import uuid
from django.db import models
from django.utils.text import slugify


class Organization(models.Model):
    """Organization model."""

    SUBSCRIPTION_TIERS = [
        ('free', 'Free'),
        ('starter', 'Starter'),
        ('professional', 'Professional'),
        ('enterprise', 'Enterprise'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=255)
    slug = models.SlugField(max_length=255, unique=True, blank=True)
    description = models.TextField(blank=True)
    logo_url = models.URLField(max_length=500, blank=True)
    industry = models.CharField(max_length=100, blank=True)
    website = models.URLField(max_length=500, blank=True)
    is_active = models.BooleanField(default=True)
    subscription_tier = models.CharField(
        max_length=50, choices=SUBSCRIPTION_TIERS, default='free'
    )
    settings = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'organizations_organization'
        verbose_name = 'Organization'
        verbose_name_plural = 'Organizations'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['slug']),
        ]

    def __str__(self):
        return self.name

    def save(self, *args, **kwargs):
        if not self.slug:
            self.slug = slugify(self.name)[:50]
            # Ensure unique slug
            base_slug = self.slug
            counter = 1
            while Organization.objects.filter(slug=self.slug).exists():
                self.slug = f"{base_slug}-{counter}"
                counter += 1
        super().save(*args, **kwargs)


class Membership(models.Model):
    """Organization membership."""

    ROLE_CHOICES = [
        ('owner', 'Owner'),
        ('admin', 'Admin'),
        ('member', 'Member'),
        ('viewer', 'Viewer'),
        ('auditor', 'Auditor'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(
        Organization, on_delete=models.CASCADE, related_name='memberships'
    )
    user = models.ForeignKey(
        'core.User', on_delete=models.CASCADE, related_name='memberships'
    )
    role = models.CharField(max_length=50, choices=ROLE_CHOICES, default='member')
    is_default = models.BooleanField(default=False)
    joined_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'organizations_membership'
        verbose_name = 'Membership'
        verbose_name_plural = 'Memberships'
        unique_together = ['organization', 'user']

    def __str__(self):
        return f'{self.user.email} - {self.organization.name} ({self.role})'
