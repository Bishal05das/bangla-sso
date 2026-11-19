from django.db import models
from django.utils import timezone
from oauth2_provider.settings import oauth2_settings


class ClientLogoutConfig(models.Model):
    """Per-client settings that django-oauth-toolkit's Application model doesn't have."""

    application = models.OneToOneField(
        oauth2_settings.APPLICATION_MODEL,
        on_delete=models.CASCADE,
        related_name="logout_config",
    )
    backchannel_logout_uri = models.URLField(
        max_length=500,
        help_text="Server-to-server URL that receives OIDC back-channel logout tokens.",
    )

    def __str__(self):
        return f"Logout config for {self.application}"


class BackchannelLogoutDelivery(models.Model):
    """Outbox row: one logout notification to one client app, retried until delivered."""

    class Status(models.TextChoices):
        PENDING = "pending", "Pending"
        DELIVERED = "delivered", "Delivered"
        FAILED = "failed", "Failed"

    application = models.ForeignKey(oauth2_settings.APPLICATION_MODEL, on_delete=models.CASCADE)
    subject = models.CharField(max_length=255, help_text="The user's OIDC 'sub' value.")
    status = models.CharField(max_length=10, choices=Status.choices, default=Status.PENDING)
    attempts = models.PositiveSmallIntegerField(default=0)
    next_attempt_at = models.DateTimeField(default=timezone.now)
    last_error = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    delivered_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        indexes = [models.Index(fields=["status", "next_attempt_at"])]
        verbose_name_plural = "back-channel logout deliveries"

    def __str__(self):
        return f"{self.application} / {self.subject} ({self.status})"
