import logging
from datetime import timedelta

import requests
from django.conf import settings
from django.db import transaction
from django.utils import timezone

from .logout_tokens import make_logout_token
from .models import BackchannelLogoutDelivery, ClientLogoutConfig

logger = logging.getLogger(__name__)


def enqueue_backchannel_logouts(user, applications):
    """Queue one logout notification per app that has a back-channel logout URI."""
    configured = ClientLogoutConfig.objects.filter(application__in=applications)
    BackchannelLogoutDelivery.objects.bulk_create(
        BackchannelLogoutDelivery(application_id=config.application_id, subject=str(user.pk))
        for config in configured
    )


def post_logout_token(uri, logout_token):
    """POST the logout token to the client. Returns None on success, or an error string."""
    try:
        response = requests.post(
            uri,
            data={"logout_token": logout_token},
            timeout=settings.BACKCHANNEL_LOGOUT_TIMEOUT_SECONDS,
            allow_redirects=False,
        )
    except requests.RequestException as exc:
        return f"{type(exc).__name__}: {exc}"
    if response.status_code in (200, 204):
        return None
    return f"HTTP {response.status_code}"


def _retry_delay(attempts):
    return timedelta(seconds=30 * 2 ** (attempts - 1))  # 30s, 1m, 2m, 4m, ...


def deliver_pending(batch_size=50):
    """Send due notifications. Safe to run from several workers at once."""
    sent = 0
    with transaction.atomic():
        deliveries = list(
            BackchannelLogoutDelivery.objects.select_for_update(skip_locked=True, of=("self",))
            .select_related("application")
            .filter(
                status=BackchannelLogoutDelivery.Status.PENDING,
                next_attempt_at__lte=timezone.now(),
            )
            .order_by("next_attempt_at")[:batch_size]
        )
        for delivery in deliveries:
            try:
                uri = delivery.application.logout_config.backchannel_logout_uri
            except ClientLogoutConfig.DoesNotExist:  # config removed after queuing
                delivery.status = BackchannelLogoutDelivery.Status.FAILED
                delivery.last_error = "No back-channel logout URI configured."
                delivery.save()
                continue
            token = make_logout_token(delivery.application, delivery.subject)
            error = post_logout_token(uri, token)
            delivery.attempts += 1
            if error is None:
                delivery.status = BackchannelLogoutDelivery.Status.DELIVERED
                delivery.delivered_at = timezone.now()
                delivery.last_error = ""
                sent += 1
            else:
                delivery.last_error = error
                if delivery.attempts >= settings.BACKCHANNEL_LOGOUT_MAX_ATTEMPTS:
                    delivery.status = BackchannelLogoutDelivery.Status.FAILED
                    logger.error("Back-channel logout to %s failed permanently: %s", uri, error)
                else:
                    delivery.next_attempt_at = timezone.now() + _retry_delay(delivery.attempts)
            delivery.save()
    return sent
