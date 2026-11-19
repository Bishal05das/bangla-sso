from oauth2_provider.models import (
    get_access_token_model,
    get_application_model,
    get_id_token_model,
    get_refresh_token_model,
)

from .backchannel import enqueue_backchannel_logouts


def applications_signed_in(user):
    """Client apps that currently hold tokens for this user."""
    app_ids = set()
    for model, extra in (
        (get_access_token_model(), {}),
        (get_refresh_token_model(), {"revoked__isnull": True}),
        (get_id_token_model(), {}),
    ):
        app_ids.update(
            model.objects.filter(user=user, **extra).values_list("application_id", flat=True)
        )
    app_ids.discard(None)
    return get_application_model().objects.filter(pk__in=app_ids)


def revoke_oauth_tokens(user):
    """Revoke every refresh, access, and ID token issued to this user, in all apps."""
    for refresh_token in get_refresh_token_model().objects.filter(user=user, revoked__isnull=True):
        refresh_token.revoke()  # also revokes its access token
    for access_token in get_access_token_model().objects.filter(user=user):
        access_token.revoke()
    get_id_token_model().objects.filter(user=user).delete()


def end_sso_session(user):
    """Sign the user out of every client app: revoke tokens and notify apps' back-ends."""
    applications = list(applications_signed_in(user))
    revoke_oauth_tokens(user)
    enqueue_backchannel_logouts(user, applications)
