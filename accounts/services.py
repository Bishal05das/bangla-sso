from axes.utils import reset as axes_reset
from oauth2_provider.models import get_access_token_model, get_refresh_token_model


def revoke_oauth_tokens(user):
    """Revoke every refresh and access token issued to this user, in all apps."""
    for refresh_token in get_refresh_token_model().objects.filter(user=user, revoked__isnull=True):
        refresh_token.revoke()  # also revokes its access token
    for access_token in get_access_token_model().objects.filter(user=user):
        access_token.revoke()


def unlock_user(user):
    """Clear brute-force lockouts for this user (e.g. after a successful password reset)."""
    axes_reset(username=user.email)
