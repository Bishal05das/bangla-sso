from django.conf import settings
from django.core import signing

EMAIL_VERIFICATION_SALT = "accounts.email-verification"


def make_email_verification_token(user):
    """Signed, timestamped token bound to the user AND their current email."""
    return signing.dumps({"uid": str(user.pk), "email": user.email}, salt=EMAIL_VERIFICATION_SALT)


def read_email_verification_token(token):
    """Return (uid, email). Raises signing.BadSignature if tampered or expired."""
    data = signing.loads(
        token,
        salt=EMAIL_VERIFICATION_SALT,
        max_age=settings.EMAIL_VERIFICATION_MAX_AGE,
    )
    return data["uid"], data["email"]
