from django.conf import settings
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode

from .tokens import make_email_verification_token


def _send(user, subject, template_name, context):
    body = render_to_string(template_name, {"user": user, **context})
    send_mail(subject, body, from_email=None, recipient_list=[user.email])


def send_verification_email(user):
    token = make_email_verification_token(user)
    _send(
        user,
        "Verify your email address",
        "accounts/email/verify_email.txt",
        {"link": f"{settings.FRONTEND_URL}/verify-email#token={token}"},
    )


def send_account_exists_email(user):
    _send(
        user,
        "Someone tried to sign up with your email",
        "accounts/email/account_exists.txt",
        {
            "login_link": f"{settings.FRONTEND_URL}/login",
            "reset_link": f"{settings.FRONTEND_URL}/forgot-password",
        },
    )


def send_password_reset_email(user):
    uid = urlsafe_base64_encode(force_bytes(user.pk))
    token = default_token_generator.make_token(user)
    _send(
        user,
        "Reset your password",
        "accounts/email/password_reset.txt",
        {"link": f"{settings.FRONTEND_URL}/reset-password#uid={uid}&token={token}"},
    )
