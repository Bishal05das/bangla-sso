from django.contrib.auth import login, logout
from django.contrib.auth.tokens import default_token_generator
from django.core import signing
from django.core.exceptions import ValidationError
from django.db import IntegrityError, transaction
from django.utils.decorators import method_decorator
from django.utils.http import url_has_allowed_host_and_scheme, urlsafe_base64_decode
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_protect, ensure_csrf_cookie
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle
from rest_framework.views import APIView
from clients.sessions import end_sso_session



from .emails import send_account_exists_email, send_password_reset_email, send_verification_email
from .forms import EmailAuthenticationForm
from .models import User
from .serializers import (
    EmailSerializer,
    EmailVerificationSerializer,
    PasswordResetConfirmSerializer,
    RegisterSerializer,
    UserSerializer,
    password_errors,
)
from .services import unlock_user
from .tokens import read_email_verification_token


DEFAULT_REDIRECT = "/"


def safe_redirect_target(request, target):
    """Only allow redirects back to this same site; anything else falls back to '/'."""
    if target and url_has_allowed_host_and_scheme(
        target,
        allowed_hosts={request.get_host()},
        require_https=request.is_secure(),
    ):
        return target
    return DEFAULT_REDIRECT


@method_decorator([ensure_csrf_cookie, never_cache], name="dispatch")
class CsrfTokenView(APIView):
    authentication_classes = []
    permission_classes = [AllowAny]

    def get(self, request):
        return Response(status=status.HTTP_204_NO_CONTENT)


@method_decorator([csrf_protect, never_cache], name="dispatch")
class LoginView(APIView):
    authentication_classes = []
    permission_classes = [AllowAny]

    def post(self, request):
        # Pass Django's own HttpRequest: axes flags lockouts on it,
        # and AxesMiddleware reads those flags from that same object.
        django_request = request._request

        form = EmailAuthenticationForm(
            django_request,
            data={
                "username": request.data.get("email", ""),
                "password": request.data.get("password", ""),
            },
        )
        if not form.is_valid():
            errors = form.errors.get_json_data()
            if "username" in errors:
                errors["email"] = errors.pop("username")
            return Response({"errors": errors}, status=status.HTTP_400_BAD_REQUEST)

        user = form.get_user()
        login(django_request, user)
        return Response({
            "user": UserSerializer(user).data,
            "redirect_to": safe_redirect_target(request, request.data.get("next")),
        })


class LogoutView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        if request.user.is_authenticated:
            end_sso_session(request.user)
        logout(request._request)
        return Response(status=status.HTTP_204_NO_CONTENT)


@method_decorator(never_cache, name="dispatch")
class MeView(APIView):
    def get(self, request):
        return Response(UserSerializer(request.user).data)


# --- Registration, email verification, password reset ---

EMAIL_SENT_RESPONSE = {
    "detail": "If the details are valid, we've sent an email with the next steps.",
}
INVALID_LINK_RESPONSE = {
    "detail": "This link is invalid or has expired.",
    "code": "invalid_token",
}


@method_decorator([csrf_protect, never_cache], name="dispatch")
class PublicAuthView(APIView):
    """Base for anonymous, rate-limited, CSRF-protected auth endpoints."""

    authentication_classes = []
    permission_classes = [AllowAny]
    throttle_classes = [ScopedRateThrottle]


class RegisterView(PublicAuthView):
    throttle_scope = "auth-email"

    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        if not serializer.is_valid():
            return Response({"errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
        data = serializer.validated_data

        existing = User.objects.filter(email__iexact=data["email"]).first()
        if existing is not None:
            send_account_exists_email(existing)
        else:
            try:
                with transaction.atomic():
                    user = User.objects.create_user(
                        email=data["email"],
                        password=data["password"],
                        first_name=data["first_name"],
                        last_name=data["last_name"],
                    )
            except IntegrityError:
                pass  # lost a race with a concurrent sign-up for the same email
            else:
                send_verification_email(user)

        # Same response whether or not the email was already registered.
        return Response(EMAIL_SENT_RESPONSE, status=status.HTTP_202_ACCEPTED)


class VerifyEmailView(PublicAuthView):
    throttle_scope = "auth-token"

    def post(self, request):
        serializer = EmailVerificationSerializer(data=request.data)
        if not serializer.is_valid():
            return Response({"errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
        try:
            uid, email = read_email_verification_token(serializer.validated_data["token"])
        except signing.BadSignature:  # includes SignatureExpired
            return Response(INVALID_LINK_RESPONSE, status=status.HTTP_400_BAD_REQUEST)

        user = User.objects.filter(pk=uid, email=email, is_active=True).first()
        if user is None:
            return Response(INVALID_LINK_RESPONSE, status=status.HTTP_400_BAD_REQUEST)

        if not user.email_verified:
            user.email_verified = True
            user.save(update_fields=["email_verified"])
        return Response({"detail": "Your email address has been verified."})


class ResendVerificationView(PublicAuthView):
    throttle_scope = "auth-email"

    def post(self, request):
        serializer = EmailSerializer(data=request.data)
        if not serializer.is_valid():
            return Response({"errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
        user = User.objects.filter(
            email__iexact=serializer.validated_data["email"], is_active=True, email_verified=False
        ).first()
        if user is not None:
            send_verification_email(user)
        return Response(EMAIL_SENT_RESPONSE, status=status.HTTP_202_ACCEPTED)


class PasswordResetRequestView(PublicAuthView):
    throttle_scope = "auth-email"

    def post(self, request):
        serializer = EmailSerializer(data=request.data)
        if not serializer.is_valid():
            return Response({"errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
        user = User.objects.filter(email__iexact=serializer.validated_data["email"], is_active=True).first()
        if user is not None and user.has_usable_password():
            send_password_reset_email(user)
        return Response(EMAIL_SENT_RESPONSE, status=status.HTTP_202_ACCEPTED)


def _user_from_uidb64(uidb64):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        return User.objects.get(pk=uid, is_active=True)
    except (TypeError, ValueError, OverflowError, ValidationError, User.DoesNotExist):
        return None


class PasswordResetConfirmView(PublicAuthView):
    throttle_scope = "auth-token"

    def post(self, request):
        serializer = PasswordResetConfirmSerializer(data=request.data)
        if not serializer.is_valid():
            return Response({"errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
        data = serializer.validated_data

        user = _user_from_uidb64(data["uid"])
        if user is None or not default_token_generator.check_token(user, data["token"]):
            return Response(INVALID_LINK_RESPONSE, status=status.HTTP_400_BAD_REQUEST)

        errors = password_errors(data["new_password"], user)
        if errors:
            return Response({"errors": {"new_password": errors}}, status=status.HTTP_400_BAD_REQUEST)

        user.set_password(data["new_password"])
        user.email_verified = True  # the reset link proved they control this inbox
        user.save(update_fields=["password", "email_verified"])

        end_sso_session(user)  # sign out of every client app
        unlock_user(user)          # clear brute-force lockout
        return Response({"detail": "Your password has been reset. You can now sign in."})
