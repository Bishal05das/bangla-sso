from django.contrib.auth import login, logout
from django.utils.decorators import method_decorator
from django.utils.http import url_has_allowed_host_and_scheme
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_protect, ensure_csrf_cookie
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from .forms import EmailAuthenticationForm
from .serializers import UserSerializer

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
        logout(request._request)
        return Response(status=status.HTTP_204_NO_CONTENT)


@method_decorator(never_cache, name="dispatch")
class MeView(APIView):
    def get(self, request):
        return Response(UserSerializer(request.user).data)
