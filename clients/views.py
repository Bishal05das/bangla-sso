from urllib.parse import urlencode

from django.conf import settings
from django.http import HttpResponseRedirect, JsonResponse
from oauth2_provider.exceptions import InvalidOIDCClientError
from oauth2_provider.models import get_application_model
from oauth2_provider.views import RPInitiatedLogoutView

from .sessions import end_sso_session


class SSOLogoutView(RPInitiatedLogoutView):
    """
    OIDC RP-Initiated Logout that:
    - signs the user out of EVERY client app (token revocation + back-channel logout),
    - asks for confirmation in the Next.js frontend instead of a Django template,
    - returns JSON errors instead of rendering HTML.
    """

    def get_request_application(self, id_token, client_id):
        if client_id:
            try:
                return get_application_model().objects.get(client_id=client_id)
            except get_application_model().DoesNotExist:
                raise InvalidOIDCClientError()  # DOT would crash with a 500 here
        return super().get_request_application(id_token, client_id)

    def do_logout(self, application=None, post_logout_redirect_uri=None, state=None, token_user=None):
        user = token_user or self.request.user
        if user.is_authenticated:
            end_sso_session(user)
        return super().do_logout(application, post_logout_redirect_uri, state, token_user)

    def render_to_response(self, context, **response_kwargs):
        # DOT only renders a template to ask "Do you want to log out?".
        # Send the user to the frontend's confirmation page instead; it POSTs back here.
        params = {key: value for key, value in self.oidc_data.items() if value}
        query = f"?{urlencode(params)}" if params else ""
        return HttpResponseRedirect(f"{settings.FRONTEND_URL}/logout/confirm{query}")

    def error_response(self, error):
        return JsonResponse(
            {"error": error.error, "error_description": error.description},
            status=error.status_code,
        )

    def form_invalid(self, form):
        return JsonResponse(
            {"error": "invalid_request", "error_description": "Invalid logout request."},
            status=400,
        )
