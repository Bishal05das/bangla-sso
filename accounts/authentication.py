from rest_framework.authentication import SessionAuthentication


class IdPSessionAuthentication(SessionAuthentication):
    """Session auth that returns 401 (not 403) when the user is not logged in."""

    def authenticate_header(self, request):
        return "Session"
