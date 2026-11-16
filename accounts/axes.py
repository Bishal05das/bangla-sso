from django.http import JsonResponse


def get_axes_username(request, credentials):
    """Normalize the username axes tracks, so case variants share one lockout counter."""
    username = (credentials or {}).get("username")
    if not username and request is not None:
        username = request.POST.get("username")
    return (username or "").strip().lower()


def lockout_response(request, original_response=None, credentials=None):
    """Return a JSON 429 instead of axes' default HTML page."""
    return JsonResponse(
        {"detail": "Too many failed sign-in attempts. Try again later.", "code": "locked_out"},
        status=429,
    )
