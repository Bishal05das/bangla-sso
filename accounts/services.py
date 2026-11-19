from axes.utils import reset as axes_reset



def unlock_user(user):
    """Clear brute-force lockouts for this user (e.g. after a successful password reset)."""
    axes_reset(username=user.email)
