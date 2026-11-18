from django import forms
from django.contrib.auth.forms import AuthenticationForm


class EmailAuthenticationForm(AuthenticationForm):
    """Login form that takes an email and normalizes it before authenticating."""

    username = forms.EmailField(label="Email")

    def clean_username(self):
        return self.cleaned_data["username"].strip().lower()

    def confirm_login_allowed(self, user):
        super().confirm_login_allowed(user)  # keeps Django's inactive-user check
        if not user.email_verified:
            raise forms.ValidationError(
                "Please verify your email address before signing in.",
                code="email_unverified",
            )
