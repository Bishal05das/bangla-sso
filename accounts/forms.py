from django import forms
from django.contrib.auth.forms import AuthenticationForm


class EmailAuthenticationForm(AuthenticationForm):
    """Login form that takes an email and normalizes it before authenticating."""

    username = forms.EmailField(label="Email")

    def clean_username(self):
        return self.cleaned_data["username"].strip().lower()
