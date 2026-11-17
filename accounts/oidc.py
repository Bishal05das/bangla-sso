from oauth2_provider.oauth2_validators import OAuth2Validator


class IdPOAuth2Validator(OAuth2Validator):
    """Adds standard OIDC claims about the user to ID tokens and /userinfo."""

    def get_additional_claims(self, request):
        user = request.user
        return {
            "email": user.email,
            "email_verified": user.email_verified,
            "given_name": user.first_name,
            "family_name": user.last_name,
            "name": user.get_full_name(),
        }
