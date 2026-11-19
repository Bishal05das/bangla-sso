import time
import uuid

from jwcrypto import jwt
from oauth2_provider.settings import oauth2_settings
from oauth2_provider.utils import jwk_from_pem

BACKCHANNEL_LOGOUT_EVENT = "http://schemas.openid.net/event/backchannel-logout"
LOGOUT_TOKEN_LIFETIME_SECONDS = 120


def make_logout_token(application, subject):
    """Build a signed OIDC Back-Channel Logout token (spec section 2.4)."""
    key = jwk_from_pem(oauth2_settings.OIDC_RSA_PRIVATE_KEY)
    now = int(time.time())
    claims = {
        "iss": oauth2_settings.OIDC_ISS_ENDPOINT,
        "aud": application.client_id,
        "iat": now,
        "exp": now + LOGOUT_TOKEN_LIFETIME_SECONDS,
        "jti": str(uuid.uuid4()),
        "sub": subject,
        "events": {BACKCHANNEL_LOGOUT_EVENT: {}},
    }
    header = {"alg": "RS256", "typ": "logout+jwt", "kid": key.thumbprint()}
    token = jwt.JWT(header=header, claims=claims)
    token.make_signed_token(key)
    return token.serialize()
