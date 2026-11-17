import base64
import hashlib
import json
import secrets
from urllib.parse import parse_qs, urlparse

from django.conf import settings
from django.test import TestCase
from django.urls import reverse
from jwcrypto import jwk, jwt
from oauth2_provider.models import get_application_model

from accounts.models import User

Application = get_application_model()

CLIENT_ID = "billing"
CLIENT_SECRET = "billing-test-secret"
REDIRECT_URI = "https://billing.example.com/oidc/callback/"


def make_pkce_pair():
    verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    return verifier, challenge


class OIDCTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user(
            "alice@example.com",
            "correct-horse-battery-staple",
            first_name="Alice",
            last_name="Smith",
            email_verified=True,
        )
        Application.objects.create(
            name="Billing",
            client_id=CLIENT_ID,
            client_secret=CLIENT_SECRET,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
            redirect_uris=REDIRECT_URI,
            algorithm=Application.RS256_ALGORITHM,
            skip_authorization=True,
        )

    def authorize(self, **overrides):
        verifier, challenge = make_pkce_pair()
        params = {
            "response_type": "code",
            "client_id": CLIENT_ID,
            "redirect_uri": REDIRECT_URI,
            "scope": "openid profile email",
            "state": "state-123",
            "nonce": "nonce-456",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
        params.update(overrides)
        params = {k: v for k, v in params.items() if v is not None}
        response = self.client.get(reverse("oauth2_provider:authorize"), params)
        return response, verifier

    def get_code(self, **overrides):
        self.client.force_login(self.user)
        response, verifier = self.authorize(**overrides)
        self.assertEqual(response.status_code, 302)
        query = parse_qs(urlparse(response.url).query)
        return query["code"][0], verifier

    def exchange(self, code, verifier, **overrides):
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "code_verifier": verifier,
        }
        data.update(overrides)
        return self.client.post(reverse("oauth2_provider:token"), data)

    def verify_id_token(self, id_token):
        """Verify the signature exactly as a client app would: using the public JWKS."""
        jwks = self.client.get(reverse("oauth2_provider:jwks-info")).content.decode()
        token = jwt.JWT(jwt=id_token, key=jwk.JWKSet.from_json(jwks), algs=["RS256"])
        return json.loads(token.claims)


class DiscoveryTests(OIDCTestCase):
    def test_discovery_document_advertises_issuer_and_endpoints(self):
        doc = self.client.get("/o/.well-known/openid-configuration").json()
        issuer = settings.OAUTH2_PROVIDER["OIDC_ISS_ENDPOINT"]
        self.assertEqual(doc["issuer"], issuer)
        self.assertTrue(doc["authorization_endpoint"].startswith(issuer.rsplit("/o", 1)[0]))
        self.assertIn("RS256", doc["id_token_signing_alg_values_supported"])

    def test_jwks_publishes_only_public_key(self):
        keys = self.client.get(reverse("oauth2_provider:jwks-info")).json()["keys"]
        self.assertEqual(len(keys), 1)
        self.assertEqual(keys[0]["kty"], "RSA")
        for private_part in ("d", "p", "q", "dp", "dq", "qi"):
            self.assertNotIn(private_part, keys[0])

    def test_application_management_views_are_not_exposed(self):
        self.client.force_login(self.user)
        for path in ("/o/applications/", "/o/applications/register/", "/o/authorized_tokens/"):
            with self.subTest(path=path):
                self.assertEqual(self.client.get(path).status_code, 404)


class AuthorizationCodeFlowTests(OIDCTestCase):
    def test_anonymous_user_is_sent_to_frontend_login(self):
        response, _ = self.authorize()
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.url.startswith("/login/?next=/o/authorize/"))

    def test_logged_in_user_gets_code_and_state_back(self):
        self.client.force_login(self.user)
        response, _ = self.authorize()
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.url.startswith(REDIRECT_URI))
        query = parse_qs(urlparse(response.url).query)
        self.assertIn("code", query)
        self.assertEqual(query["state"], ["state-123"])

    def test_full_flow_returns_valid_signed_id_token(self):
        code, verifier = self.get_code()
        response = self.exchange(code, verifier)
        self.assertEqual(response.status_code, 200)
        body = response.json()
        for key in ("access_token", "refresh_token", "id_token"):
            self.assertIn(key, body)

        claims = self.verify_id_token(body["id_token"])
        self.assertEqual(claims["iss"], settings.OAUTH2_PROVIDER["OIDC_ISS_ENDPOINT"])
        self.assertEqual(claims["aud"], CLIENT_ID)
        self.assertEqual(claims["sub"], str(self.user.pk))
        self.assertEqual(claims["nonce"], "nonce-456")
        self.assertEqual(claims["email"], "alice@example.com")
        self.assertTrue(claims["email_verified"])
        self.assertEqual(claims["name"], "Alice Smith")

    def test_scopes_limit_claims(self):
        code, verifier = self.get_code(scope="openid")
        claims = self.verify_id_token(self.exchange(code, verifier).json()["id_token"])
        self.assertEqual(claims["sub"], str(self.user.pk))
        for claim in ("email", "email_verified", "name", "given_name"):
            self.assertNotIn(claim, claims)

    def test_userinfo_returns_claims_for_access_token(self):
        code, verifier = self.get_code()
        access_token = self.exchange(code, verifier).json()["access_token"]
        self.client.logout()
        response = self.client.get(
            reverse("oauth2_provider:user-info"),
            HTTP_AUTHORIZATION=f"Bearer {access_token}",
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["email"], "alice@example.com")


class SecurityTests(OIDCTestCase):
    def test_pkce_is_required(self):
        self.client.force_login(self.user)
        response, _ = self.authorize(code_challenge=None, code_challenge_method=None)
        query = parse_qs(urlparse(response.url).query)
        self.assertNotIn("code", query)
        self.assertEqual(query["error"], ["invalid_request"])

    def test_wrong_code_verifier_is_rejected(self):
        code, _ = self.get_code()
        response = self.exchange(code, "a-completely-different-verifier-value-" + "x" * 20)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["error"], "invalid_grant")

    def test_code_cannot_be_used_twice(self):
        code, verifier = self.get_code()
        self.assertEqual(self.exchange(code, verifier).status_code, 200)
        response = self.exchange(code, verifier)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["error"], "invalid_grant")

    def test_wrong_client_secret_is_rejected(self):
        code, verifier = self.get_code()
        response = self.exchange(code, verifier, client_secret="wrong-secret")
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json()["error"], "invalid_client")

    def test_unregistered_redirect_uri_is_never_redirected_to(self):
        self.client.force_login(self.user)
        response, _ = self.authorize(redirect_uri="https://evil.example.com/callback/")
        self.assertNotEqual(response.status_code, 302)

    def test_client_secret_is_stored_hashed(self):
        app = Application.objects.get(client_id=CLIENT_ID)
        self.assertNotEqual(app.client_secret, CLIENT_SECRET)
