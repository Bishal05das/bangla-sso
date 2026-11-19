import json
from datetime import timedelta
from io import StringIO
from unittest import mock

import requests
from django.conf import settings
from django.core.management import CommandError, call_command
from django.urls import reverse
from django.utils import timezone
from jwcrypto import jwk, jwt
from oauth2_provider.models import (
    get_access_token_model,
    get_application_model,
    get_id_token_model,
    get_refresh_token_model,
)

from accounts.models import User
from accounts.test_oidc import CLIENT_ID, OIDCTestCase
from clients.backchannel import deliver_pending
from clients.logout_tokens import BACKCHANNEL_LOGOUT_EVENT
from clients.models import BackchannelLogoutDelivery, ClientLogoutConfig

Application = get_application_model()

POST_LOGOUT_URI = "https://billing.example.com/logged-out/"
BILLING_BACKCHANNEL_URI = "https://billing.example.com/oidc/backchannel-logout/"
CRM_REDIRECT_URI = "https://crm.example.com/oidc/callback/"
CRM_BACKCHANNEL_URI = "https://crm.example.com/oidc/backchannel-logout/"
CRM_SECRET = "crm-test-secret"


def http_response(status_code):
    return mock.Mock(status_code=status_code)


class LogoutTestCase(OIDCTestCase):
    @classmethod
    def setUpTestData(cls):
        super().setUpTestData()  # creates alice + the Billing app
        cls.billing = Application.objects.get(client_id=CLIENT_ID)
        cls.billing.post_logout_redirect_uris = POST_LOGOUT_URI
        cls.billing.save()
        cls.crm = Application.objects.create(
            name="CRM",
            client_id="crm",
            client_secret=CRM_SECRET,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
            redirect_uris=CRM_REDIRECT_URI,
            algorithm=Application.RS256_ALGORITHM,
            skip_authorization=True,
        )
        ClientLogoutConfig.objects.create(application=cls.billing, backchannel_logout_uri=BILLING_BACKCHANNEL_URI)
        ClientLogoutConfig.objects.create(application=cls.crm, backchannel_logout_uri=CRM_BACKCHANNEL_URI)

    def sign_in_to_billing(self):
        code, verifier = self.get_code()
        return self.exchange(code, verifier).json()

    def sign_in_to_crm(self):
        code, verifier = self.get_code(client_id="crm", redirect_uri=CRM_REDIRECT_URI)
        return self.exchange(
            code, verifier, client_id="crm", client_secret=CRM_SECRET, redirect_uri=CRM_REDIRECT_URI
        ).json()

    def rp_logout(self, **params):
        return self.client.get(reverse("oauth2_provider:rp-initiated-logout"), params)

    def assertLoggedIn(self):
        self.assertIn("_auth_user_id", self.client.session)

    def assertLoggedOut(self):
        self.assertNotIn("_auth_user_id", self.client.session)


class RPInitiatedLogoutTests(LogoutTestCase):
    def test_discovery_advertises_end_session_endpoint(self):
        doc = self.client.get("/o/.well-known/openid-configuration").json()
        self.assertTrue(doc["end_session_endpoint"].endswith("/o/logout/"))

    def test_logout_with_id_token_hint_ends_session_and_redirects_back(self):
        tokens = self.sign_in_to_billing()
        response = self.rp_logout(
            id_token_hint=tokens["id_token"], post_logout_redirect_uri=POST_LOGOUT_URI, state="abc"
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, f"{POST_LOGOUT_URI}?state=abc")
        self.assertLoggedOut()

    def test_logout_revokes_tokens_in_every_app(self):
        self.sign_in_to_billing()
        tokens = self.sign_in_to_crm()
        self.rp_logout(id_token_hint=tokens["id_token"])
        self.assertFalse(get_access_token_model().objects.filter(user=self.user).exists())
        self.assertFalse(get_id_token_model().objects.filter(user=self.user).exists())
        self.assertFalse(
            get_refresh_token_model().objects.filter(user=self.user, revoked__isnull=True).exists()
        )

    def test_logout_notifies_every_signed_in_app(self):
        tokens = self.sign_in_to_billing()
        self.sign_in_to_crm()
        self.rp_logout(id_token_hint=tokens["id_token"], post_logout_redirect_uri=POST_LOGOUT_URI)
        deliveries = BackchannelLogoutDelivery.objects.all()
        self.assertEqual({d.application.client_id for d in deliveries}, {"billing", "crm"})
        self.assertTrue(all(d.subject == str(self.user.pk) for d in deliveries))

    def test_apps_the_user_never_signed_into_are_not_notified(self):
        tokens = self.sign_in_to_billing()
        self.rp_logout(id_token_hint=tokens["id_token"])
        self.assertEqual(
            list(BackchannelLogoutDelivery.objects.values_list("application__client_id", flat=True)),
            ["billing"],
        )

    def test_unregistered_post_logout_redirect_uri_is_rejected(self):
        tokens = self.sign_in_to_billing()
        response = self.rp_logout(
            id_token_hint=tokens["id_token"], post_logout_redirect_uri="https://evil.example.com/"
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["error"], "invalid_request")
        self.assertLoggedIn()

    def test_unknown_client_id_is_rejected_cleanly(self):
        self.client.force_login(self.user)
        response = self.rp_logout(client_id="does-not-exist", post_logout_redirect_uri=POST_LOGOUT_URI)
        self.assertEqual(response.status_code, 400)
        self.assertLoggedIn()

    def test_logout_without_id_token_hint_asks_frontend_to_confirm(self):
        self.client.force_login(self.user)
        response = self.rp_logout(client_id=CLIENT_ID, post_logout_redirect_uri=POST_LOGOUT_URI)
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.url.startswith(f"{settings.FRONTEND_URL}/logout/confirm?"))
        self.assertIn("client_id=billing", response.url)
        self.assertLoggedIn()

    def test_confirmed_logout_via_post(self):
        self.client.force_login(self.user)
        response = self.client.post(
            reverse("oauth2_provider:rp-initiated-logout"),
            {"allow": "true", "client_id": CLIENT_ID, "post_logout_redirect_uri": POST_LOGOUT_URI},
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, POST_LOGOUT_URI)
        self.assertLoggedOut()

    def test_id_token_of_another_user_requires_confirmation(self):
        alice_tokens = self.sign_in_to_billing()
        bob = User.objects.create_user("bob@example.com", "bobs-long-passphrase-1", email_verified=True)
        self.client.force_login(bob)
        response = self.rp_logout(id_token_hint=alice_tokens["id_token"])
        self.assertTrue(response.url.startswith(f"{settings.FRONTEND_URL}/logout/confirm"))
        self.assertEqual(self.client.session["_auth_user_id"], str(bob.pk))

    def test_user_already_logged_out_is_just_redirected(self):
        tokens = self.sign_in_to_billing()
        self.client.logout()
        response = self.rp_logout(id_token_hint=tokens["id_token"], post_logout_redirect_uri=POST_LOGOUT_URI)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, POST_LOGOUT_URI)


class IdPLogoutTests(LogoutTestCase):
    def test_api_logout_signs_user_out_of_every_app(self):
        self.sign_in_to_billing()
        self.sign_in_to_crm()
        response = self.client.post(reverse("accounts:logout"))
        self.assertEqual(response.status_code, 204)
        self.assertFalse(get_access_token_model().objects.filter(user=self.user).exists())
        self.assertEqual(BackchannelLogoutDelivery.objects.count(), 2)


class BackchannelDeliveryTests(LogoutTestCase):
    def queue_logout_for_billing(self):
        tokens = self.sign_in_to_billing()
        self.rp_logout(id_token_hint=tokens["id_token"])
        return BackchannelLogoutDelivery.objects.get()

    @mock.patch("clients.backchannel.requests.post", return_value=http_response(200))
    def test_sends_valid_signed_logout_token(self, post):
        delivery = self.queue_logout_for_billing()
        self.assertEqual(deliver_pending(), 1)

        args, kwargs = post.call_args
        self.assertEqual(args[0], BILLING_BACKCHANNEL_URI)
        self.assertFalse(kwargs["allow_redirects"])
        logout_token = kwargs["data"]["logout_token"]

        # Verify exactly as a client app would: signature via the public JWKS.
        jwks = self.client.get(reverse("oauth2_provider:jwks-info")).content.decode()
        token = jwt.JWT(jwt=logout_token, key=jwk.JWKSet.from_json(jwks), algs=["RS256"])
        header = json.loads(token.header)
        claims = json.loads(token.claims)
        self.assertEqual(header["typ"], "logout+jwt")
        self.assertEqual(claims["iss"], settings.OAUTH2_PROVIDER["OIDC_ISS_ENDPOINT"])
        self.assertEqual(claims["aud"], CLIENT_ID)
        self.assertEqual(claims["sub"], str(self.user.pk))
        self.assertIn(BACKCHANNEL_LOGOUT_EVENT, claims["events"])
        self.assertIn("jti", claims)
        self.assertNotIn("nonce", claims)  # forbidden by the spec

        delivery.refresh_from_db()
        self.assertEqual(delivery.status, BackchannelLogoutDelivery.Status.DELIVERED)
        self.assertIsNotNone(delivery.delivered_at)

    @mock.patch("clients.backchannel.requests.post", return_value=http_response(500))
    def test_failed_delivery_is_retried_later(self, post):
        delivery = self.queue_logout_for_billing()
        deliver_pending()
        delivery.refresh_from_db()
        self.assertEqual(delivery.status, BackchannelLogoutDelivery.Status.PENDING)
        self.assertEqual(delivery.attempts, 1)
        self.assertEqual(delivery.last_error, "HTTP 500")
        self.assertGreater(delivery.next_attempt_at, timezone.now())

        deliver_pending()  # not due yet, so no second attempt
        self.assertEqual(post.call_count, 1)

    @mock.patch("clients.backchannel.requests.post", side_effect=requests.ConnectionError("refused"))
    def test_gives_up_after_max_attempts(self, post):
        delivery = self.queue_logout_for_billing()
        for _ in range(settings.BACKCHANNEL_LOGOUT_MAX_ATTEMPTS):
            BackchannelLogoutDelivery.objects.update(next_attempt_at=timezone.now() - timedelta(seconds=1))
            deliver_pending()
        delivery.refresh_from_db()
        self.assertEqual(delivery.status, BackchannelLogoutDelivery.Status.FAILED)
        self.assertEqual(delivery.attempts, settings.BACKCHANNEL_LOGOUT_MAX_ATTEMPTS)
        self.assertIn("ConnectionError", delivery.last_error)

    @mock.patch("clients.backchannel.requests.post", return_value=http_response(200))
    def test_worker_command_delivers_queue(self, post):
        self.queue_logout_for_billing()
        out = StringIO()
        call_command("send_backchannel_logouts", stdout=out)
        self.assertIn("Delivered 1", out.getvalue())


class SetBackchannelLogoutUriCommandTests(LogoutTestCase):
    def test_sets_uri(self):
        call_command("set_backchannel_logout_uri", "crm", "https://crm.example.com/new/", stdout=StringIO())
        self.crm.logout_config.refresh_from_db()
        self.assertEqual(self.crm.logout_config.backchannel_logout_uri, "https://crm.example.com/new/")

    def test_rejects_invalid_uri(self):
        with self.assertRaises(Exception):
            call_command("set_backchannel_logout_uri", "crm", "not a url", stdout=StringIO())

    def test_rejects_unknown_client(self):
        with self.assertRaises(CommandError):
            call_command("set_backchannel_logout_uri", "nope", "https://x.example.com/", stdout=StringIO())
