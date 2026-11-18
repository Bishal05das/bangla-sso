import re
import time
from datetime import timedelta
from unittest import mock

from django.conf import settings
from django.core import mail
from django.core.cache import cache
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone
from oauth2_provider.models import get_access_token_model, get_application_model, get_refresh_token_model
from rest_framework.test import APIClient

from accounts.models import User

PASSWORD = "correct-horse-battery-staple"
NEW_PASSWORD = "another-long-passphrase-42"


class AccountFlowTestCase(TestCase):
    def setUp(self):
        cache.clear()  # reset DRF throttle counters between tests
        self.client = APIClient()

    def post(self, name, data):
        return self.client.post(reverse(f"accounts:{name}"), data, format="json")

    def login(self, email, password):
        return self.post("login", {"email": email, "password": password})

    def last_email_link_fragment(self):
        """Return the #fragment part of the link in the most recent email, as a dict."""
        link = re.search(r"https?://\S+", mail.outbox[-1].body).group(0)
        self.assertTrue(link.startswith(settings.FRONTEND_URL))
        fragment = link.split("#", 1)[1]
        return dict(part.split("=", 1) for part in fragment.split("&"))


class RegistrationTests(AccountFlowTestCase):
    def register(self, email="new@example.com", password=PASSWORD, **extra):
        return self.post("register", {"email": email, "password": password, **extra})

    def test_register_creates_unverified_user_and_sends_verification_email(self):
        response = self.register(email="New@Example.com", first_name="Nina")
        self.assertEqual(response.status_code, 202)
        user = User.objects.get(email="new@example.com")
        self.assertFalse(user.email_verified)
        self.assertEqual(user.first_name, "Nina")
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(mail.outbox[0].to, ["new@example.com"])
        self.assertIn("/verify-email#token=", mail.outbox[0].body)

    def test_existing_email_gets_identical_response_and_a_notice_email(self):
        User.objects.create_user("taken@example.com", PASSWORD)
        new = self.register(email="fresh@example.com")
        existing = self.register(email="TAKEN@example.com")
        self.assertEqual(existing.status_code, new.status_code)
        self.assertEqual(existing.json(), new.json())
        self.assertEqual(User.objects.filter(email__iexact="taken@example.com").count(), 1)
        self.assertEqual(mail.outbox[-1].subject, "Someone tried to sign up with your email")

    def test_weak_password_is_rejected(self):
        response = self.register(password="short")
        self.assertEqual(response.status_code, 400)
        self.assertIn("password", response.json()["errors"])
        self.assertFalse(User.objects.filter(email="new@example.com").exists())

    def test_password_similar_to_email_is_rejected(self):
        response = self.register(email="johnathan.smithers@example.com", password="johnathan.smithers")
        self.assertEqual(response.status_code, 400)

    def test_unverified_user_cannot_log_in(self):
        self.register()
        response = self.login("new@example.com", PASSWORD)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["errors"]["__all__"][0]["code"], "email_unverified")
        self.assertNotIn("_auth_user_id", self.client.session)

    def test_sign_up_is_rate_limited(self):
        for i in range(5):
            self.assertEqual(self.register(email=f"user{i}@example.com").status_code, 202)
        self.assertEqual(self.register(email="user99@example.com").status_code, 429)


class EmailVerificationTests(AccountFlowTestCase):
    def setUp(self):
        super().setUp()
        self.post("register", {"email": "new@example.com", "password": PASSWORD})
        self.token = self.last_email_link_fragment()["token"]

    def test_valid_token_verifies_email_and_allows_login(self):
        response = self.post("verify-email", {"token": self.token})
        self.assertEqual(response.status_code, 200)
        self.assertTrue(User.objects.get(email="new@example.com").email_verified)
        self.assertEqual(self.login("new@example.com", PASSWORD).status_code, 200)

    def test_tampered_token_is_rejected(self):
        response = self.post("verify-email", {"token": self.token[:-2] + "xx"})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["code"], "invalid_token")

    def test_expired_token_is_rejected(self):
        later = time.time() + settings.EMAIL_VERIFICATION_MAX_AGE + 60
        with mock.patch("django.core.signing.time.time", return_value=later):
            response = self.post("verify-email", {"token": self.token})
        self.assertEqual(response.status_code, 400)
        self.assertFalse(User.objects.get(email="new@example.com").email_verified)

    def test_token_is_invalid_after_email_changes(self):
        User.objects.filter(email="new@example.com").update(email="changed@example.com")
        response = self.post("verify-email", {"token": self.token})
        self.assertEqual(response.status_code, 400)

    def test_resend_only_emails_unverified_accounts(self):
        User.objects.create_user("verified@example.com", PASSWORD, email_verified=True)
        mail.outbox.clear()
        for email in ("new@example.com", "verified@example.com", "nobody@example.com"):
            response = self.post("verify-email-resend", {"email": email})
            self.assertEqual(response.status_code, 202)
        self.assertEqual([m.to for m in mail.outbox], [["new@example.com"]])


class PasswordResetTests(AccountFlowTestCase):
    def setUp(self):
        super().setUp()
        self.user = User.objects.create_user("alice@example.com", PASSWORD, email_verified=True)

    def request_reset(self, email="alice@example.com"):
        response = self.post("password-reset", {"email": email})
        self.assertEqual(response.status_code, 202)
        return response

    def confirm(self, password=NEW_PASSWORD, **overrides):
        data = {**self.last_email_link_fragment(), "new_password": password, **overrides}
        return self.post("password-reset-confirm", data)

    def test_unknown_email_gets_identical_response_and_no_email(self):
        known = self.request_reset("alice@example.com")
        unknown = self.request_reset("nobody@example.com")
        self.assertEqual(known.json(), unknown.json())
        self.assertEqual(len(mail.outbox), 1)

    def test_reset_changes_password(self):
        self.request_reset()
        self.assertIn("/reset-password#uid=", mail.outbox[0].body)
        response = self.confirm()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.login("alice@example.com", PASSWORD).status_code, 400)
        self.assertEqual(self.login("alice@example.com", NEW_PASSWORD).status_code, 200)

    def test_reset_link_works_only_once(self):
        self.request_reset()
        self.assertEqual(self.confirm().status_code, 200)
        response = self.confirm(password="yet-another-passphrase-77")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["code"], "invalid_token")

    def test_weak_new_password_is_rejected(self):
        self.request_reset()
        response = self.confirm(password="short")
        self.assertEqual(response.status_code, 400)
        self.assertIn("new_password", response.json()["errors"])
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password(PASSWORD))

    def test_garbage_uid_is_rejected(self):
        self.request_reset()
        response = self.confirm(uid="not-a-real-uid")
        self.assertEqual(response.status_code, 400)

    def test_reset_signs_user_out_of_all_client_apps(self):
        app = get_application_model().objects.create(
            name="Billing", client_id="billing", client_type="confidential",
            authorization_grant_type="authorization-code",
            redirect_uris="https://billing.example.com/cb/", algorithm="RS256",
        )
        access = get_access_token_model().objects.create(
            user=self.user, application=app, token="access-123", scope="openid",
            expires=timezone.now() + timedelta(minutes=10),
        )
        get_refresh_token_model().objects.create(
            user=self.user, application=app, token="refresh-123", access_token=access,
        )
        self.request_reset()
        self.confirm()
        self.assertFalse(get_access_token_model().objects.filter(user=self.user).exists())
        self.assertFalse(
            get_refresh_token_model().objects.filter(user=self.user, revoked__isnull=True).exists()
        )

    def test_reset_clears_brute_force_lockout(self):
        for _ in range(5):
            self.login("alice@example.com", "wrong-password")
        self.assertEqual(self.login("alice@example.com", PASSWORD).status_code, 429)
        self.request_reset()
        self.confirm()
        self.assertEqual(self.login("alice@example.com", NEW_PASSWORD).status_code, 200)

    def test_reset_marks_email_as_verified(self):
        User.objects.filter(pk=self.user.pk).update(email_verified=False)
        self.request_reset()
        self.confirm()
        self.user.refresh_from_db()
        self.assertTrue(self.user.email_verified)


class CsrfProtectionTests(AccountFlowTestCase):
    def test_public_account_endpoints_require_csrf_token(self):
        client = APIClient(enforce_csrf_checks=True)
        for name, data in (
            ("register", {"email": "new@example.com", "password": PASSWORD}),
            ("verify-email", {"token": "x"}),
            ("verify-email-resend", {"email": "new@example.com"}),
            ("password-reset", {"email": "new@example.com"}),
            ("password-reset-confirm", {"uid": "x", "token": "x", "new_password": NEW_PASSWORD}),
        ):
            with self.subTest(endpoint=name):
                response = client.post(reverse(f"accounts:{name}"), data, format="json")
                self.assertEqual(response.status_code, 403)
