from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient

from accounts.models import User

PASSWORD = "correct-horse-battery-staple"


class AuthAPITestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user("alice@example.com", PASSWORD, email_verified=True)


    def setUp(self):
        self.client = APIClient()

    def login(self, email, password, **extra):
        return self.client.post(
            reverse("accounts:login"),
            {"email": email, "password": password, **extra},
            format="json",
        )


class LoginTests(AuthAPITestCase):
    def test_login_succeeds_case_insensitively(self):
        response = self.login("ALICE@Example.com", PASSWORD)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["user"]["email"], "alice@example.com")
        self.assertIn("_auth_user_id", self.client.session)

    def test_response_never_exposes_sensitive_fields(self):
        user = self.login("alice@example.com", PASSWORD).json()["user"]
        for field in ("password", "is_staff", "is_superuser"):
            self.assertNotIn(field, user)

    def test_wrong_password_returns_generic_error(self):
        response = self.login("alice@example.com", "wrong-password")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["errors"]["__all__"][0]["code"], "invalid_login")
        self.assertNotIn("_auth_user_id", self.client.session)

    def test_unknown_email_returns_same_error_as_wrong_password(self):
        response = self.login("nobody@example.com", "whatever-password")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["errors"]["__all__"][0]["code"], "invalid_login")

    def test_invalid_email_error_uses_email_key(self):
        response = self.login("not-an-email", PASSWORD)
        self.assertEqual(response.status_code, 400)
        self.assertIn("email", response.json()["errors"])

    def test_safe_next_is_returned(self):
        target = "/o/authorize/?client_id=abc"
        response = self.login("alice@example.com", PASSWORD, next=target)
        self.assertEqual(response.json()["redirect_to"], target)

    def test_external_next_is_replaced(self):
        for evil in ("https://evil.example.com/", "//evil.example.com/", "javascript:alert(1)"):
            with self.subTest(next=evil):
                self.client.logout()
                response = self.login("alice@example.com", PASSWORD, next=evil)
                self.assertEqual(response.json()["redirect_to"], "/")


class CsrfTests(AuthAPITestCase):
    def setUp(self):
        self.client = APIClient(enforce_csrf_checks=True)

    def test_login_without_csrf_token_is_rejected(self):
        response = self.login("alice@example.com", PASSWORD)
        self.assertEqual(response.status_code, 403)
        self.assertNotIn("_auth_user_id", self.client.session)

    def test_login_with_csrf_token_succeeds(self):
        self.client.get(reverse("accounts:csrf"))
        token = self.client.cookies["csrftoken"].value
        response = self.client.post(
            reverse("accounts:login"),
            {"email": "alice@example.com", "password": PASSWORD},
            format="json",
            HTTP_X_CSRFTOKEN=token,
        )
        self.assertEqual(response.status_code, 200)

    def test_logout_without_csrf_token_is_rejected(self):
        self.client.force_login(self.user)
        response = self.client.post(reverse("accounts:logout"))
        self.assertEqual(response.status_code, 403)
        self.assertIn("_auth_user_id", self.client.session)


class LockoutTests(AuthAPITestCase):
    def test_account_locks_after_repeated_failures(self):
        for _ in range(5):
            self.login("alice@example.com", "wrong-password")
        response = self.login("alice@example.com", PASSWORD)
        self.assertEqual(response.status_code, 429)
        self.assertEqual(response.json()["code"], "locked_out")
        self.assertNotIn("_auth_user_id", self.client.session)

    def test_case_variants_share_one_lockout_counter(self):
        for email in ("alice@example.com", "ALICE@example.com", "Alice@Example.com",
                      "aLiCe@EXAMPLE.com", "ALICE@EXAMPLE.COM"):
            self.login(email, "wrong-password")
        response = self.login("alice@example.com", PASSWORD)
        self.assertEqual(response.status_code, 429)


class SessionEndpointTests(AuthAPITestCase):
    def test_me_requires_login(self):
        response = self.client.get(reverse("accounts:me"))
        self.assertEqual(response.status_code, 401)

    def test_me_returns_current_user(self):
        self.client.force_login(self.user)
        response = self.client.get(reverse("accounts:me"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["id"], str(self.user.id))

    def test_logout_rejects_get(self):
        self.client.force_login(self.user)
        response = self.client.get(reverse("accounts:logout"))
        self.assertEqual(response.status_code, 405)
        self.assertIn("_auth_user_id", self.client.session)

    def test_logout_ends_session(self):
        self.client.force_login(self.user)
        response = self.client.post(reverse("accounts:logout"))
        self.assertEqual(response.status_code, 204)
        self.assertEqual(self.client.get(reverse("accounts:me")).status_code, 401)
