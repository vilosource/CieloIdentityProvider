from django.contrib.auth.models import User
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase


class AuthenticationTests(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="alice", password="password", email="alice@example.com")

    def test_login_success(self):
        url = reverse("identity:login")
        response = self.client.post(url, {"username": "alice", "password": "password"}, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("username", response.data)

    def test_login_failure(self):
        url = reverse("identity:login")
        response = self.client.post(url, {"username": "alice", "password": "wrong"}, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_session_requires_authentication(self):
        url = reverse("identity:session")
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_session_after_login(self):
        self.client.post(reverse("identity:login"), {"username": "alice", "password": "password"}, format="json")
        response = self.client.get(reverse("identity:session"))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data.get("authenticated"))

    def test_current_user(self):
        self.client.post(reverse("identity:login"), {"username": "alice", "password": "password"}, format="json")
        response = self.client.get(reverse("identity:current_user"))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["username"], "alice")

    def test_logout(self):
        self.client.post(reverse("identity:login"), {"username": "alice", "password": "password"}, format="json")
        self.client.post(reverse("identity:logout"))
        response = self.client.get(reverse("identity:session"))
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

