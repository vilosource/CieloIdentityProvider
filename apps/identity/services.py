from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.http import HttpRequest


class AuthenticationService:
    """Service layer for authentication operations."""

    def authenticate_credentials(self, username: str, password: str):
        return authenticate(username=username, password=password)

    def login_user(self, request: HttpRequest, user: User) -> None:
        login(request, user)

    def logout_user(self, request: HttpRequest) -> None:
        logout(request)

    def is_authenticated(self, request: HttpRequest) -> bool:
        return request.user.is_authenticated

