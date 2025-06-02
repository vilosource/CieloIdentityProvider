from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.http import HttpRequest
import logging

logger = logging.getLogger(__name__)


class AuthenticationService:
    """Service layer for authentication operations."""

    def authenticate_credentials(self, username: str, password: str):
        logger.debug(f"Authenticating user: {username}")
        return authenticate(username=username, password=password)

    def login_user(self, request: HttpRequest, user: User) -> None:
        logger.debug(f"Logging in user: {user.username}")
        logger.debug(f"Session key before login: {request.session.session_key}")
        
        # Force session to be created
        if not request.session.session_key:
            request.session.create()
            logger.debug(f"Created new session: {request.session.session_key}")
        
        login(request, user)
        
        # Force session to be saved
        request.session.save()
        
        logger.debug(f"Session key after login: {request.session.session_key}")
        logger.debug(f"Session data: {dict(request.session)}")
        logger.debug(f"Session modified: {request.session.modified}")
        logger.debug(f"Session accessed: {request.session.accessed}")

    def logout_user(self, request: HttpRequest) -> None:
        logger.debug(f"Logging out user: {request.user.username if request.user.is_authenticated else 'Anonymous'}")
        logout(request)

    def is_authenticated(self, request: HttpRequest) -> bool:
        logger.debug(f"Session key during auth check: {request.session.session_key}")
        logger.debug(f"Session data during auth check: {dict(request.session)}")
        logger.debug(f"Request headers: {dict(request.headers)}")
        logger.debug(f"Request cookies: {request.COOKIES}")
        logger.debug(f"Checking if user is authenticated: {request.user.username if request.user.is_authenticated else 'Anonymous'}")
        return request.user.is_authenticated

