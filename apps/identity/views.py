import logging

from django.contrib.auth.decorators import login_required
from django.utils.decorators import method_decorator
from django.contrib.auth import update_session_auth_hash
from django.conf import settings
from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from drf_spectacular.utils import extend_schema, extend_schema_view

from .serializers import UserSerializer, ChangePasswordSerializer
from .services import AuthenticationService

logger = logging.getLogger(__name__)

@extend_schema_view(
    post=extend_schema(
        request=UserSerializer,
        responses={200: UserSerializer},
        description="Authenticate a user and return user data",
    )
)
class LoginView(APIView):
    service_class = AuthenticationService

    def post(self, request):
        logger.debug("Login attempt received")
        username = request.data.get("username")
        password = request.data.get("password")
        service = self.service_class()
        user = service.authenticate_credentials(username=username, password=password)
        if user is None:
            logger.warning(f"Failed login attempt for username: {username}")
            return Response({"detail": "Invalid credentials"}, status=status.HTTP_400_BAD_REQUEST)
        service.login_user(request, user)
        logger.info(f"User {username} logged in successfully")
        
        # Create response with user data
        data = UserSerializer(user).data
        response = Response(data)
        
        # Ensure session cookie is set in the response
        if request.session.session_key:
            session_cookie_name = getattr(settings, 'SESSION_COOKIE_NAME', 'sessionid')
            session_cookie_domain = getattr(settings, 'SESSION_COOKIE_DOMAIN', None)
            session_cookie_path = getattr(settings, 'SESSION_COOKIE_PATH', '/')
            session_cookie_secure = getattr(settings, 'SESSION_COOKIE_SECURE', False)
            session_cookie_httponly = getattr(settings, 'SESSION_COOKIE_HTTPONLY', True)
            session_cookie_samesite = getattr(settings, 'SESSION_COOKIE_SAMESITE', 'Lax')
            
            response.set_cookie(
                session_cookie_name,
                request.session.session_key,
                domain=session_cookie_domain,
                path=session_cookie_path,
                secure=session_cookie_secure,
                httponly=session_cookie_httponly,
                samesite=session_cookie_samesite
            )
            
            logger.debug(f"Manually set session cookie: {session_cookie_name}={request.session.session_key}")
            logger.debug(f"Cookie domain: {session_cookie_domain}, path: {session_cookie_path}")
        
        # Log session information for debugging
        logger.debug(f"Response session key: {request.session.session_key}")
        logger.debug(f"Session cookie domain: {getattr(settings, 'SESSION_COOKIE_DOMAIN', 'None')}")
        logger.debug(f"Session cookie name: {getattr(settings, 'SESSION_COOKIE_NAME', 'sessionid')}")
        
        return response

@extend_schema_view(
    post=extend_schema(
        responses={204: None},
        description="Logout the currently authenticated user",
    )
)
class LogoutView(APIView):
    service_class = AuthenticationService

    permission_classes = [IsAuthenticated]

    def post(self, request):
        service = self.service_class()
        service.logout_user(request)
        logger.info(f"User {request.user.username} logged out successfully")
        return Response(status=status.HTTP_204_NO_CONTENT)

@extend_schema_view(
    get=extend_schema(
        responses={200: {"type": "object", "properties": {"authenticated": {"type": "boolean"}}}},
        description="Check if the current session is authenticated",
    )
)
class SessionView(APIView):
    service_class = AuthenticationService

    def get(self, request):
        service = self.service_class()
        if service.is_authenticated(request):
            logger.info(f"Session check for authenticated user: {request.user.username}")
            return Response({"authenticated": True})
        logger.warning("Session check for unauthenticated user")
        return Response({"authenticated": False}, status=status.HTTP_403_FORBIDDEN)

@extend_schema_view(
    get=extend_schema(
        responses={200: UserSerializer},
        description="Get the currently authenticated user's data",
    )
)
@method_decorator(login_required, name="dispatch")
class CurrentUserView(APIView):
    def get(self, request):
        logger.info(f"Retrieving current user info for: {request.user.username}")
        data = UserSerializer(request.user).data
        return Response(data)

@extend_schema_view(
    post=extend_schema(
        request=ChangePasswordSerializer,
        responses={204: None},
        description="Change the password for the currently authenticated user",
    )
)
class ChangePasswordView(APIView):
    permission_classes = [IsAuthenticated]
    serializer_class = ChangePasswordSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data, context={"request": request})
        if serializer.is_valid():
            user = request.user
            user.set_password(serializer.validated_data["new_password1"])
            user.save()
            update_session_auth_hash(request, user)
            logger.info(f"Password changed for user: {user.username}")
            return Response(status=status.HTTP_204_NO_CONTENT)
        logger.warning(f"Password change failed for user: {request.user.username}, errors: {serializer.errors}")
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
