import logging

from django.contrib.auth.decorators import login_required
from django.utils.decorators import method_decorator
from django.contrib.auth import update_session_auth_hash
from django.conf import settings
from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from drf_spectacular.utils import extend_schema, extend_schema_view

from .serializers import UserSerializer, ChangePasswordSerializer, JWTLoginSerializer
from .services import AuthenticationService

logger = logging.getLogger(__name__)

class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    """Custom JWT token serializer that includes user data"""
    
    def validate(self, attrs):
        data = super().validate(attrs)
        # Add user data to response
        data['user'] = UserSerializer(self.user).data
        return data

@extend_schema_view(
    post=extend_schema(
        request=JWTLoginSerializer,
        responses={200: {"type": "object", "properties": {
            "access": {"type": "string"},
            "refresh": {"type": "string"},
            "user": {"type": "object"}
        }}},
        description="Authenticate user and return JWT tokens",
    )
)
class JWTLoginView(TokenObtainPairView):
    """JWT-based login that returns access and refresh tokens"""
    serializer_class = CustomTokenObtainPairSerializer

    def post(self, request, *args, **kwargs):
        try:
            response = super().post(request, *args, **kwargs)
            if response.status_code == 200:
                user = self.get_user_from_request(request)
                if user:
                    logger.info(f"JWT login successful for user: {user.username}")
                else:
                    logger.info("JWT login successful")
            return response
        except Exception as e:
            logger.warning(f"JWT login failed: {str(e)}")
            return Response(
                {"detail": "Invalid credentials"},
                status=status.HTTP_401_UNAUTHORIZED
            )
    
    def get_user_from_request(self, request):
        """Get user from token for logging"""
        try:
            username = request.data.get('username')
            if username:
                from django.contrib.auth import get_user_model
                User = get_user_model()
                return User.objects.filter(username=username).first()
        except:
            pass
        return None

@extend_schema_view(
    post=extend_schema(
        request=UserSerializer,
        responses={200: UserSerializer},
        description="Authenticate a user and return user data (legacy session-based)",
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
            
            # For HTTPS development with cross-origin support
            # Use SameSite=None with Secure=True for cross-origin authentication
            response.set_cookie(
                session_cookie_name,
                request.session.session_key,
                domain=session_cookie_domain,
                path=session_cookie_path,
                secure=True,  # True for HTTPS
                httponly=False,  # False for debugging and JavaScript access
                samesite='None'  # None allows cookies across different origins
            )
            
            logger.debug(f"Manually set session cookie: {session_cookie_name}={request.session.session_key}")
            logger.debug(f"Cookie domain: {session_cookie_domain}, path: {session_cookie_path}")
            logger.debug(f"Cookie settings: secure=True, httponly=False, samesite=None")
        
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
        from django.middleware.csrf import get_token
        
        service = self.service_class()
        
        # Ensure CSRF token is generated
        csrf_token = get_token(request)
        
        # Check if we have JWT authentication
        auth_header = request.META.get('HTTP_AUTHORIZATION', '')
        is_jwt_auth = auth_header.startswith('Bearer ')
        
        if is_jwt_auth:
            # JWT authentication
            if request.user and request.user.is_authenticated:
                logger.info(f"JWT session check for authenticated user: {request.user.username}")
                response = Response({
                    "authenticated": True,
                    "csrf_token": csrf_token,
                    "auth_type": "jwt"
                })
            else:
                logger.debug("JWT session check for unauthenticated user")
                response = Response({
                    "authenticated": False,
                    "csrf_token": csrf_token,
                    "auth_type": "jwt"
                })
        elif service.is_authenticated(request):
            # Legacy cookie authentication
            logger.info(f"Session check for authenticated user: {request.user.username}")
            response = Response({
                "authenticated": True,
                "csrf_token": csrf_token,
                "auth_type": "cookie"
            })
        else:
            logger.debug("Session check for unauthenticated user")
            response = Response({
                "authenticated": False,
                "csrf_token": csrf_token,
                "auth_type": "none"
            })
        
        # Ensure CSRF cookie is set by accessing the token
        response["X-CSRFToken"] = csrf_token
        return response

@extend_schema_view(
    get=extend_schema(
        responses={200: UserSerializer},
        description="Get the currently authenticated user's data",
    )
)
class CurrentUserView(APIView):
    permission_classes = [IsAuthenticated]
    
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

@extend_schema_view(
    post=extend_schema(
        responses={204: None},
        description="Invalidate JWT refresh token for user logout",
    )
)
class JWTLogoutView(APIView):
    """Logout view that blacklists the refresh token to invalidate a JWT session"""
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            # Get the refresh token from request
            refresh_token = request.data.get('refresh')
            if refresh_token:
                # Blacklist the token to invalidate it
                token = RefreshToken(refresh_token)
                token.blacklist()
                logger.info(f"JWT logout successful for user: {request.user.username}")
            return Response(status=status.HTTP_204_NO_CONTENT)
        except Exception as e:
            logger.warning(f"JWT logout failed: {str(e)}")
            return Response({"detail": str(e)}, status=status.HTTP_400_BAD_REQUEST)

@extend_schema_view(
    post=extend_schema(
        responses={200: {"type": "object", "properties": {
            "access": {"type": "string"},
            "refresh": {"type": "string", "nullable": True}
        }}},
        description="Refresh JWT access token using refresh token",
    )
)
class JWTTokenRefreshView(TokenRefreshView):
    """View to refresh JWT access tokens using a refresh token"""
    
    def post(self, request, *args, **kwargs):
        try:
            return super().post(request, *args, **kwargs)
        except Exception as e:
            logger.warning(f"JWT token refresh failed: {str(e)}")
            return Response(
                {"detail": "Invalid refresh token"},
                status=status.HTTP_401_UNAUTHORIZED
            )
