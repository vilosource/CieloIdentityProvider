# CieloIdentityProvider Authentication Implementation Guide

This document provides comprehensive guidance for implementing, configuring, and maintaining the authentication system in the CieloIdentityProvider Django project.

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Authentication Implementation](#authentication-implementation)
- [Session Management](#session-management)
- [API Endpoints](#api-endpoints)
- [Security Configuration](#security-configuration)
- [Cross-Origin Support](#cross-origin-support)
- [User Management](#user-management)
- [Middleware and Services](#middleware-and-services)
- [Database Schema](#database-schema)
- [Testing](#testing)
- [Monitoring and Logging](#monitoring-and-logging)
- [Deployment](#deployment)
- [Troubleshooting](#troubleshooting)

## Overview

CieloIdentityProvider is a specialized Django service that provides centralized authentication and identity management for the Cielo platform. It serves as the single source of truth for user authentication, session management, and user data.

### Key Responsibilities

- **User Authentication**: Validate credentials and create sessions
- **Session Management**: Maintain and validate user sessions across services
- **User Data**: Store and provide user profile information
- **API Services**: Expose authentication APIs for other services
- **Security**: Implement security best practices for authentication

### Design Principles

- **Centralized Authentication**: Single point of authentication for all services
- **Session-Based**: Uses Django sessions for state management
- **API-First**: RESTful APIs for all authentication operations
- **Cross-Origin Ready**: Supports CORS for multi-domain architecture
- **Extensible**: Designed for future identity provider integrations

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Client Apps   │    │CieloIdentityProv│    │   Data Store    │
│  (Frontend,     │    │ider (Auth Core) │    │   (Database)    │
│   Services)     │    │                 │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         │ 1. Auth Requests      │                       │
         ├──────────────────────▶│                       │
         │                       │ 2. User Lookup        │
         │                       ├──────────────────────▶│
         │                       │                       │
         │                       │ 3. User Data          │
         │                       │◀──────────────────────┤
         │ 4. Session Cookie     │                       │
         │◀──────────────────────┤                       │
         │                       │ 5. Session Storage    │
         │                       ├──────────────────────▶│
```

### Core Components

1. **Authentication Views**: Handle login, logout, session validation
2. **User Model**: Extended Django user model with profile data
3. **Session Backend**: Custom session handling for cross-origin support
4. **Authentication Service**: Business logic for authentication operations
5. **API Serializers**: Data serialization for API responses
6. **Middleware**: Request processing and session validation

## Authentication Implementation

### User Model

```python
# apps/identity/models.py
from django.contrib.auth.models import AbstractUser
from django.db import models

class User(AbstractUser):
    """
    Extended user model with additional profile information
    """
    email = models.EmailField(unique=True)
    first_name = models.CharField(max_length=30)
    last_name = models.CharField(max_length=30)
    phone = models.CharField(max_length=20, blank=True)
    company = models.CharField(max_length=100, blank=True)
    job_title = models.CharField(max_length=100, blank=True)
    
    # Authentication fields
    is_email_verified = models.BooleanField(default=False)
    email_verification_token = models.CharField(max_length=255, blank=True)
    password_reset_token = models.CharField(max_length=255, blank=True)
    password_reset_expires = models.DateTimeField(null=True, blank=True)
    
    # Audit fields
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_login_ip = models.GenericIPAddressField(null=True, blank=True)
    failed_login_attempts = models.PositiveIntegerField(default=0)
    account_locked_until = models.DateTimeField(null=True, blank=True)
    
    # Use email as username
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username', 'first_name', 'last_name']
    
    class Meta:
        db_table = 'identity_user'
        
    def __str__(self):
        return f"{self.email} ({self.first_name} {self.last_name})"
    
    @property
    def full_name(self):
        return f"{self.first_name} {self.last_name}".strip()
    
    def is_account_locked(self):
        """Check if account is currently locked"""
        if self.account_locked_until:
            from django.utils import timezone
            return timezone.now() < self.account_locked_until
        return False
```

### Authentication Service

```python
# apps/identity/services.py
import logging
from datetime import timedelta
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import AnonymousUser
from django.utils import timezone
from django.conf import settings
from .models import User

logger = logging.getLogger(__name__)

class AuthenticationService:
    """
    Core authentication business logic
    """
    
    def __init__(self):
        self.max_failed_attempts = getattr(settings, 'MAX_FAILED_LOGIN_ATTEMPTS', 5)
        self.account_lockout_duration = getattr(settings, 'ACCOUNT_LOCKOUT_DURATION', 30)  # minutes
    
    def authenticate_user(self, email, password, request=None):
        """
        Authenticate user with email and password
        
        Returns:
            tuple: (success: bool, user: User|None, message: str)
        """
        try:
            # Get user by email
            try:
                user = User.objects.get(email=email, is_active=True)
            except User.DoesNotExist:
                logger.warning(f"Login attempt with non-existent email: {email}")
                return False, None, "Invalid credentials"
            
            # Check if account is locked
            if user.is_account_locked():
                logger.warning(f"Login attempt on locked account: {email}")
                return False, None, "Account is temporarily locked. Please try again later."
            
            # Authenticate
            authenticated_user = authenticate(username=email, password=password)
            
            if authenticated_user:
                # Reset failed attempts on successful login
                user.failed_login_attempts = 0
                user.account_locked_until = None
                
                # Update last login info
                user.last_login = timezone.now()
                if request:
                    user.last_login_ip = self.get_client_ip(request)
                
                user.save()
                
                logger.info(f"Successful login for user: {email}")
                return True, authenticated_user, "Login successful"
            else:
                # Increment failed attempts
                user.failed_login_attempts += 1
                
                # Lock account if max attempts reached
                if user.failed_login_attempts >= self.max_failed_attempts:
                    user.account_locked_until = timezone.now() + timedelta(minutes=self.account_lockout_duration)
                    logger.warning(f"Account locked due to failed attempts: {email}")
                
                user.save()
                
                logger.warning(f"Failed login attempt for user: {email} (attempt {user.failed_login_attempts})")
                return False, None, "Invalid credentials"
                
        except Exception as e:
            logger.error(f"Authentication error for {email}: {str(e)}")
            return False, None, "Authentication error occurred"
    
    def login_user(self, request, user):
        """
        Log in user and create session
        """
        # Force session creation if none exists
        if not request.session.session_key:
            request.session.create()
        
        # Authenticate user
        login(request, user)
        
        # Force session save to ensure persistence
        request.session.save()
        
        logger.info(f"User {user.email} logged in with session {request.session.session_key}")
        
        return request.session.session_key
    
    def logout_user(self, request):
        """
        Log out user and destroy session
        """
        if request.user.is_authenticated:
            user_email = request.user.email
            logout(request)
            logger.info(f"User {user_email} logged out")
            return True
        
        return False
    
    def validate_session(self, request):
        """
        Validate current session and return user data
        
        Returns:
            dict: Session validation result
        """
        if request.user.is_authenticated:
            return {
                'valid': True,
                'user': {
                    'id': request.user.id,
                    'username': request.user.username,
                    'email': request.user.email,
                    'first_name': request.user.first_name,
                    'last_name': request.user.last_name,
                    'full_name': request.user.full_name,
                    'company': request.user.company,
                    'job_title': request.user.job_title,
                    'is_staff': request.user.is_staff,
                    'is_superuser': request.user.is_superuser,
                    'last_login': request.user.last_login.isoformat() if request.user.last_login else None,
                }
            }
        else:
            return {
                'valid': False,
                'user': None
            }
    
    def get_client_ip(self, request):
        """Get client IP address from request"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip

# Global service instance
auth_service = AuthenticationService()
```

### Authentication Views

```python
# apps/identity/views.py
import logging
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.conf import settings
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from .services import auth_service
from .serializers import LoginSerializer, UserSerializer

logger = logging.getLogger(__name__)

@method_decorator(csrf_exempt, name='dispatch')
class LoginView(APIView):
    """
    User login endpoint
    POST /login/
    """
    
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        
        if not serializer.is_valid():
            return Response(
                {'error': 'Invalid input data', 'details': serializer.errors},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        email = serializer.validated_data['email']
        password = serializer.validated_data['password']
        
        # Authenticate user
        success, user, message = auth_service.authenticate_user(email, password, request)
        
        if success:
            # Create session
            session_key = auth_service.login_user(request, user)
            
            # Prepare response
            response_data = {
                'success': True,
                'message': message,
                'user': UserSerializer(user).data
            }
            
            response = Response(response_data, status=status.HTTP_200_OK)
            
            # Manually set session cookie to ensure browser receives it
            session_cookie_name = getattr(settings, 'SESSION_COOKIE_NAME', 'sessionid')
            session_cookie_domain = getattr(settings, 'SESSION_COOKIE_DOMAIN', None)
            session_cookie_path = getattr(settings, 'SESSION_COOKIE_PATH', '/')
            session_cookie_secure = getattr(settings, 'SESSION_COOKIE_SECURE', False)
            session_cookie_httponly = getattr(settings, 'SESSION_COOKIE_HTTPONLY', True)
            session_cookie_samesite = getattr(settings, 'SESSION_COOKIE_SAMESITE', 'Lax')
            
            response.set_cookie(
                session_cookie_name,
                session_key,
                domain=session_cookie_domain,
                path=session_cookie_path,
                secure=session_cookie_secure,
                httponly=session_cookie_httponly,
                samesite=session_cookie_samesite
            )
            
            # Add debug headers
            response['X-Session-Key'] = session_key
            response['X-User-ID'] = str(user.id)
            
            logger.info(f"Login successful for {email}, session: {session_key}")
            return response
        else:
            logger.warning(f"Login failed for {email}: {message}")
            return Response(
                {'error': message},
                status=status.HTTP_401_UNAUTHORIZED
            )

class LogoutView(APIView):
    """
    User logout endpoint
    POST /logout/
    """
    
    def post(self, request):
        success = auth_service.logout_user(request)
        
        if success:
            response = Response({
                'success': True,
                'message': 'Logout successful'
            })
            
            # Clear session cookie
            session_cookie_name = getattr(settings, 'SESSION_COOKIE_NAME', 'sessionid')
            response.delete_cookie(session_cookie_name)
            
            return response
        else:
            return Response(
                {'error': 'No active session'},
                status=status.HTTP_400_BAD_REQUEST
            )

class CheckSessionView(APIView):
    """
    Session validation endpoint
    GET /check-session/
    """
    
    def get(self, request):
        # Log session details for debugging
        logger.info(f"Session check - Key: {request.session.session_key}")
        logger.info(f"Session check - User: {request.user}")
        logger.info(f"Session check - Authenticated: {request.user.is_authenticated}")
        logger.info(f"Session check - Cookies: {dict(request.COOKIES)}")
        
        if request.user.is_authenticated:
            return Response({
                'authenticated': True,
                'user': UserSerializer(request.user).data
            })
        else:
            return Response({
                'authenticated': False
            })

class CurrentUserView(APIView):
    """
    Get current user data
    GET /current-user/
    """
    
    def get(self, request):
        if request.user.is_authenticated:
            return Response(UserSerializer(request.user).data)
        else:
            return Response(
                {'error': 'Not authenticated'},
                status=status.HTTP_401_UNAUTHORIZED
            )

class ValidateSessionView(APIView):
    """
    Internal session validation for other services
    GET /validate-session/
    """
    
    def get(self, request):
        validation_result = auth_service.validate_session(request)
        
        if validation_result['valid']:
            return Response(validation_result)
        else:
            return Response(
                {'valid': False, 'user': None},
                status=status.HTTP_401_UNAUTHORIZED
            )
```

### Serializers

```python
# apps/identity/serializers.py
from rest_framework import serializers
from django.contrib.auth import get_user_model

User = get_user_model()

class LoginSerializer(serializers.Serializer):
    """Serializer for login requests"""
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

class UserSerializer(serializers.ModelSerializer):
    """Serializer for user data"""
    full_name = serializers.ReadOnlyField()
    
    class Meta:
        model = User
        fields = [
            'id', 'username', 'email', 'first_name', 'last_name', 'full_name',
            'company', 'job_title', 'is_staff', 'is_superuser', 'last_login',
            'date_joined', 'is_email_verified'
        ]
        read_only_fields = [
            'id', 'username', 'last_login', 'date_joined', 'is_staff', 'is_superuser'
        ]

class UserProfileSerializer(serializers.ModelSerializer):
    """Serializer for user profile updates"""
    class Meta:
        model = User
        fields = [
            'first_name', 'last_name', 'phone', 'company', 'job_title'
        ]
```

## Session Management

### Session Configuration

```python
# project/settings/base.py

# Session configuration for cross-origin support
SESSION_ENGINE = 'django.contrib.sessions.backends.db'
SESSION_COOKIE_NAME = 'cielo_sessionid'
SESSION_COOKIE_DOMAIN = '.cielo.test'  # Allow sharing across subdomains
SESSION_COOKIE_PATH = '/'
SESSION_COOKIE_SECURE = False  # Set to True in production with HTTPS
SESSION_COOKIE_HTTPONLY = False  # Allow JavaScript access for debugging
SESSION_COOKIE_SAMESITE = None  # Allow cross-site requests
SESSION_SAVE_EVERY_REQUEST = True
SESSION_EXPIRE_AT_BROWSER_CLOSE = False
SESSION_COOKIE_AGE = 86400 * 7  # 7 days

# Custom session serializer for security
SESSION_SERIALIZER = 'django.contrib.sessions.serializers.JSONSerializer'
```

### Custom Session Middleware

```python
# apps/identity/middleware.py
import logging
from django.contrib.sessions.middleware import SessionMiddleware

logger = logging.getLogger(__name__)

class CustomSessionMiddleware(SessionMiddleware):
    """
    Enhanced session middleware with logging and debugging
    """
    
    def process_request(self, request):
        # Log session details for debugging
        session_key = request.COOKIES.get(settings.SESSION_COOKIE_NAME)
        if session_key:
            logger.debug(f"Request with session key: {session_key}")
        
        # Call parent middleware
        super().process_request(request)
        
        # Additional session processing if needed
        if hasattr(request, 'session'):
            # Ensure session is saved if modified
            request.session.modified = True

    def process_response(self, request, response):
        # Call parent middleware
        response = super().process_response(request, response)
        
        # Add debug headers
        if hasattr(request, 'session') and request.session.session_key:
            response['X-Session-Debug'] = request.session.session_key
        
        return response
```

## API Endpoints

### URL Configuration

```python
# apps/identity/urls.py
from django.urls import path
from . import views

urlpatterns = [
    # Authentication endpoints
    path('login/', views.LoginView.as_view(), name='login'),
    path('logout/', views.LogoutView.as_view(), name='logout'),
    path('check-session/', views.CheckSessionView.as_view(), name='check-session'),
    path('current-user/', views.CurrentUserView.as_view(), name='current-user'),
    
    # Internal service endpoints
    path('validate-session/', views.ValidateSessionView.as_view(), name='validate-session'),
    
    # User management endpoints
    path('users/me/', views.CurrentUserView.as_view(), name='user-profile'),
    path('users/me/update/', views.UpdateProfileView.as_view(), name='update-profile'),
    
    # Password management
    path('change-password/', views.ChangePasswordView.as_view(), name='change-password'),
    path('reset-password/', views.ResetPasswordView.as_view(), name='reset-password'),
    path('reset-password/confirm/', views.ResetPasswordConfirmView.as_view(), name='reset-password-confirm'),
]
```

### API Response Format

```python
# Standard API response format
{
    "success": true|false,
    "message": "Human readable message",
    "data": {...},  # Response data
    "errors": {...}  # Validation errors if applicable
}

# Authentication responses
{
    "success": true,
    "message": "Login successful",
    "user": {
        "id": 1,
        "email": "user@example.com",
        "first_name": "John",
        "last_name": "Doe",
        "full_name": "John Doe"
    }
}

# Session validation responses
{
    "authenticated": true,
    "user": {
        "id": 1,
        "email": "user@example.com",
        "first_name": "John",
        "last_name": "Doe"
    }
}
```

## Security Configuration

### CORS Settings

```python
# project/settings/base.py

# CORS configuration for cross-origin requests
CORS_ALLOW_CREDENTIALS = True
CORS_ALLOWED_ORIGINS = [
    "http://cielo.test",
    "http://billing.cielo.test",
    "http://azurebilling.cielo.test",
    "http://localhost:8001",  # Development frontend
]

CORS_ALLOWED_ORIGIN_REGEXES = [
    r"^http://.*\.cielo\.test$",  # Allow all cielo.test subdomains
]

CORS_ALLOW_HEADERS = [
    'accept',
    'accept-encoding',
    'authorization',
    'content-type',
    'dnt',
    'origin',
    'user-agent',
    'x-csrftoken',
    'x-requested-with',
]

CORS_EXPOSE_HEADERS = [
    'Set-Cookie',
    'X-Session-Key',
    'X-User-ID',
]

CORS_PREFLIGHT_MAX_AGE = 86400  # 24 hours
```

### Security Headers

```python
# Security middleware configuration
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
SECURE_HSTS_SECONDS = 31536000  # 1 year

# Content Security Policy
CSP_DEFAULT_SRC = ["'self'"]
CSP_SCRIPT_SRC = ["'self'", "'unsafe-inline'"]
CSP_STYLE_SRC = ["'self'", "'unsafe-inline'"]
CSP_IMG_SRC = ["'self'", "data:"]
CSP_CONNECT_SRC = ["'self'", "*.cielo.test"]
```

### Rate Limiting

```python
# apps/identity/decorators.py
from functools import wraps
from django.core.cache import cache
from rest_framework.response import Response
from rest_framework import status

def rate_limit(max_requests=5, window=300):  # 5 requests per 5 minutes
    """Rate limiting decorator for authentication endpoints"""
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(self, request, *args, **kwargs):
            # Get client IP
            ip = request.META.get('HTTP_X_FORWARDED_FOR', 
                                 request.META.get('REMOTE_ADDR', ''))
            if ',' in ip:
                ip = ip.split(',')[0].strip()
            
            # Create cache key
            cache_key = f"rate_limit:{ip}:{view_func.__name__}"
            
            # Get current count
            current_count = cache.get(cache_key, 0)
            
            if current_count >= max_requests:
                return Response(
                    {'error': 'Rate limit exceeded. Please try again later.'},
                    status=status.HTTP_429_TOO_MANY_REQUESTS
                )
            
            # Increment counter
            cache.set(cache_key, current_count + 1, window)
            
            return view_func(self, request, *args, **kwargs)
        return wrapper
    return decorator
```

## Cross-Origin Support

### CORS Middleware Configuration

```python
# project/settings/base.py

MIDDLEWARE = [
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'apps.identity.middleware.CustomSessionMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]
```

### Cross-Origin Session Handling

```python
# apps/identity/utils.py
from django.conf import settings

def set_cross_origin_cookie(response, name, value, **kwargs):
    """
    Set a cookie that works across origins
    """
    cookie_settings = {
        'domain': getattr(settings, 'SESSION_COOKIE_DOMAIN', None),
        'path': getattr(settings, 'SESSION_COOKIE_PATH', '/'),
        'secure': getattr(settings, 'SESSION_COOKIE_SECURE', False),
        'httponly': getattr(settings, 'SESSION_COOKIE_HTTPONLY', True),
        'samesite': getattr(settings, 'SESSION_COOKIE_SAMESITE', 'Lax'),
    }
    
    # Override with provided kwargs
    cookie_settings.update(kwargs)
    
    response.set_cookie(name, value, **cookie_settings)
    return response
```

## User Management

### User Creation and Management

```python
# apps/identity/management/commands/create_superuser.py
from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model

User = get_user_model()

class Command(BaseCommand):
    help = 'Create a superuser for the identity provider'
    
    def add_arguments(self, parser):
        parser.add_argument('--email', required=True)
        parser.add_argument('--password', required=True)
        parser.add_argument('--first-name', required=True)
        parser.add_argument('--last-name', required=True)
    
    def handle(self, *args, **options):
        email = options['email']
        password = options['password']
        first_name = options['first_name']
        last_name = options['last_name']
        
        if User.objects.filter(email=email).exists():
            self.stdout.write(
                self.style.ERROR(f'User with email {email} already exists')
            )
            return
        
        user = User.objects.create_superuser(
            username=email,  # Use email as username
            email=email,
            password=password,
            first_name=first_name,
            last_name=last_name
        )
        
        self.stdout.write(
            self.style.SUCCESS(f'Superuser {email} created successfully')
        )
```

## Database Schema

### Migrations

```python
# apps/identity/migrations/0001_initial.py
from django.db import migrations, models
import django.contrib.auth.models

class Migration(migrations.Migration):
    initial = True
    
    dependencies = [
        ('auth', '0012_alter_user_first_name_max_length'),
    ]
    
    operations = [
        migrations.CreateModel(
            name='User',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('password', models.CharField(max_length=128, verbose_name='password')),
                ('last_login', models.DateTimeField(blank=True, null=True, verbose_name='last login')),
                ('is_superuser', models.BooleanField(default=False, verbose_name='superuser status')),
                ('username', models.CharField(max_length=150, unique=True, verbose_name='username')),
                ('first_name', models.CharField(max_length=30, verbose_name='first name')),
                ('last_name', models.CharField(max_length=30, verbose_name='last name')),
                ('email', models.EmailField(max_length=254, unique=True, verbose_name='email address')),
                ('is_staff', models.BooleanField(default=False, verbose_name='staff status')),
                ('is_active', models.BooleanField(default=True, verbose_name='active')),
                ('date_joined', models.DateTimeField(auto_now_add=True, verbose_name='date joined')),
                ('phone', models.CharField(blank=True, max_length=20)),
                ('company', models.CharField(blank=True, max_length=100)),
                ('job_title', models.CharField(blank=True, max_length=100)),
                ('is_email_verified', models.BooleanField(default=False)),
                ('email_verification_token', models.CharField(blank=True, max_length=255)),
                ('password_reset_token', models.CharField(blank=True, max_length=255)),
                ('password_reset_expires', models.DateTimeField(blank=True, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('last_login_ip', models.GenericIPAddressField(blank=True, null=True)),
                ('failed_login_attempts', models.PositiveIntegerField(default=0)),
                ('account_locked_until', models.DateTimeField(blank=True, null=True)),
                ('groups', models.ManyToManyField(blank=True, related_name='user_set', to='auth.Group', verbose_name='groups')),
                ('user_permissions', models.ManyToManyField(blank=True, related_name='user_set', to='auth.Permission', verbose_name='user permissions')),
            ],
            options={
                'db_table': 'identity_user',
            },
            managers=[
                ('objects', django.contrib.auth.models.UserManager()),
            ],
        ),
    ]
```

## Testing

### Unit Tests

```python
# apps/identity/tests/test_authentication.py
from django.test import TestCase
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient
from rest_framework import status

User = get_user_model()

class AuthenticationTestCase(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123',
            first_name='Test',
            last_name='User'
        )
    
    def test_login_success(self):
        """Test successful login"""
        response = self.client.post('/login/', {
            'email': 'test@example.com',
            'password': 'testpass123'
        })
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['success'])
        self.assertIn('user', response.data)
    
    def test_login_invalid_credentials(self):
        """Test login with invalid credentials"""
        response = self.client.post('/login/', {
            'email': 'test@example.com',
            'password': 'wrongpassword'
        })
        
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertIn('error', response.data)
    
    def test_session_check_authenticated(self):
        """Test session check with authenticated user"""
        # Login first
        self.client.login(username='test@example.com', password='testpass123')
        
        response = self.client.get('/check-session/')
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['authenticated'])
    
    def test_session_check_unauthenticated(self):
        """Test session check without authentication"""
        response = self.client.get('/check-session/')
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertFalse(response.data['authenticated'])
```

### Integration Tests

```python
# apps/identity/tests/test_integration.py
from django.test import TestCase, Client
from django.contrib.auth import get_user_model

User = get_user_model()

class AuthenticationIntegrationTestCase(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
    
    def test_complete_auth_flow(self):
        """Test complete authentication flow"""
        # 1. Check initial session (should be unauthenticated)
        response = self.client.get('/check-session/')
        self.assertFalse(response.json()['authenticated'])
        
        # 2. Login
        response = self.client.post('/login/', {
            'email': 'test@example.com',
            'password': 'testpass123'
        }, content_type='application/json')
        self.assertEqual(response.status_code, 200)
        
        # 3. Check session (should be authenticated)
        response = self.client.get('/check-session/')
        self.assertTrue(response.json()['authenticated'])
        
        # 4. Get current user
        response = self.client.get('/current-user/')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['email'], 'test@example.com')
        
        # 5. Logout
        response = self.client.post('/logout/')
        self.assertEqual(response.status_code, 200)
        
        # 6. Check session (should be unauthenticated)
        response = self.client.get('/check-session/')
        self.assertFalse(response.json()['authenticated'])
```

## Monitoring and Logging

### Logging Configuration

```python
# project/settings/base.py

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {process:d} {thread:d} {message}',
            'style': '{',
        },
        'simple': {
            'format': '{levelname} {message}',
            'style': '{',
        },
    },
    'handlers': {
        'file': {
            'level': 'INFO',
            'class': 'logging.FileHandler',
            'filename': 'identity.log',
            'formatter': 'verbose',
        },
        'console': {
            'level': 'DEBUG',
            'class': 'logging.StreamHandler',
            'formatter': 'simple',
        },
    },
    'loggers': {
        'apps.identity': {
            'handlers': ['file', 'console'],
            'level': 'INFO',
            'propagate': True,
        },
        'django.security': {
            'handlers': ['file', 'console'],
            'level': 'WARNING',
            'propagate': True,
        },
    },
}
```

### Metrics and Monitoring

```python
# apps/identity/metrics.py
from django.core.cache import cache
from django.utils import timezone
import json

class AuthMetrics:
    """Collect authentication metrics"""
    
    @staticmethod
    def record_login_attempt(email, success, ip_address=None):
        """Record login attempt for metrics"""
        timestamp = timezone.now().isoformat()
        
        # Store recent attempts for analysis
        cache_key = f"login_attempts:{timezone.now().strftime('%Y-%m-%d-%H')}"
        attempts = cache.get(cache_key, [])
        
        attempts.append({
            'email': email,
            'success': success,
            'timestamp': timestamp,
            'ip_address': ip_address
        })
        
        # Keep only last 1000 attempts per hour
        if len(attempts) > 1000:
            attempts = attempts[-1000:]
        
        cache.set(cache_key, attempts, 3600)  # 1 hour
    
    @staticmethod
    def get_login_metrics(hours=24):
        """Get login metrics for specified hours"""
        metrics = {
            'total_attempts': 0,
            'successful_logins': 0,
            'failed_logins': 0,
            'unique_users': set(),
            'unique_ips': set()
        }
        
        for hour in range(hours):
            timestamp = timezone.now() - timezone.timedelta(hours=hour)
            cache_key = f"login_attempts:{timestamp.strftime('%Y-%m-%d-%H')}"
            attempts = cache.get(cache_key, [])
            
            for attempt in attempts:
                metrics['total_attempts'] += 1
                if attempt['success']:
                    metrics['successful_logins'] += 1
                else:
                    metrics['failed_logins'] += 1
                
                metrics['unique_users'].add(attempt['email'])
                if attempt['ip_address']:
                    metrics['unique_ips'].add(attempt['ip_address'])
        
        metrics['unique_users'] = len(metrics['unique_users'])
        metrics['unique_ips'] = len(metrics['unique_ips'])
        
        return metrics
```

## Deployment

### Production Settings

```python
# project/settings/prod.py
from .base import *

# Security settings for production
DEBUG = False
ALLOWED_HOSTS = ['identity.cielo.test', 'identity.example.com']

# Secure session cookies
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Lax'

# CSRF protection
CSRF_COOKIE_SECURE = True
CSRF_COOKIE_HTTPONLY = True

# Database configuration
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': os.environ.get('DB_NAME'),
        'USER': os.environ.get('DB_USER'),
        'PASSWORD': os.environ.get('DB_PASSWORD'),
        'HOST': os.environ.get('DB_HOST', 'localhost'),
        'PORT': os.environ.get('DB_PORT', '5432'),
    }
}

# Cache configuration
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.redis.RedisCache',
        'LOCATION': os.environ.get('REDIS_URL', 'redis://127.0.0.1:6379/1'),
    }
}

# Logging to external service
LOGGING['handlers']['external'] = {
    'level': 'ERROR',
    'class': 'your_logging_handler.ExternalHandler',
    'formatter': 'verbose',
}
```

### Docker Configuration

```dockerfile
# Dockerfile
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

EXPOSE 8002

CMD ["gunicorn", "--bind", "0.0.0.0:8002", "project.wsgi:application"]
```

## Troubleshooting

### Common Issues

1. **Session cookies not working across domains**
   - Check `SESSION_COOKIE_DOMAIN = ".cielo.test"`
   - Verify browser accepts third-party cookies
   - Ensure CORS is properly configured

2. **CORS errors in browser**
   - Verify `CORS_ALLOW_CREDENTIALS = True`
   - Check allowed origins include frontend domain
   - Ensure proper headers in responses

3. **Authentication fails intermittently**
   - Check session backend configuration
   - Verify database connectivity
   - Review rate limiting settings

4. **High login failure rates**
   - Check for brute force attacks
   - Review account lockout settings
   - Monitor IP addresses and patterns

### Debug Commands

```python
# Management command for debugging
# apps/identity/management/commands/debug_auth.py
from django.core.management.base import BaseCommand
from django.contrib.sessions.models import Session
from django.contrib.auth import get_user_model

User = get_user_model()

class Command(BaseCommand):
    help = 'Debug authentication issues'
    
    def add_arguments(self, parser):
        parser.add_argument('--user-email', help='Email of user to debug')
        parser.add_argument('--session-key', help='Session key to debug')
        parser.add_argument('--list-sessions', action='store_true', help='List all active sessions')
    
    def handle(self, *args, **options):
        if options['list_sessions']:
            sessions = Session.objects.all()
            for session in sessions:
                data = session.get_decoded()
                user_id = data.get('_auth_user_id')
                if user_id:
                    try:
                        user = User.objects.get(id=user_id)
                        self.stdout.write(f"Session {session.session_key}: {user.email}")
                    except User.DoesNotExist:
                        self.stdout.write(f"Session {session.session_key}: Invalid user ID {user_id}")
        
        if options['user_email']:
            try:
                user = User.objects.get(email=options['user_email'])
                self.stdout.write(f"User: {user.email}")
                self.stdout.write(f"Active: {user.is_active}")
                self.stdout.write(f"Failed attempts: {user.failed_login_attempts}")
                self.stdout.write(f"Locked until: {user.account_locked_until}")
            except User.DoesNotExist:
                self.stdout.write(f"User {options['user_email']} not found")
```

This documentation provides comprehensive guidance for implementing, configuring, and maintaining the authentication system in the CieloIdentityProvider Django project.
