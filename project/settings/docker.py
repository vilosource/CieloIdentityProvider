# Docker-specific settings for CieloIdentityProvider
from .base import *
import os

# Debug settings for development
DEBUG = True

# Database configuration for Docker
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': os.environ.get('POSTGRES_DB', 'cielo'),
        'USER': os.environ.get('POSTGRES_USER', 'cielo'),
        'PASSWORD': os.environ.get('POSTGRES_PASSWORD', 'cielo_dev_password'),
        'HOST': os.environ.get('POSTGRES_HOST', 'postgres'),
        'PORT': os.environ.get('POSTGRES_PORT', '5432'),
    }
}

# Redis configuration for Docker
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.redis.RedisCache',
        'LOCATION': f"redis://{os.environ.get('REDIS_HOST', 'redis')}:6379/0",
    }
}

# Session backend using Redis
SESSION_ENGINE = 'django.contrib.sessions.backends.cache'
SESSION_CACHE_ALIAS = 'default'

# Allow all hosts in Docker development
ALLOWED_HOSTS = [
    'identity.dev.viloforge.com',
    'identity.cielo.test',
    'localhost',
    '127.0.0.1',
    'cielo_identity',  # Docker service name
    '*',  # Allow all for development
]

# Cross-Origin Resource Sharing (CORS) settings
CORS_ALLOWED_ORIGINS = [
    "https://cielo.dev.viloforge.com",
    "https://identity.dev.viloforge.com", 
    "https://billing.dev.viloforge.com",
    "https://azurebilling.dev.viloforge.com",
    # Fallback for local development
    "http://cielo.test",
    "http://identity.cielo.test", 
    "http://billing.cielo.test",
    "http://localhost:8001",
    "http://localhost:8002",
    "http://localhost:8003",
    "http://localhost:8004",
]

CORS_ALLOW_CREDENTIALS = True

# Additional CORS settings for cross-origin cookie handling
CORS_EXPOSE_HEADERS = ['Set-Cookie']  # Allow browser to access Set-Cookie header
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
    'cookie',
]

# Session cookie settings for cross-domain sharing
SESSION_COOKIE_NAME = 'cielo_sessionid'  # Custom session cookie name
SESSION_COOKIE_DOMAIN = '.dev.viloforge.com'
SESSION_COOKIE_PATH = '/'
SESSION_COOKIE_SECURE = True  # True for HTTPS
SESSION_COOKIE_HTTPONLY = False  # Allow JavaScript access for cross-origin
SESSION_COOKIE_SAMESITE = 'None'  # None required for cross-origin with Secure=True

# CSRF settings
CSRF_COOKIE_DOMAIN = '.dev.viloforge.com'
CSRF_COOKIE_SECURE = True  # True for HTTPS
CSRF_COOKIE_SAMESITE = 'None'  # None required for cross-origin with Secure=True
CSRF_TRUSTED_ORIGINS = [
    'https://cielo.dev.viloforge.com',
    'https://identity.dev.viloforge.com',
    'https://billing.dev.viloforge.com',
    'https://azurebilling.dev.viloforge.com',
    # Fallback for local development
    'http://cielo.test',
    'http://identity.cielo.test',
    'http://billing.cielo.test',
]

# Development-specific middleware (add debug toolbar)
MIDDLEWARE.insert(0, 'debug_toolbar.middleware.DebugToolbarMiddleware')

# Add debug toolbar to installed apps
INSTALLED_APPS.append('debug_toolbar')

# Debug toolbar settings
INTERNAL_IPS = [
    '127.0.0.1',
    '172.16.0.0/12',  # Docker networks
    '10.0.0.0/8',     # Docker networks
]

# Logging configuration for Docker
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
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'verbose',
        },
    },
    'loggers': {
        'django': {
            'handlers': ['console'],
            'level': 'INFO',
        },
        'apps.identity': {
            'handlers': ['console'],
            'level': 'DEBUG',
        },
    },
}

# Static files configuration
STATIC_URL = '/static/'
STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')

# Media files configuration
MEDIA_URL = '/media/'
MEDIA_ROOT = os.path.join(BASE_DIR, 'media')
