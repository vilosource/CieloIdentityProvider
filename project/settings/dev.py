from .base import *
DEBUG = True

# Domain configuration
DEV_DOMAIN = ".dev.viloforge.com"
HTTPS_ORIGINS = [
    "https://cielo.dev.viloforge.com",
    "https://identity.dev.viloforge.com",
    "https://billing.dev.viloforge.com",
    "https://azurebilling.dev.viloforge.com",
]

# Enable DEBUG logging for identity app in development
LOGGING['loggers']['apps.identity']['level'] = 'DEBUG'

SESSION_COOKIE_DOMAIN = DEV_DOMAIN
SESSION_COOKIE_PATH = "/"
SESSION_COOKIE_NAME = 'cielo_sessionid'

# Additional session configuration for cross-domain authentication
SESSION_COOKIE_SAMESITE = 'None'  # None required for cross-origin HTTPS
SESSION_COOKIE_SECURE = True  # Required for HTTPS and SameSite=None
SESSION_COOKIE_HTTPONLY = False  # Allow JavaScript access for cross-origin
SESSION_SAVE_EVERY_REQUEST = True  # Ensure session is saved on every request
SESSION_COOKIE_AGE = 86400  # 24 hours

# CSRF configuration for HTTPS
CSRF_COOKIE_SECURE = True
CSRF_COOKIE_SAMESITE = 'None'
CSRF_COOKIE_DOMAIN = DEV_DOMAIN
CSRF_TRUSTED_ORIGINS = HTTPS_ORIGINS

ALLOWED_HOSTS.extend([DEV_DOMAIN, "localhost", "127.0.0.1"])

# CORS settings for development
CORS_ALLOWED_ORIGINS = HTTPS_ORIGINS

CORS_ALLOW_CREDENTIALS = True
CORS_ALLOW_ALL_ORIGINS = False  # Be explicit about allowed origins

# Allow specific headers needed for authentication
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

# Additional CORS settings for session handling
CORS_EXPOSE_HEADERS = ['Set-Cookie']
CORS_PREFLIGHT_MAX_AGE = 86400
