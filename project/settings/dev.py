from .base import *
DEBUG = True

# Enable DEBUG logging for identity app in development
LOGGING['loggers']['apps.identity']['level'] = 'DEBUG'

SESSION_COOKIE_DOMAIN = ".cielo.test"
SESSION_COOKIE_PATH = "/"
SESSION_COOKIE_NAME = 'cielo_sessionid'

# Additional session configuration for cross-domain authentication
SESSION_COOKIE_SAMESITE = None  # Allow cross-site cookies
SESSION_COOKIE_SECURE = False  # Set to True in production with HTTPS
SESSION_COOKIE_HTTPONLY = False  # Allow JavaScript access for debugging
SESSION_SAVE_EVERY_REQUEST = True  # Ensure session is saved on every request
SESSION_COOKIE_AGE = 86400  # 24 hours

ALLOWED_HOSTS = [".cielo.test", "localhost", "127.0.0.1"]

# CORS settings for development
CORS_ALLOWED_ORIGINS = [
    "http://cielo.test",
    "https://cielo.test",
    "http://cielot.test",
    "https://cielot.test",
]

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
