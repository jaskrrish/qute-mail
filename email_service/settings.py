import os
from pathlib import Path
from decouple import config
import dj_database_url

BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = config('SECRET_KEY', default='your-secret-key-here')
DEBUG = config('DEBUG', default=False, cast=bool)

ALLOWED_HOSTS = [
    '*',  # Allow all hosts for development
    '01d0bcfe877c.ngrok-free.app',  # Ngrok tunnel
    'https://01d0bcfe877c.ngrok-free.app',  # Ngrok tunnel with protocol
    'localhost',
    '127.0.0.1',
]

# CSRF trusted origins for external domains
CSRF_TRUSTED_ORIGINS = [
    'https://01d0bcfe877c.ngrok-free.app',
    'http://localhost:8000',
    'http://127.0.0.1:8000',
]

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'rest_framework',
    'rest_framework.authtoken',
    'email_core',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'email_service.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'email_service.wsgi.application'

# REST Framework Configuration
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework.authentication.TokenAuthentication',
        'rest_framework.authentication.SessionAuthentication',
    ],
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.IsAuthenticated',
    ],
}

# Database configuration - supports both DATABASE_URL and individual settings
if config('DATABASE_URL', default=None):
    DATABASES = {
        'default': dj_database_url.parse(config('DATABASE_URL'))
    }
else:
    # Use SQLite for local development (easier setup)
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.sqlite3',
            'NAME': BASE_DIR / 'db.sqlite3',
        }
    }
    
    # Uncomment below for PostgreSQL setup
    # DATABASES = {
    #     'default': {
    #         'ENGINE': 'django.db.backends.postgresql',
    #         'NAME': config('DB_NAME', default='email_service'),
    #         'USER': config('DB_USER', default='postgres'),
    #         'PASSWORD': config('DB_PASSWORD', default='postgres'),
    #         'HOST': config('DB_HOST', default='localhost'),
    #         'PORT': config('DB_PORT', default='5432'),
    #     }
    # }

# Email Service Configuration
EMAIL_SERVICE_CONFIG = {
    'SMTP_PORT': 25,
    'SMTP_SSL_PORT': 465,
    'SMTP_TLS_PORT': 587,
    'IMAP_PORT': 143,
    'IMAP_SSL_PORT': 993,
    'SERVER_HOSTNAME': config('SERVER_HOSTNAME', default='mail.yourdomain.com'),
    'SERVER_IP': config('SERVER_IP', default='0.0.0.0'),
}

# Django Email Configuration (for sending emails)
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = config('EMAIL_HOST', default='localhost')  # Use localhost when running Django locally
EMAIL_PORT = config('EMAIL_PORT', default=1025, cast=int)
EMAIL_USE_TLS = config('EMAIL_USE_TLS', default=False, cast=bool)
EMAIL_USE_SSL = config('EMAIL_USE_SSL', default=False, cast=bool)
EMAIL_HOST_USER = config('EMAIL_HOST_USER', default='')
EMAIL_HOST_PASSWORD = config('EMAIL_HOST_PASSWORD', default='')
DEFAULT_FROM_EMAIL = config('DEFAULT_FROM_EMAIL', default='noreply@localhost')

# Celery Configuration
CELERY_BROKER_URL = config('REDIS_URL', default='redis://redis:6379/0')
CELERY_RESULT_BACKEND = config('REDIS_URL', default='redis://redis:6379/0')

STATIC_URL = '/static/'
STATIC_ROOT = os.path.join(BASE_DIR, 'static')

MEDIA_URL = '/media/'
MEDIA_ROOT = os.path.join(BASE_DIR, 'media')