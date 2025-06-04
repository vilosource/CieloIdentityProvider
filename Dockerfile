# Dockerfile for CieloIdentityProvider
# Build the base image in the parent directory first
FROM python:3.11-slim AS base

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Install system dependencies and create app directory
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        curl \
        git \
        libpq-dev \
        postgresql-client \
        vim \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /app

# Install common Python development dependencies
RUN pip install --no-cache-dir \
    django-debug-toolbar \
    django-extensions \
    gunicorn \
    ipython \
    psycopg2-binary \
    watchfiles

# Set working directory
WORKDIR /app

# Copy requirements and install specific dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Create non-root user and set ownership
RUN groupadd -r appuser && useradd -r -g appuser appuser \
    && chown -R appuser:appuser /app

USER appuser

# Copy application code
COPY . .

# Expose the service port
EXPOSE 8002

# Default command (can be overridden in docker-compose)
CMD ["python", "manage.py", "runserver", "0.0.0.0:8002"]
