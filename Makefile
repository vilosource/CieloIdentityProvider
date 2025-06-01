# Makefile for Cielo Frontend Django Project

# Python interpreter
PYTHON := python3
PIP := pip3

# Django management command
MANAGE := $(PYTHON) manage.py

# Project directories
PROJECT_DIR := .
APPS_DIRS := cielo_frontend users

.PHONY: help clean clean-pyc clean-build clean-db install migrate runserver test lint format tarball

# Default target
help:
	@echo "Available targets:"
	@echo "  clean         - Remove all runtime files (pyc, pycache, etc.)"
	@echo "  clean-pyc     - Remove Python cache files"
	@echo "  clean-build   - Remove build artifacts"
	@echo "  clean-db      - Remove SQLite database"
	@echo "  install       - Install dependencies"
	@echo "  migrate       - Run Django migrations"
	@echo "  runserver     - Start Django development server"
	@echo "  test          - Run tests"
	@echo "  lint          - Run linting checks"
	@echo "  format        - Format code"
	@echo "  tarball       - Create tar.gz archive (excluding database and runtime files)"

# Clean all runtime files
clean: clean-pyc clean-build
	@echo "Cleaned all runtime files"

# Remove Python cache files
clean-pyc:
	@echo "Removing Python cache files..."
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyo" -delete
	find . -type f -name "*~" -delete
	find . -type f -name ".coverage" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true

# Remove build artifacts
clean-build:
	@echo "Removing build artifacts..."
	rm -rf build/
	rm -rf dist/
	rm -rf .eggs/
	find . -name '*.egg-info' -exec rm -rf {} + 2>/dev/null || true
	find . -name '*.egg' -exec rm -f {} + 2>/dev/null || true

# Remove SQLite database (use with caution)
clean-db:
	@echo "Removing SQLite database..."
	rm -f db.sqlite3

# Install dependencies
install:
	$(PIP) install -r requirements.txt

# Run Django migrations
migrate:
	$(MANAGE) makemigrations
	$(MANAGE) migrate

# Start development server
runserver:
	$(MANAGE) runserver

# Run tests
test:
	$(MANAGE) test

# Run linting (if you have flake8 or similar installed)
lint:
	@if command -v flake8 >/dev/null 2>&1; then \
		echo "Running flake8..."; \
		flake8 $(APPS_DIRS); \
	else \
		echo "flake8 not found. Install with: pip install flake8"; \
	fi

# Format code (if you have black installed)
format:
	@if command -v black >/dev/null 2>&1; then \
		echo "Running black..."; \
		black $(APPS_DIRS); \
	else \
		echo "black not found. Install with: pip install black"; \
	fi

# Collect static files
collectstatic:
	$(MANAGE) collectstatic --noinput

# Create superuser
createsuperuser:
	$(MANAGE) createsuperuser

# Show Django shell
shell:
	$(MANAGE) shell

# Show project tree (excluding runtime files)
tree:
	@if command -v tree >/dev/null 2>&1; then \
		tree -I "*.pyc|__pycache__|static|*.egg-info|.git|*.pyo"; \
	else \
		echo "tree command not found. Install with: sudo apt-get install tree"; \
	fi

# Create tarball archive (excluding database and runtime files)
tarball:
	@echo "Creating tarball archive..."
	@PROJECT_NAME=$$(basename $$(pwd)); \
	TIMESTAMP=$$(date +%Y%m%d_%H%M%S); \
	ARCHIVE_NAME="$${PROJECT_NAME}_$${TIMESTAMP}.tar.gz"; \
	tar --create --gzip --file="../$${ARCHIVE_NAME}" \
		--exclude="db.sqlite3" \
		--exclude="*.pyc" \
		--exclude="__pycache__" \
		--exclude="*.pyo" \
		--exclude="*.egg-info" \
		--exclude=".git" \
		--exclude="*.log" \
		--exclude=".coverage" \
		--exclude="build" \
		--exclude="dist" \
		--exclude=".eggs" \
		--exclude="node_modules" \
		--exclude=".env" \
		--exclude=".venv" \
		--exclude="venv" \
		--exclude="*.tar.gz" \
		.; \
	echo "Archive created: ../$${ARCHIVE_NAME}"
