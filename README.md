# CieloIdentityProvider

A Django-based identity provider for handling user authentication using session-based login.

## Quickstart

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
2. Apply migrations (creates default admin `admin`/`admin`):
   ```bash
   python manage.py migrate
   ```
3. Run the development server:
   ```bash
   python manage.py runserver
   ```
4. Visit `http://localhost:8000/admin/` to access the admin interface.

See `docs/developer_guide.md` for API usage details.

