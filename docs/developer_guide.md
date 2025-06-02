# Developer Guide

This guide explains how to use `CieloIdentityProvider` during development and how other Django projects can authenticate users via its API.

## Running the service

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
2. Apply migrations:
   ```bash
   python manage.py migrate
   ```
3. Create a superuser (optional):
   ```bash
   python manage.py createsuperuser
   ```
4. Start the development server:
   ```bash
   python manage.py runserver
   ```
4. Visit `http://localhost:8000/admin/` and log in with your superuser credentials to access the admin interface.

## API usage

All authentication endpoints are available under the `/api/` prefix.

### Login
`POST /api/login`

Body parameters:
- `username`
- `password`

Returns the user profile when the credentials are valid.

### Logout
`POST /api/logout`

Logs out the current session.

### Session Status
`GET /api/session`

Returns `{"authenticated": true}` when the session is valid. Otherwise a `403` status is returned.

### Current User
`GET /api/users/me`

Returns the authenticated user's profile.

### Change Password
`POST /api/users/change-password`

Body parameters:
- `current_password`
- `new_password1`
- `new_password2`

Returns a `204` status code on success.

Other Django projects can authenticate via these endpoints using the standard session authentication mechanism provided by Django REST Framework.

