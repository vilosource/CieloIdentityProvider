# 🔐 CieloIdentityProvider – Minimal Implementation Plan

This document outlines the minimal viable implementation of the `CieloIdentityProvider` Django service. It is designed to provide centralized session-based authentication, session validation, and user identity services to the rest of the CIELO platform.

---

## 🎯 Objectives

* Enable `CieloFrontend` and other clients to authenticate users via session-based login
* Provide API endpoints to check session status and fetch current user data
* Lay the groundwork for future support of third-party identity providers (e.g., Azure Entra ID, GitHub, GitLab)

---

## 🧱 Initial Features and Endpoints

### ✅ Required Endpoints

| Endpoint        | Method | Description                             |
| --------------- | ------ | --------------------------------------- |
| `/api/login`    | POST   | Authenticate and create user session    |
| `/api/logout`   | POST   | Destroy current user session            |
| `/api/session`  | GET    | Return 200 OK if session is valid       |
| `/api/users/me` | GET    | Return current logged-in user's profile |

These endpoints will be used by both:

* The frontend JavaScript for page-level data population
* Traefik for `forwardAuth` session validation

---

## 📂 Project Structure

```bash
CieloIdentityProvider/
├── manage.py
├── project/
│   ├── settings/
│   │   ├── base.py
│   │   ├── dev.py
│   │   └── prod.py
│   ├── urls.py
│   └── wsgi.py
├── apps/
│   └── identity/                # To be created
│       ├── views.py
│       ├── urls.py
│       ├── serializers.py
│       └── tests.py
├── requirements.txt            # Includes Django, DRF, and standard packages defined by scaffold
├── static/
├── templates/
└── .envrc
```

---

## 🔐 Authentication

* Use Django's built-in `User` model (`django.contrib.auth`)
* Use session middleware and CSRF for secure login
* Store sessions in Redis for shared cross-service access

---

## 🛠️ Key Implementation Details

### `POST /api/login`

* Accepts username and password
* Uses `authenticate()` and `login()`
* Returns JSON with user info or error

### `POST /api/logout`

* Uses `logout()` to destroy the session

### `GET /api/session`

* Returns HTTP 200 with `{ "authenticated": true }` if session is valid
* Returns 403 if not authenticated (for Traefik forwardAuth)

### `GET /api/users/me`

* Returns current user info (username, email, etc.)
* Protected by `@login_required`

---

## ⚙️ Django Configuration Notes

* Enable `SessionMiddleware`, `AuthenticationMiddleware`
* Configure `SESSION_ENGINE` to use Redis
* Use secure cookie settings and `SameSite=Lax`

---

## 🔄 Future Enhancements (Not in scope for MVP)

* OAuth2/OIDC support (Azure Entra ID, GitHub, GitLab)
* User registration or self-service profile editing
* Role/group-based access control

---

This minimal implementation provides the foundation for unified, secure, and extensible identity across the CIELO platform.

