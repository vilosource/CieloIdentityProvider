from django.urls import path, re_path

from .views import (
    LoginView,
    LogoutView,
    SessionView,
    CurrentUserView,
    ChangePasswordView,
    JWTLoginView,
    JWTLogoutView,
    JWTTokenRefreshView
)


app_name = "identity"

urlpatterns = [
    # Legacy cookie-based authentication endpoints
    re_path(r"^login/?$", LoginView.as_view(), name="login"),
    re_path(r"^logout/?$", LogoutView.as_view(), name="logout"),
    re_path(r"^session/?$", SessionView.as_view(), name="session"),
    
    # JWT token-based authentication endpoints
    re_path(r"^token/?$", JWTLoginView.as_view(), name="token_obtain_pair"),
    re_path(r"^token/refresh/?$", JWTTokenRefreshView.as_view(), name="token_refresh"),
    re_path(r"^token/logout/?$", JWTLogoutView.as_view(), name="token_logout"),
    
    # User-related endpoints
    re_path(r"^users/me/?$", CurrentUserView.as_view(), name="current_user"),
    re_path(r"^users/change-password/?$", ChangePasswordView.as_view(), name="change_password"),
]

