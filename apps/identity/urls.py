from django.urls import path, re_path

from .views import (
    LoginView,
    LogoutView,
    SessionView,
    CurrentUserView,
    ChangePasswordView,
)


app_name = "identity"

urlpatterns = [
    re_path(r"^login/?$", LoginView.as_view(), name="login"),
    re_path(r"^logout/?$", LogoutView.as_view(), name="logout"),
    re_path(r"^session/?$", SessionView.as_view(), name="session"),
    re_path(r"^users/me/?$", CurrentUserView.as_view(), name="current_user"),
    re_path(r"^users/change-password/?$", ChangePasswordView.as_view(), name="change_password"),
]

