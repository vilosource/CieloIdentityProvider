from django.urls import path

from .views import LoginView, LogoutView, SessionView, CurrentUserView


app_name = "identity"

urlpatterns = [
    path("login", LoginView.as_view(), name="login"),
    path("logout", LogoutView.as_view(), name="logout"),
    path("session", SessionView.as_view(), name="session"),
    path("users/me", CurrentUserView.as_view(), name="current_user"),
]

