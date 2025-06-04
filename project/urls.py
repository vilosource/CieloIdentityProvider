from django.contrib import admin
from django.urls import path, include
from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView, SpectacularRedocView
from django.views.generic import TemplateView
from django.http import JsonResponse, HttpRequest

def health_check(request: HttpRequest) -> JsonResponse:
    return JsonResponse({"status": "ok", "service": "CieloIdentityProvider"})

urlpatterns = [
    path("", health_check, name="health-check"),
    path("admin/", admin.site.urls),
    path("api/", include("apps.identity.urls", namespace="identity")),
    path("api/schema/", SpectacularAPIView.as_view(), name="schema"),
    path("api/docs/", SpectacularSwaggerView.as_view(url_name="schema"), name="swagger-ui"),
    path("api/redoc/", SpectacularRedocView.as_view(url_name="schema"), name="redoc"),
    path("api/login-form/", TemplateView.as_view(template_name="login_form.html"), name="login-form"),
]
