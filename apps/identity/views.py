from django.contrib.auth.decorators import login_required
from django.utils.decorators import method_decorator
from django.contrib.auth import update_session_auth_hash
from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated

from .serializers import UserSerializer, ChangePasswordSerializer
from .services import AuthenticationService


class LoginView(APIView):
    service_class = AuthenticationService

    def post(self, request):
        username = request.data.get("username")
        password = request.data.get("password")
        service = self.service_class()
        user = service.authenticate_credentials(username=username, password=password)
        if user is None:
            return Response({"detail": "Invalid credentials"}, status=status.HTTP_400_BAD_REQUEST)
        service.login_user(request, user)
        data = UserSerializer(user).data
        return Response(data)


class LogoutView(APIView):
    service_class = AuthenticationService

    permission_classes = [IsAuthenticated]

    def post(self, request):
        service = self.service_class()
        service.logout_user(request)
        return Response(status=status.HTTP_204_NO_CONTENT)


class SessionView(APIView):
    service_class = AuthenticationService

    def get(self, request):
        service = self.service_class()
        if service.is_authenticated(request):
            return Response({"authenticated": True})
        return Response({"authenticated": False}, status=status.HTTP_403_FORBIDDEN)


@method_decorator(login_required, name="dispatch")
class CurrentUserView(APIView):
    def get(self, request):
        data = UserSerializer(request.user).data
        return Response(data)


class ChangePasswordView(APIView):
    permission_classes = [IsAuthenticated]
    serializer_class = ChangePasswordSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data, context={"request": request})
        if serializer.is_valid():
            user = request.user
            user.set_password(serializer.validated_data["new_password1"])
            user.save()
            update_session_auth_hash(request, user)
            return Response(status=status.HTTP_204_NO_CONTENT)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

