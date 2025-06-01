from django.contrib.auth.models import User
from rest_framework import serializers


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["id", "username", "email", "first_name", "last_name"]


class ChangePasswordSerializer(serializers.Serializer):
    current_password = serializers.CharField(write_only=True)
    new_password1 = serializers.CharField(write_only=True)
    new_password2 = serializers.CharField(write_only=True)

    def validate_current_password(self, value):
        user = self.context["request"].user
        if not user.check_password(value):
            raise serializers.ValidationError("Invalid password")
        return value

    def validate(self, attrs):
        if attrs.get("new_password1") != attrs.get("new_password2"):
            raise serializers.ValidationError("Passwords do not match")
        from django.contrib.auth.password_validation import validate_password
        user = self.context["request"].user
        try:
            validate_password(attrs.get("new_password1"), user=user)
        except Exception:
            raise serializers.ValidationError("Invalid password")
        return attrs

