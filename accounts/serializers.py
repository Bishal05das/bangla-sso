from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError as DjangoValidationError
from rest_framework import serializers

from .models import User


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ("id", "email", "first_name", "last_name", "email_verified")
        read_only_fields = fields


class NormalizedEmailField(serializers.EmailField):
    def to_internal_value(self, data):
        return User.objects.normalize_email(super().to_internal_value(data))


def password_errors(password, user):
    """Run Django's password validators; return a list of messages ([] if OK)."""
    try:
        validate_password(password, user=user)
    except DjangoValidationError as exc:
        return list(exc.messages)
    return []


class RegisterSerializer(serializers.Serializer):
    email = NormalizedEmailField()
    password = serializers.CharField(write_only=True, trim_whitespace=False)
    first_name = serializers.CharField(max_length=150, required=False, allow_blank=True, default="")
    last_name = serializers.CharField(max_length=150, required=False, allow_blank=True, default="")

    def validate(self, attrs):
        # Unsaved user so similarity checks (password vs email/name) work.
        candidate = User(email=attrs["email"], first_name=attrs["first_name"], last_name=attrs["last_name"])
        errors = password_errors(attrs["password"], candidate)
        if errors:
            raise serializers.ValidationError({"password": errors})
        return attrs


class EmailSerializer(serializers.Serializer):
    email = NormalizedEmailField()


class EmailVerificationSerializer(serializers.Serializer):
    token = serializers.CharField()


class PasswordResetConfirmSerializer(serializers.Serializer):
    uid = serializers.CharField()
    token = serializers.CharField()
    new_password = serializers.CharField(write_only=True, trim_whitespace=False)
