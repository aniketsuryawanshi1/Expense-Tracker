from rest_framework import serializers
from .models import User
from django.contrib.auth import authenticate
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import force_str
from django.utils.http import urlsafe_base64_decode

class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(max_length=68, min_length = 6, write_only = True)
    password2 = serializers.CharField(max_length = 68, min_length = 6, write_only = True)
    
    class Meta:
        model = User
        fields = ['username', 'email', 'password', 'password2']

    def validate(self, data):
        password = data.get('password')
        password2 = data.get('password2')
        
        if password!= password2:
            raise serializers.ValidationError("Passwords do not match.")
        validate_password(password)
        return data
    
    def create(self, validated_data):
        user = User.objects.create_user(
            username = validated_data['username'],
            email = validated_data['email'],
            password = validated_data['password']
        )
        return user
    

""" User Login """
class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)
    username = serializers.CharField(max_length=255, read_only=True)
    access_token = serializers.CharField(max_length=255, read_only=True)
    refresh_token = serializers.CharField(max_length=255, read_only=True)

    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')
        request = self.context.get('request')

        # Try fetching user by email
        user = User.objects.filter(email=email).first()
        if not user:
            raise AuthenticationFailed('No account found with this email.')

        # Authenticate user (username is used internally)
        user = authenticate(request, username=user.username, password=password)

        if not user:
            raise AuthenticationFailed('Invalid credentials, try again.')

        if not user.is_verified:
            raise AuthenticationFailed('User is not verified. Please verify your email.')

        if not user.is_active:
            raise AuthenticationFailed('This account is inactive. Contact support.')

        # Generate tokens
        tokens = user.tokens()

        return {
            'email': user.email,
            'username': user.username,
            'access_token': str(tokens.get('access')),
            'refresh_token': str(tokens.get('refresh')),
        }

class OTPSerializer(serializers.Serializer):
    email = serializers.EmailField()

class VerifyOTPSerializer(serializers.Serializer):
    otp = serializers.CharField(max_length=6)

class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()

class PasswordResetConfirmSerializer(serializers.Serializer):
    password = serializers.CharField(max_length=68, min_length=6, write_only=True)
    password2 = serializers.CharField(max_length=68, min_length=6, write_only=True)
    token = serializers.CharField(max_length=255, write_only=True)
    uidb64 = serializers.CharField(max_length=255, write_only=True)

    class Meta:
        fields = ['password', 'password2', 'token', 'uidb64']

    def validate(self, data):
        password = data.get('password')
        password2 = data.get('password2')
        token = data.get('token')
        uidb64 = data.get('uidb64')

        if password != password2:
            raise serializers.ValidationError('Passwords do not match.')
        
        try:
            user_id = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=user_id)

            if not PasswordResetTokenGenerator().check_token(user, token):
                raise serializers.ValidationError("Reset link is invalid or has expired", 401)
            
            data['user'] = user

            return data
        
        except User.DoesNotExist:
            raise AuthenticationFailed("Invalid User.")
        except Exception:
            raise AuthenticationFailed("Link is invalid or has expired")
        
    def save(self, **kwargs):
        user = self.validated_data['user']
        password = self.validated_data['password']

        user.set_password(password)
        user.save()

        return user