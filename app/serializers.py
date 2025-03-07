from rest_framework import serializers
from .models import User, Expense, ExpenseTracker, Category
from django.contrib.auth import authenticate
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import force_str
from django.utils.http import urlsafe_base64_decode
from rest_framework_simplejwt.tokens import RefreshToken

""" User Register Service """
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
        
""" User Logout """

class LogoutSerializer(serializers.Serializer):
    refresh_token = serializers.CharField()
    
    default_error_messages = {
        'bad_token': ('Token is expired or invalid')
    }
    
    def validate(self, attrs):  
        self.token = attrs['refresh_token']
        
        return attrs
    
    def save(self):
        try:
            refresh_token = RefreshToken(self.token)
            refresh_token.blacklist()
        except Exception as e:
            self.fail('bad_token', e=str(e))

""" OTP Resend Service """
class OTPSerializer(serializers.Serializer):
    email = serializers.EmailField()

""" OTP Verification service"""
class VerifyOTPSerializer(serializers.Serializer):
    otp = serializers.CharField(max_length=6)

""" Password reset request service"""
class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()

""" Password reset confirm service """
class PasswordResetConfirmSerializer(serializers.Serializer):
    password = serializers.CharField(max_length=68, min_length=6, write_only=True)
    password2 = serializers.CharField(max_length=68, min_length=6, write_only=True)
    token = serializers.CharField(max_length=255, write_only=True)
    uidb64 = serializers.CharField(max_length=255, write_only=True)

    class Meta:
        fields = ['password', 'password2', 'token', 'uidb64']
        
    
    """ Password Validation """
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
        
    """ Save Password in Database"""
    def save(self, **kwargs):
        user = self.validated_data['user']
        password = self.validated_data['password']

        user.set_password(password)
        user.save()

        return user
    
""" Expense Model Services """

class CategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = Category
        fields = ['id', 'name']

class ExpenseSerializer(serializers.ModelSerializer):
    category_name = serializers.CharField(source='category.name', read_only=True)
    
    
    class Meta:
        model = Expense
        fields = ['id', 'user', 'category', 'category_name', 'amount', 'date', 'description', 'add_expense_type']
        read_only_fields = ['user']

class ExpenseTrackerSerializer(serializers.ModelSerializer):
    class Meta:
        model = ExpenseTracker
        fields = ['user', 'total_amount', 'total_expenses', 'total_income']
        read_only_fields = ['user', 'total_amount', 'total_expenses', 'total_income']
