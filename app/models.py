from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin, Group, Permission
from django.utils import timezone
from rest_framework_simplejwt.tokens import RefreshToken
from datetime import timedelta

AUTH_PROVIDERS = {
    'email': 'email'
}

# Custom Manager for User
class UserManager(BaseUserManager):

    def create_user(self, username, email, password=None, **extra_fields):
        if not email:
            raise ValueError('Please provide an email address')
        if not username:
            raise ValueError('Please provide a username')

        email = self.normalize_email(email)
        user = self.model(username=username, email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, username, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)

        # Default superuser permissions
        extra_fields.setdefault('can_create', True)
        extra_fields.setdefault('can_update', True)
        extra_fields.setdefault('can_delete', True)
        extra_fields.setdefault('can_read', True)
        extra_fields.setdefault('is_verified', True)

        return self.create_user(username, email, password, **extra_fields)


# Custom User model
class User(AbstractBaseUser, PermissionsMixin):
    id = models.BigAutoField(primary_key=True, editable=False)
    username = models.CharField(max_length=255, unique=True)
    email = models.EmailField(max_length=255, unique=True)
    is_staff = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    is_superuser = models.BooleanField(default=False)
    date_joined = models.DateTimeField(auto_now_add=True)
    last_login = models.DateTimeField(auto_now=True)
    auth_provider = models.CharField(max_length=50, blank=False, null=False, default=AUTH_PROVIDERS.get('email'))
    can_create = models.BooleanField(default=False)
    can_read = models.BooleanField(default=True)
    can_update = models.BooleanField(default=False)
    can_delete = models.BooleanField(default=False)
    is_verified = models.BooleanField(default=False)

    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = ['email']

    objects = UserManager()

    def tokens(self):
        refresh = RefreshToken.for_user(self)
        return {
            'refresh': str(refresh),
            'access': str(refresh.access_token)
        }

    def __str__(self):
        return self.email

    # Adding related_name to avoid clashes with built-in Group and Permission models
    groups = models.ManyToManyField(
        Group,  # Correctly refer to the Group model from django.contrib.auth
        related_name='custom_user_set',
        blank=True,
    )

    user_permissions = models.ManyToManyField(
        Permission,  # Correctly refer to the Permission model from django.contrib.auth
        related_name='custom_user_set',
        blank=True,
    )


# OTP model to handle one-time passwords
class OTP(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    otp = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)
    is_verified = models.BooleanField(default=False)

    # Check if OTP has expired
    def is_expired(self):
        OTP_EXPIRY_TIME = timedelta(seconds=150)  # Expiry time for OTP
        return timezone.now() > self.created_at + OTP_EXPIRY_TIME

    def __str__(self):
        return f"OTP(user = {self.user}, otp = {self.otp}, is_verified = {self.is_verified})"


# OTP Request Tracker model
class OTPRequestTracker(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    last_request_time = models.DateTimeField(auto_now_add=True)
    request_count = models.PositiveIntegerField(default=0)

    def reset_request_count(self):
        self.request_count = 0
        self.save()

    def can_request_otp(self):
        if self.last_request_time < timezone.now() - timedelta(hours=24):
            self.reset_request_count()
        return self.request_count < 3

    def increment_request_count(self):
        self.request_count += 1
        self.save()

    def __str__(self):
        return f"OTPRequestTracker(user = {self.user}, request_count = {self.request_count})"


# Password Reset Token model to handle password reset functionality
class PasswordResetToken(models.Model):
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    token = models.CharField(max_length=64)
    created_at = models.DateTimeField(auto_now_add=True)

    def is_expired(self):
        return timezone.now() > self.created_at + timedelta(minutes=15)

    def __str__(self):
        return f"PasswordResetToken(user = {self.user}, token = {self.token})"
