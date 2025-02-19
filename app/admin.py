from django.contrib import admin
from .models import User, OTP, PasswordResetToken, OTPRequestTracker

@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    list_display = ('username', 'email', 'is_staff', 'is_active', 'is_superuser')
    search_fields = ('email', 'username')
    list_filter = ('is_staff', 'is_active', 'is_superuser')


@admin.register(PasswordResetToken)
class PasswordResetTokenAdmin(admin.ModelAdmin):
    list_display = ('user', 'token', 'created_at')
    search_fields = ('user__username', 'user__email')
    readonly_fields = ('created_at', 'token', 'user')


@admin.register(OTP)
class OTPAdmin(admin.ModelAdmin):
    list_display = ('user', 'otp', 'created_at', 'is_verified')
    search_fields = ('user__username', 'user__email', 'otp')
    list_filter = ('is_verified', 'created_at')
    readonly_fields = ('created_at', 'otp', 'user')


@admin.register(OTPRequestTracker)
class OTPRequestTrackerAdmin(admin.ModelAdmin):
    list_display = ('user', 'request_count', 'last_request_time')
    search_fields = ('user__username', 'user__email')
    readonly_fields = ('last_request_time', 'request_count', 'user')