from django.urls import path
from .views import (
    RegisterView, LoginView,  
    ResendOTPView, VerifyOTPView, PasswordResetRequestView, 
    PasswordResetConfirmationView
)
from rest_framework_simplejwt.views import (TokenRefreshView,)

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('otp/resend/', ResendOTPView.as_view(), name='otp_resend'),
    path('verify-otp/', VerifyOTPView.as_view(), name='verify_otp'),
    path('password-reset/', PasswordResetRequestView.as_view(), name='password_reset_request'),
    path('password-reset-confirm/<uidb64>/<token>/', PasswordResetConfirmationView.as_view(), name='password_reset_confirm'),
]
