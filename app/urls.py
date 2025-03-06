from django.urls import path
from .views import (
    RegisterView, LoginView,  
    ResendOTPView, VerifyOTPView, PasswordResetRequestView, 
    PasswordResetConfirmationView, CategoryAPIView, ExpenseAPIView,
    ExpenseDetailAPIView, ExpenseReportAPIView, LogoutAPIView
)
from rest_framework_simplejwt.views import (TokenRefreshView,)

urlpatterns = [
    
    # Accounts Api Endpoints
    
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('logout/', LogoutAPIView.as_view(), name='logout'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('otp/resend/', ResendOTPView.as_view(), name='otp_resend'),
    path('verify-otp/', VerifyOTPView.as_view(), name='verify_otp'),
    path('password-reset/', PasswordResetRequestView.as_view(), name='password_reset_request'),
    path('password-reset-confirm/<uidb64>/<token>/', PasswordResetConfirmationView.as_view(), name='password_reset_confirm'),
    
    # Expense Model Api Endpoints
    
        # Category API Endpoints
    path('categories/', CategoryAPIView.as_view(), name='category-list'),
    path('categories/<int:pk>/', CategoryAPIView.as_view(), name='category-detail'),

    # Expense API Endpoints
    path('expenses/', ExpenseAPIView.as_view(), name='expense-list'),
    path('expenses/<int:pk>/', ExpenseDetailAPIView.as_view(), name='expense-detail'),

    # Expense Report API Endpoint
    path('expenses/report/', ExpenseReportAPIView.as_view(), name='expense-report'),
   
]
