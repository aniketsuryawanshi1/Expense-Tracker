from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from .models import User, OTP, OTPRequestTracker, Expense, ExpenseTracker, Category
import pandas as pd
from datetime import datetime
from .serializers import (
    RegisterSerializer, LoginSerializer, OTPSerializer,
    PasswordResetRequestSerializer, PasswordResetConfirmSerializer,
    LogoutSerializer,
    VerifyOTPSerializer, ExpenseSerializer, ExpenseTrackerSerializer, CategorySerializer, 
)

from django.http import HttpResponse
from .utils import generate_otp, send_email
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_bytes
from django.utils.http import urlsafe_base64_encode
from django.urls import reverse
from rest_framework.permissions import IsAuthenticated



class RegisterView(APIView):

    def post(self, request):
        serializer = RegisterSerializer(data = request.data)

        if serializer.is_valid(raise_exception=True):
            user = serializer.save()
            otp = OTP.objects.create(user = user, otp = generate_otp())
            print("in if block or above the send mail function ")

            send_email(
                "Your OTP Code",
                f"Hello {user.username}, \n\nYour OTP code is {otp.otp}. It expires in 150 seconds.",
                to_email=user.email
                
            )
            print("below the print function ")
            return Response({'message': 'User registered. Please verify your otp.'}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LoginView(APIView):
    def post(self, request):
        serializer = LoginSerializer(data=request.data, context={'request': request})

        if serializer.is_valid():
            validated_data = serializer.validated_data
            login_message = "User logged in successfully"

            response_data = {"message": login_message, **validated_data}
            return Response(response_data, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class VerifyOTPView(APIView):
    def post(self,request):
        serializer = VerifyOTPSerializer(data = request.data)
        if serializer.is_valid():
            otp_code = serializer.validated_data['otp']
            email = OTP.objects.get(otp = otp_code)
            email = email.user

            try:
                user = User.objects.get(email = email)

                otp_instance = OTP.objects.get(otp = otp_code)

                if otp_instance.is_expired():
                    return Response({'error' : 'OTP has expired. Please request a new one.'}, status = status.HTTP_400_BAD_REQUEST)

                if otp_instance.otp == otp_code:
                    user.is_verified = True

                    user.save()

                    otp_instance.is_verified  = True

                    otp_instance.save()

                    return Response({"message" : "OTP verified successfully."}, status=status.HTTP_200_OK)
                else:
                    return Response({'message' : "Invalid OTP"}, status = status.HTTP_400_BAD_REQUEST)

            except User.DoesNotExist:
                return Response({"error": "User with this email does not exist"}, status=status.HTTP_404_NOT_FOUND)

            except OTP.DoesNotExist:
                return Response({'error' : "Invalid OTP or already verified"}, status = status.HTTP_404_NOT_FOUND)

        return Response(serializer.errors, status = status.HTTP_400_BAD_REQUEST)


class LogoutAPIView(APIView):
    serializer_class = LogoutSerializer
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            return Response({'message': 'User logged out successfully'}, status=status.HTTP_204_NO_CONTENT)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class ResendOTPView(APIView):
    def post(self, request):
        serializer =  OTPSerializer(data = request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            user = User.objects.filter(email = email).first()
            if user:
                otp_tracker, _ = OTPRequestTracker.objects.get_or_create(user = user)

                if otp_tracker.can_request_otp():
                    OTP.objects.filter(user = user , is_verified = False).delete()

                    """ Generate OTP and update counter """
                    otp = OTP.objects.create(user = user, otp = generate_otp())

                    otp_tracker.increment_request_count()

                    """ Sending Email """
                    send_email(
                        subject = 'Your OTP Code.',
                        message = f"Hello {user.username}, \n\nYour OTP code is {otp.otp}. It expires in 150 seconds.",
                        to_email=user.email
                    )

                    return Response({'message' : 'OTP resent to your email. '}, status = status.HTTP_200_OK)
                else:
                    return Response(
                        {'error' : "Maximum OTP resend attempts exceeded. Try again after 24 hours."},
                        status = status.HTTP_429_TOO_MANY_REQUESTS
                    )

            else:
                return Response(
                    {'error' : "User with this email does not exist."}, status = status.HTTP_404_NOT_FOUND
                )
        else:
            return Response(
                serializer.errors, status = status.HTTP_400_BAD_REQUEST
            )

class PasswordResetRequestView(APIView):
    def post(self, request):
        serializer = PasswordResetRequestSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            if User.objects.filter(email=email).exists():
                user = User.objects.get(email=email)
                uidb64 = urlsafe_base64_encode(smart_bytes(user.id))
                token = PasswordResetTokenGenerator().make_token(user)
                relative_link = reverse(
                    'password_reset_confirm', kwargs={'uidb64': uidb64, 'token': token}
                )
                abslink = f"http://localhost:5173{relative_link}"
                print("gmail link : ", abslink)
                send_email(
                    'Password Reset Request',
                    f'Hello {user.username}, \n\nUse this link to reset your password: {abslink}. The link expires in 15 minutes.',
                    user.email
                )
                return Response({'message': 'Password reset link sent to your email.'}, status=status.HTTP_200_OK)
            return Response({'error': "User with this email does not exist."}, status=status.HTTP_404_NOT_FOUND)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class PasswordResetConfirmationView(APIView):

    def post(self,request, uidb64, token):
        data = {
            'uidb64' : uidb64,
            'token' : token,
            'password' : request.data.get('password'),
            'password2' : request.data.get('password2')

        }

        serializer = PasswordResetConfirmSerializer(data = data)
        if serializer.is_valid():
            serializer.save()
            return Response({'message' : 'Password reset successful.'}, status = status.HTTP_200_OK)
        return Response(serializer.errors, status = status.HTTP_400_BAD_REQUEST)
    
""" Category Service """
class CategoryAPIView(APIView):
    """ API to manage categories """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        """ Retrieve all categories """
        categories = Category.objects.all()
        serializer = CategorySerializer(categories, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request):
        """ Create a new category """
        serializer = CategorySerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def put(self, request, pk):
        """ Update an existing category """
        try:
            category = Category.objects.get(id=pk)
        except Category.DoesNotExist:
            return Response({'error': 'Category not found'}, status=status.HTTP_404_NOT_FOUND)
        
        serializer = CategorySerializer(category, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def delete(self, request, pk):
        """ Delete an existing category """
        try:
            category = Category.objects.get(id=pk)
        except Category.DoesNotExist:
            return Response({'error': 'Category not found'}, status=status.HTTP_404_NOT_FOUND)
        
        category.delete()
        return Response({'message': 'Category deleted successfully'}, status=status.HTTP_204_NO_CONTENT)


""" Expenses Services """
class ExpenseAPIView(APIView):
    """ API to manage user expenses."""
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        """ Retrieve all expenses for the logged-in user. """
        expenses = Expense.objects.filter(user=request.user)
        serializer = ExpenseSerializer(expenses, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
    def post(self, request):
        """ Add a new Expense or Income."""
        data = request.data.copy()
        data['user'] = request.user.id  # Ensure user is assigned.
        
        serializer = ExpenseSerializer(data=data)
        if serializer.is_valid():
            serializer.save(user=request.user)
            
            """ Update the expense tracker """
            tracker, created = ExpenseTracker.objects.get_or_create(user=request.user)
            tracker.update_totals()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


""" Expense Detail Service """
class ExpenseDetailAPIView(APIView):
    """ API to update or delete an expense """
    permission_classes = [IsAuthenticated]

    def put(self, request, pk):
        """ Update an existing expense """
        try:
            expense = Expense.objects.get(id=pk, user=request.user)
        except Expense.DoesNotExist:
            return Response({"error": "Expense not found"}, status=status.HTTP_404_NOT_FOUND)

        serializer = ExpenseSerializer(expense, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            # Update the tracker after modification
            tracker = ExpenseTracker.objects.get(user=request.user)
            tracker.update_totals()
            return Response(serializer.data, status=status.HTTP_200_OK)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk):
        """ Delete an expense """
        try:
            expense = Expense.objects.get(id=pk, user=request.user)
            expense.delete()
            # Update the tracker after deletion
            tracker = ExpenseTracker.objects.get(user=request.user)
            tracker.update_totals()
            return Response({"message": "Expense deleted successfully"}, status=status.HTTP_204_NO_CONTENT)
        except Expense.DoesNotExist:
            return Response({"error": "Expense not found"}, status=status.HTTP_404_NOT_FOUND)


""" Expense Report Service """
class ExpenseReportAPIView(APIView):
    """ API to generate monthly or yearly reports in Excel """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        """ Generate an expense report for a specific month or year """
        report_type = request.query_params.get('type', 'monthly')  # 'monthly' or 'yearly'
        year = int(request.query_params.get('year', datetime.now().year)) # type: ignore
        month = int(request.query_params.get('month', datetime.now().month)) # type: ignore

        expenses = Expense.objects.filter(user=request.user)
        if report_type == "monthly":
            expenses = expenses.filter(date__year=year, date__month=month)
        elif report_type == "yearly":
            expenses = expenses.filter(date__year=year)

        data = [{
            "Category": exp.category.name,
            "Amount": exp.amount,
            "Date": exp.date.strftime("%Y-%m-%d"),
            "Type": exp.add_expense_type,
            "Description": exp.description
        } for exp in expenses]

        # Create DataFrame and generate Excel
        df = pd.DataFrame(data)
        response = HttpResponse(content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet") # type: ignore
        response["Content-Disposition"] = f'attachment; filename="Expense_Report_{year}.xlsx"'
        df.to_excel(response, index=False)
        return response