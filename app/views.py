from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from .models import User, OTP, OTPRequestTracker

from .serializers import (
    RegisterSerializer, LoginSerializer, OTPSerializer,
    PasswordResetRequestSerializer, PasswordResetConfirmSerializer,
    VerifyOTPSerializer
)
from .utils import generate_otp, send_email
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_bytes
from django.utils.http import urlsafe_base64_encode
from django.urls import reverse
# from rest_framework.permissions import IsAuthenticated



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
            return Response({'message': 'User registered. Please verify your otp.'}, status=status.HTTP_100_CONTINUE)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LoginView(APIView):
    def post(self, request):
        serializer = LoginSerializer(data = request.POST, context = {'request' : request})

        if serializer.is_valid():
            validated_data = serializer.validated_data
            # user = User.objects.get(email = validated_data['email'])
            login_message = "User login successfully" 

            response_data =  {"message" : login_message, **validated_data}
            return Response(response_data, status = status.HTTP_200_OK)
        
        return Response(serializer.errors, status = status.HTTP_400_BAD_REQUEST)


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

        serializer = PasswordResetRequestSerializer(data = request.data)

        if serializer.is_valid():

            email = serializer._validated_data['email']

            if User.objects.filter(email = email).exists():
                user = User.objects.get(email = email)
                uidb64 = urlsafe_base64_encode(smart_bytes(user.id))
                token = PasswordResetTokenGenerator().make_token(user)
                current_site = request.get_host()
                relative_link = reverse(
                    'password_reset_confirm', kwargs = {'uidb64' : uidb64, 'token' : token} 
                )

                abslink = f"http://{current_site}{relative_link}"

                send_email(
                    'Password Reset Request',
                    f'Hello {user.username}, \n\nUse this link to reset your password: {abslink}. The link expires in 15 minutes.',
                    user.email
                )

                return Response({'message' : 'Password reset link sent to your email.'}, status = status.HTTP_200_OK)
            return Response({'error' : "User with this email does not exists."}, status= status.HTTP_404_NOT_FOUND)
        return Response(serializer.errors, status = status.HTTP_400_BAD_REQUEST)


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