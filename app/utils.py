import random 
import string
from django.core.mail import send_mail

def generate_otp():
    return ''.join(random.choices(string.digits, k = 6))

def generate_reset_token():
    return ''.join(random.choices(string.ascii_letters + string.digits, k = 64))

def send_email(subject, message, to_email):
    print("In send mail function from utils file ")
    send_mail(
        subject,
        message,
        'twomindscreate17@gmail.com',
        [to_email],
        fail_silently=False    
        )
    