from django.core.mail import send_mail,EmailMessage
import random
import os
from .models import User


def send_otp_via_email(email,username):
    Subject="Your Account Verifications Mail"
    otp=random.randint(1000,9999)
    massege=f"Your Otp is {otp}"
    email_from= os.environ.get("EMAIL_FROM")
    
    send_mail(Subject,massege,email_from,[email])
    user_obj=User.objects.get(username=username)
    user_obj.otp=otp
    user_obj.save()
    
def send_email(data):
    eamil=EmailMessage(
        subject=data["email_subject"],
        body=data['body'],
        from_email=os.environ.get("EMAIL_FROM"),
        to=[data['to_email']]
    )
    eamil.send()