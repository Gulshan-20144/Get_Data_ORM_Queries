from rest_framework.urls import path
from .views import UserRegistrations,Userlogin,Userdetails,VerifyOTP,ResendOtp,ChangePassword,SendResetPasswordlinkView,UserPasswordResetView,UserApi
urlpatterns = [
    path("api/register_user/",UserRegistrations.as_view()),
    path("api/login_user/",Userlogin.as_view()),
    path("api/user_details/",Userdetails.as_view()),
    path("api/otp_user/",VerifyOTP.as_view()),
    path("api/resent_user_otp/",ResendOtp.as_view()),
    path("api/change_user_pass/",ChangePassword.as_view()),
    path("api/send_reset_password_link-api/",SendResetPasswordlinkView.as_view()),
    path("api/reset_password-link/<uid>/<token>/",UserPasswordResetView.as_view()),
    
    path("api/insert_data/",UserApi.as_view()),
    path("api/get_data/",UserApi.as_view()),
]
