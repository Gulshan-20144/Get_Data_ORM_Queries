import logging
from django.db.models import Q,F,Sum,Avg,Max,Min,Count
from ORM_API import status
from django.core.files.base import ContentFile
from rest_framework import generics
from django.shortcuts import render
from .models import User,USER1
from .email import send_otp_via_email
from rest_framework.views import APIView
from rest_framework.response import Response
from .serializers import RagistrationSerializers,LoginSerializer,ChangePasswordSerializer,SendLinkSerializers,ResetPasswordSerializers,Userserilizers
from rest_framework.permissions import IsAuthenticated,AllowAny
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.authentication import JWTAuthentication
# Create your views here.
logger=logging.getLogger("get_Company")

class UserRegistrations(APIView):
    # permissions_classes=[AllowAny]
    serializers_class=RagistrationSerializers
    def post(self,request):
        try:
            logger.info(
            f"Enetr log: Requesting {request.build_absolute_uri()}\n\n additionalInfo:\n\n {request.data}\n\n,")
            serializers=self.serializers_class(data=request.data)
            if serializers.is_valid():
                # print(serializers)
                serializers.save()
                send_otp_via_email(serializers.data["email"],serializers.data["username"])
                status_code=status.CREATED
                response= {
                    "success":True,
                    "massage":" User Ragister Successfully",
                    "status_code":status_code,
                    "Data":serializers.data
                }
               # serializer_data=serializers.data
            elif User.username is not None:
                status_code=status.BAD_REQUEST
                response={
                    "success":False,
                    "status_code":status_code,
                    "Error":{"Username":"Username is already exists"}
                    }
            elif serializers.errors:
                status_code=status.BAD_REQUEST
                response={
                    "success":False,
                    "status_code":status_code,
                    "massage":"Internal Error",
                    "error":serializers.errors
                }
            logger.info(
                f"Enetr log: Requesting {request.build_absolute_uri()}\n\n additionalInfo:\n\n {response}\n\n,")
            # if serializers.errors:
            #    raise Exception
        except Exception as e:
            status_code=status.BAD_REQUEST
            response = {
                "success":False,
                "status_code":status_code,
                "message":"somthing went wrong",
                "error": str(e)
            }
            logger.error(
                f"Enetr log: Requesting {request.build_absolute_uri()}\n\n additionalInfo:\n\n {response}\n\n,")
        return Response(response,status=status_code)
    

class Userlogin(APIView):
   permission_classes = [AllowAny]

   def post(self, request):
      # impor
      # response = {}  # Initialize response with a default value

      logger.info(
         f"Log Enter:Requesting {request.build_absolute_uri()}\n\n additionalInfo\n\n{request.data}"
      )
      
      try:
         username = request.data.get("username")
         email1 = request.data.get("email")
         data = User.objects.filter(username=username).first()
         if data is None:
            raise Exception("Please Enter Correct Username")
         email = data.email
         
         if email == email1:
            if data.verified == True:
               serializers = LoginSerializer(data=request.data)
               if serializers.is_valid():
                  user = serializers.validated_data['user']
                  refresh = RefreshToken.for_user(user)
                  status_code = status.OK
                  response = {
                     "success": True,
                     "status_code": status_code,
                     "message": "Token Created Successfully",
                     "refresh": str(refresh),
                     "Token": str(refresh.access_token)
                  }
               else:
                  raise Exception(serializers.errors)
            else:
               raise Exception("Please verify this user via OTP") 
         else:
            raise Exception("Please Enter Correct Email")  
         
         logger.info(
            f"Log Enter:Requesting {request.build_absolute_uri()}\n\n additionalInfo\n\n{response}"
         )
      
      except Exception as e:
         status_code = status.BAD_REQUEST
         response = {
            "success": False,
            "status_code": status_code,
            "message": "Something went wrong",
            "error": str(e)
         }
         logger.error(
            f"Log Enter:Requesting {request.build_absolute_uri()}\n\n additionalInfo\n\n{response}"
         )
      
      return Response(response, status=status_code)
  
class Userdetails(generics.GenericAPIView):
    permission_classes=[IsAuthenticated]
    authentication_classes=[JWTAuthentication]
    def get(self, request, *args, **kwargs):
        
        logger.info(
            f"Log Enter:Requesting {request.build_absolute_uri()}\n\n additionalInfo\n\n{request.user}"
        )
        try:
            user =request.user
            if user:
                data={
                    "username":user.username,
                    "firstname":user.firstname,
                    "lastname":user.lastname,
                    "email":user.email,
                    "DOB":user.DOB,
                    "image_field": user.image_field.url if user.image_field else None,
                    }
                print(data)
                status_code=status.OK
                response={
                    "Success":True,
                    "Status_code":status_code,
                    "Massege":"Data feched Succesfully",
                    "Data":data
                }
            else:
                status_code=status.NO_CONTENT
                response={
                    "Success":False,
                    "Status_code":status_code,
                    "Massege":"Not  feched User",
                }
            logger.info(
                f"Log Enter:Requesting {request.build_absolute_uri()}\n\n additionalInfo\n\n{response}"
            )
        except Exception as e:
            status_code=status.BAD_REQUEST
            response={
                "Success":True,
                "Status_code":status_code,
                "Massege":"Somthing went wrong",
                "Data":str(e)
            }
            logger.error(
                f"Log Enter:Requesting {request.build_absolute_uri()}\n\n additionalInfo\n\n{response}"
            )
        return Response(response,status=status_code)


class VerifyOTP(APIView):
   def post(self, request):
    try:
        logger.info(
            f"Enter log: Requesting {request.build_absolute_uri()}\n\n additionalInfo:\n\n {request.data}\n\n,")

        email = request.data.get('email')
        otp = request.data.get('otp')
        if otp is None or email is None:
            status_code = status.BAD_REQUEST
            response = {
                "success": False,
                "status_code": status_code,
                "msg": 'You Are Missing One Fields OTP Or Email',
            }
        else:
            user = User.objects.filter(email=email)
            
            if  user.exists():  
               Verified=user[0].verified
               if Verified == False:
                  
                  if user[0].otp != otp:
                     status_code = status.BAD_REQUEST
                     response = {
                        "success": False,
                        "status_code": status_code,
                        "msg": 'Please Enter Valid OTP',
                     }
                  elif user[0].otp == otp:
                     status_code = status.BAD_REQUEST
                     data = {
                        "email": user[0].email,
                        "username": user[0].username,
                     }
                     user=user.first()
                     user.verified = True
                     response = {
                        "success": True,
                        "status_code": status_code,
                        "msg": 'Verified Email Successfully',
                        "Verified": user.verified,
                        "Data": data

                     }
                     user.save()
               else:
                  raise Exception("This User is Already Verified")
            else:
               status_code = status.NO_CONTENT
               response = {
                     "success": False,
                     "status_code": status_code,
                     "msg": 'Email Not Exists',
                  }
        logger.info(
            f"Enter log: Requesting {request.build_absolute_uri()}\n\n additionalInfo:\n\n {response}\n\n,")
    except Exception as e:
        status_code = status.BAD_REQUEST
        response = {
            "success": False,
            "status_code": status_code,
            "msg": 'Something Went Wrong',
            "error": str(e)
        }
        logger.error(
            f"Enter log: Requesting {request.build_absolute_uri()}\n\n additionalInfo:\n\n {response}\n\n,")
    return Response(response, status=status_code)
 

class ResendOtp(APIView):
   def post(self,request):
      try:
         logger.info(
            f"Enter Log:Requesting{request.build_absolute_uri()}\n\n AdditionalInfo:\n\n {request.data}\n\n"
         )
         email=request.data.get("email")
         print(email)
         if email is None:
            raise Exception("Please Enter Email")
         send_otp_via_email(email)
         status_code=status.CREATED
         response= {
                  "success":True,
                  "massage":" OTP Resend Successfully",
                  "status_code":status_code
         }
         logger.info(
            f"Enter Log:Requesting{request.build_absolute_uri()}\n\n Additionalinfo\n\n{response}"
         )
      except Exception as e:
         status_code=status.BAD_REQUEST
         response= {
                  "success":False,
                  "massage":" Something Went Wrong",
                  "status_code":status_code,
                  "error":str(e)
         }
         logger.error(
            f"Enter Log:Requesting{request.build_absolute_uri()}\n\n Additionalinfo\n\n{response}"
         )
      return Response(response,status=status_code)
   
# class ChangePassword
class ChangePassword(APIView):
   permission_classes=[IsAuthenticated]
   
   def post(self,request):
      try:
         logger.info(
            f"Log Enter:Requesting{request.build_absolute_uri()}\n\n AdditionalInfo{request.data}\n\n"
         )
         serializers=ChangePasswordSerializer(data=request.data,context={"user":request.user})
         print(serializers)
         if serializers.is_valid(raise_exception=True):
            
            status_code=status.OK
            response={
               "Success":True,
               "status_code":status_code,
               "massege":"Password Change Successfully"
            } 
         logger.info(
            f"Log Enter:Requesting{request.build_absolute_uri()}\n\n AdditionalInfo{response}\n\n"
         )
      except Exception as e:
         status_code=status.BAD_REQUEST
         response={
               "Success":False,
               "status_code":status_code,
               "massege":"Somthing Went Wrong",
               "Error":str(e)
            }
         logger.error(
            f"Log Enter: Requesting {request.build_absolute_uri()}\n\n AdditionalInfo {response}\n\n"
         )
      return Response(response,status=status_code)
   
class SendResetPasswordlinkView(APIView):
   permission_classes=[AllowAny]
   def post(self,request):
      try:
         logger.info(
            f"Log Enter:Requesting{request.build_absolute_uri()}\n\n AdditionalInfo{request.data}\n\n"
         )
         serializers=SendLinkSerializers(data=request.data)
         if serializers.is_valid():
            status_code=status.BAD_REQUEST
            response={
            "success":True,
            "status_code":status_code,
            "massege":"Reset Link On Your Mail Please Check Your MailBox",
            }
         else:
            raise Exception(serializers.errors)
         logger.info(
            f"Log Enter:Requesting{request.build_absolute_uri()}\n\n AdditionalInfo{response}\n\n"
         )
      except Exception as e:
         status_code=status.BAD_REQUEST
         response={
            "success":False,
            "status_code":status_code,
            "massege":"Somthing Went Wrong",
            "error":str(e)
         }
         logger.info(
            f"Log Enter:Requesting{request.build_absolute_uri()}\n\n AdditionalInfo{response}\n\n"
         )
      return Response(response,status=status_code)
   
class UserPasswordResetView(APIView):
   def post(self,request,uid,token,format=None):
      try:
         logger.info(
            f"Log Enter:Requesting{request.build_absolute_uri()}\n\n AdditionalInfo{request.data}\n\n"
         )
         
         serializers=ResetPasswordSerializers(data=request.data,context={"uid":uid,'token':token})
         if serializers.is_valid():
            status_code=status.OK
            response={
            "success":True,
            "status_code":status_code,
            "massege":"Password Reset Successfully",
            }
         else:
            raise Exception(serializers.errors)
      except Exception as e:
         status_code=status.BAD_REQUEST
         response={
            "success":False,
            "status_code":status_code,
            "massege":"Somthing Went Wrong",
            "error":str(e)
         }
         logger.info(
            f"Log Enter:Requesting{request.build_absolute_uri()}\n\n AdditionalInfo{response}\n\n"
         )
      return Response(response,status=status_code)
   


class UserApi(APIView):
   def post(self,request,format=None):
      logger.info(
            f"Log Enter:Requesting {request.build_absolute_uri()}\n\n additionalInfo\n\n{request.data}"
        )
      try:
         serializer=Userserilizers(data=request.data)
         if serializer.is_valid(raise_exception=True):
            
            phone=serializer.data.get('phone')
            sallary = serializer.data.get("sallary")
            gender = serializer.data.get("gender")
            detail=serializer.data.get("detail")
            print(detail)
            data=User.objects.filter(username=detail).first()
            print(data)
            USER1.objects.create(phone=phone,sallary=sallary,gender=gender,detail=data)
            
            status_code=status.CREATED
            response={
               'Success': True,
               'Status code': status_code,
               'Message':'User Data Created Succesfully',
               "Data":serializer.data
            }
         
         logger.info(
            f"Log Enter:Requesting {request.build_absolute_uri()}\n\n additionalInfo\n\n{response}"
         )
      except Exception as e:
         status_code=status.BAD_REQUEST
         response={
            'Success': False,
            'Status code': status_code,
            'Message':'Somthing Went Wrong',
            "data":str(e)
         }
      return Response(response,status=status_code)
   
   def get(self,request,format=None):
      logger.info(
            f"Log Enter:Requesting {request.build_absolute_uri()}\n\n additionalInfo\n\n{request.data}"
        )
      try:
         detail=request.data.get("detail",None)
         pk=request.data.get("id",None)
         sallary=request.data.get("sallary",None)
         phone=request.data.get("phone",None)
         if pk  is None and detail is None and phone is None and sallary is None: 
            # users=USER1.objects.all # this query get all data from the database
            data=USER1.objects.all().order_by('-id')
            serializer=Userserilizers(data,many=True)
            status_code=status.OK
            response={
               'Success': True,
               'Status code': status_code,
               'Message':'User Data Get Succesfully BY OREDERD BY ID',
               "Data":serializer.data
            }
         elif pk is not None and sallary is None and phone is None:
            # user=USER1.objects.get(id=pk)
            user=USER1.objects.count()
            print(user)
            # serializer=Userserilizers(user)
            status_code=status.OK
            response={
               'Success': True,
               'Status code': status_code,
               'Message':'User COUNT Get Succesfully',
               "Data":user
            }
         elif pk is None and sallary is not None and detail is None and phone is None:
            print(sallary)
            # user=USER1.objects.aggregate(sallary=Sum("sallary"))
            # user=USER1.objects.aggregate(sallary=Avg("sallary"))
            # user=USER1.objects.aggregate(sallary=Min("sallary"))
            user=USER1.objects.aggregate(sallary=Max("sallary"))
            
            print(user)
            # serializer=Userserilizers(user)
            status_code=status.OK
            response={
               'Success': True,
               'Status code': status_code,
               'Message':'User MAX Data Get Succesfully',
               "Data":user
            }
         elif detail is not None and pk is None and sallary is None:
            user=USER1.objects.filter(detail__username=detail).select_related("detail")
            # print(user)
            serializer=Userserilizers(user,many=True)
            status_code=status.OK
            response={
               'Success': True,
               'Status code': status_code,
               'Message':'User Data Get Succesfully BY ONTOMAYRELATIONSHIP',
               "Data":serializer.data
            }
         elif pk is  None and detail is None and phone is not None:
            print(phone)
            user=USER1.objects.exclude(phone=phone)
            # user =USER1.objects.filter(phone=phone).filter(sallary=sallary) #filter by two fields this called channing filters
            print(user)
            serializer=Userserilizers(user,many=True)
            status_code=status.OK
            response={
               'Success': True,
               'Status code': status_code,
               'Message':'User Data Get Succesfully AND exclude FIELD',
               "Data":serializer.data
            }
         elif sallary is not None and detail is not None and phone is None:
            print(detail)
            # user=USER1.objects.filter(Q(detail__username = detail) | Q(sallary = sallary))
            # user=USER1.objects.filter(Q(detail__username = detail) & Q(sallary = sallary))
            user=USER1.objects.filter(Q(detail__username = detail) & ~Q(sallary = sallary))
            print(user)
            serializer=Userserilizers(user,many=True)
            status_code=status.OK
            response={
               'Success': True,
               'Status code': status_code,
               'Message':'User Data Get Succesfully BY USING BIG Q FUNCTIONS',
               "Data":serializer.data
            }
         elif pk is not None and sallary is not None:
            print(pk)
            print(sallary)
            
            # print(user)
            user=USER1.objects.order_by(F("sallary").desc(nulls_last=True))
            print(user)
            serializer=Userserilizers(user, many=True)
            status_code=status.OK
            response={
               'Success': True,
               'Status code': status_code,
               'Message':'User Data Get Succesfully BY USING F FUNCTIONS',
               "Data":serializer.data
            }
         elif pk is not None and phone is not None:
            print(pk)
            user=USER1.objects.values("phone").annotate(pk__count=Count("pk"))
            print(user)
            # serializer=Userserilizers(user,many=True)
            status_code=status.OK
            response={
               'Success': True,
               'Status code': status_code,
               'Message':'User Data Get Succesfully',
               "Data":user
            }
         logger.info(
            f"Log Enter:Requesting {request.build_absolute_uri()}\n\n additionalInfo\n\n{response}"
         )
      except Exception as e:
         status_code=status.BAD_REQUEST
         response={
            'Success': False,
            'Status code': status_code,
            'Message':'Somethin Went Wrong',
            "data":str(e)
         }
      return Response(response,status=status_code)
   
   def put(self,request):
      logger.info(
            f"Log Enter:Requesting {request.build_absolute_uri()}\n\n additionalInfo\n\n{request.data}"
        )
      try:
         serializers=Userserilizers(data=request.data)
         if serializers.is_valid():
            id = request.data.get( "id",None)
            phone2=request.data.get('phone')
            sallary = request.data.get("sallary")
            gender2 = request.data.get("gender")
            detail2=request.data.get("detail")
            # print(detail)
            # user=USER1.objects.filter(id=id).update(phone=phone2,sallary=sallary2,gender=gender2,detail=detail2)
            user =USER1.objects.update(sallary=F("sallary")*1.2)
            # print(user)
            status_code=status.CREATED
            response={
                  'Success': True,
                  'Status code': status_code,
                  'Message':'User Data Updated Succesfully',
                  "Data":serializers.data
               }
            
         logger.info(
            f"Log Enter:Requesting {request.build_absolute_uri()}\n\n additionalInfo\n\n{response}"
         )
      except Exception as e:
         status_code=status.BAD_REQUEST
         response={
            'Success': False,
            'Status code': status_code,
            'Message':'Somthing Went Wrong',
            "data":str(e)
         }
      return Response(response,status=status_code)
   
   def delete(self,request):
      logger.info(
            f"Log Enter:Requesting {request.build_absolute_uri()}\n\n additionalInfo\n\n{request.data}"
        )
      try:
         id=request.data.get( "id" )
         user=USER1.objects.get(id=id)
         print(user)
         user.delete()
         
         status_code=status.CREATED
         response={
                  'Success': True,
                  'Status code': status_code,
                  'Message':'User Data Deleted Succesfully',
               }
            
         logger.info(
            f"Log Enter:Requesting {request.build_absolute_uri()}\n\n additionalInfo\n\n{response}"
         )
      except Exception as e:
         status_code=status.BAD_REQUEST
         response={
            'Success': False,
            'Status code': status_code,
            'Message':'Somthing Went Wrong',
            "data":str(e)
         }
      return Response(response,status=status_code)
   