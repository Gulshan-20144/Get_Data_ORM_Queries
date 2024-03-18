from django.db import models
from django.contrib.auth.models import AbstractBaseUser,BaseUserManager
import uuid
# Create your models here.

#CUSTOM USER MANAGER
class UserManager(BaseUserManager):
    
    def create_user(self,username,email,firstname,lastname,DOB,image_field,password=None,**extra_fields):
        """
            Creates and saves a User with the given username, email, DOB,Image, name, and password.
        """
        if not username:
            raise ValueError("User's must have username")
        user=self.model(
            username=username,
            email=email,
            firstname=firstname,
            lastname=lastname,
            DOB=DOB,
            image_field=image_field,
            password=password,
            **extra_fields,
        )
        user.set_password(password)
        user.save(using=self._db)
        return user
            
    def create_superuser(self,username,email,firstname,lastname,DOB,image_field,password=None,**extra_fields):
        """
        Creates and saves a superuser with the given username, email, DOB,image, name, and password.
        """
        user=self.create_user(
            username=username,
            email=email,
            firstname=firstname,
            lastname=lastname,
            DOB=DOB,
            image_field=image_field,
            password=password,
            **extra_fields,
        )
        user.is_admin=True
        user.save(using=self._db)
        return user
    

#custum user model
class User(AbstractBaseUser):
    id=models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        unique=True,
        editable=False,
    )
    username=models.CharField(
        max_length=100,
        verbose_name="username",
        unique=True,
        blank=True,
        null=False
    )
    email = models.EmailField(
        verbose_name="email address",
        max_length=255,
    )
    
    firstname=models.CharField(max_length=100,blank=False,null=False)
    lastname=models.CharField(max_length=100,blank=True,null=True)
    DOB = models.DateField(blank=True,null=True)
    is_active = models.BooleanField(default=True)
    created_on = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_admin = models.BooleanField(default=False)
    otp = models.CharField(max_length=6)
    verified = models.BooleanField(default=False)
    image_field=models.ImageField(upload_to='media', blank=True, null=True)
    
    objects = UserManager()
    USERNAME_FIELD = "username"
    REQUIRED_FIELDS=['firstname','lastname','email',"DOB","image_field"]
    
    def __str__(self):
        return self.username

    def has_perm(self, perm, obj=None):
        "Does the user have a specific permission?"
        # Simplest possible answer: Yes, always
        return self.is_admin

    def has_module_perms(self, app_label):
        "Does the user have permissions to view the app `app_label`?"
        # Simplest possible answer: Yes, always
        return True

    @property
    def is_staff(self):
        "Is the user a member of staff?"
        # Simplest possible answer: All admins are staff
        return self.is_admin

class USER1(models.Model):
    CHOISE_FIELDS=(
        ("M","MALE"),
        ("F","FEMALE"),
        ("T","TRANSH_GENDER"),
    )
    phone=models.IntegerField(blank=True,null=True)
    sallary=models.DecimalField(max_digits=10,decimal_places=3,blank=True,null=True)
    gender=models.CharField(max_length=128,choices=CHOISE_FIELDS,null=True,blank=True)
    detail=models.ForeignKey(User,on_delete=models.CASCADE,null=True,related_name="User",to_field="username")
    
    