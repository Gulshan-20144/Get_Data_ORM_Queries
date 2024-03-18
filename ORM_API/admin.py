from django.contrib import admin
from .models import User,USER1
# Register your models here.
@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    list_display = ['id','username','email','password','DOB','is_active','otp','created_on','updated_at','is_admin','verified']
    
@admin.register(USER1)
class USER1Admin(UserAdmin):
    list_display = ['id','phone','gender',"sallary","detail"]