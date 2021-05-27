from django.shortcuts import render, redirect
from django.contrib import messages
from .models import *
import bcrypt

def index(request):
    return render(request, 'index.html')

def register(request):
    if request.method == "POST":
        errors = User.objects.basic_validator(request.POST)
        if len(errors) > 0:
            for key, value in errors.items():
                messages.error(request, value)
            return redirect('/')
        first_name = request.POST['first_name']
        last_name = request.POST['last_name']
        email = request.POST['email']
        birthday = request.POST['birthday']
        password = request.POST['password']

        pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

        user = User.objects.create(first_name=first_name, last_name=last_name, email=email, birthday=birthday, password=pw_hash)
        request.session['user_id'] = user.id
        request.session['user_name'] = f'{user.first_name} {user.last_name}'
        
        return redirect('/success')
    return redirect('/')

def login(request):
    if request.method == "POST":
        email = request.POST['email']
        password = request.POST['password']
        logged_user = User.objects.filter(email=email)
    
    if logged_user:
        logged_user = logged_user[0]
        if bcrypt.checkpw(request.POST['password'].encode(), logged_user.password.encode()):
            request.session["user_id"] = logged_user.id
            request.session["user_name"] = f"{logged_user.first_name} {logged_user.last_name}"
            return redirect('/success')
        else:
            messages.error(request, "Password and username do not match.")
            return redirect('/')
    else:
        messages.error(request, "User does not exist.")
        return redirect('/')

    return redirect('/')

def success(request):
    if not "user_id" in request.session:
        return redirect('/')
    
    return render(request, "success.html")

def logout(request):
    request.session.flush()
    return redirect('/')