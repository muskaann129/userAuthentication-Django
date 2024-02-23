from django.shortcuts import render
from rest_framework.response import Response
from rest_framework.decorators import api_view
from .serializers import RegisterSerializer
from .models import User
from .utils import *
# Create your views here.

@api_view(['POST'])
def register(request):
    userData = request.data
    hashed_password = hash_password(userData['password'])
    serializer = RegisterSerializer(data={**userData, 'password': hashed_password.decode('utf-8')})
    if serializer.is_valid():
        serializer.save() 
        return Response(serializer.data)
    return Response(serializer.errors)

@api_view(['POST'])
def login(request):
    try:
        user = User.objects.get(email=request.data['email'])
        exist = check_password(request.data['password'], user.password.encode('utf-8'))
        if exist:
            token = generate_token(user)
            if is_token_expired(token):
                return Response("Your token has expired!!")
            else:
              response = set_token_cookie(request, token)
              return response
        else:
            return Response('Invalid credentials')
    except:
        return Response('User does not exist')
    
@api_view(['GET'])
def get_user(request):
    # get the user id from the request object
    user_id = request.payload['user']['id']
    user = User.objects.get(id=user_id)
    serializer = RegisterSerializer(user)
    return Response(serializer.data)