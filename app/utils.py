import bcrypt
import jwt
from datetime import datetime, timedelta
from django.conf import settings
from django.http import HttpResponse

def hash_password(password):
  salt = bcrypt.gensalt(rounds=10)
  hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
  return hashed_password

def check_password(password, hashed_password):
  return bcrypt.checkpw(password.encode('utf-8'), hashed_password)

def generate_token(user):
  user_info={
    "id": user.id
  }
  expiration_time = datetime.utcnow() + timedelta(minutes=5) 
  
  token = jwt.encode(
    {'user': user_info, 'exp': expiration_time},
    settings.SECRET_KEY,
    algorithm='HS256'
  )
  return token

def set_token_cookie(request, token):
  expiration_time = datetime.utcnow() + timedelta(minutes=5) 
  response = HttpResponse("Token set in cookie!")
  response.set_cookie("jwt_token", token, expires=expiration_time, httponly=True)

  return response

def verify_token(token):
  payload = jwt.decode(token, options={"verify_signature" : False})
  return payload

def is_token_expired(token):
  try:
    payload = jwt.decode(token, options={"verify_signature" : False})
    expiration_time = datetime.utcfromtimestamp(payload["exp"])
    current_time = datetime.utcnow()
    return current_time > expiration_time
  except jwt.ExpiredSignatureError:
    # token has expired
    return True
  except jwt.DecodeError:
    # token is invalid
    return True