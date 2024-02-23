from rest_framework.exceptions import PermissionDenied
from .utils import verify_token

class AuthMiddleware:
  def __init__(self, get_response):
    self.get_response = get_response

  def __call__(self, request):
    if request.path == "/app/login" or request.path == "/app/register":
      return self.get_response(request)

    cookies = request.COOKIES
    acees_token = cookies.get("jwt_token")

    # Check if the acces token is present
    if not acees_token:
      return PermissionDenied("No access token found", status=401)
    
    # decode the acces token
    payload = verify_token(acees_token)

    if not payload:
      return PermissionDenied("Invalid token", status=401)

    # set the user id in the request object
    request.payload = payload
    
    response = self.get_response(request)
    return response
