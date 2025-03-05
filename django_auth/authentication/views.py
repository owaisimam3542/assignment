from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth import authenticate, login, logout
from django.middleware.csrf import get_token
from django.http import JsonResponse
from .serializers import RegisterSerializer
from django.contrib.auth import get_user_model
from rest_framework.permissions import IsAuthenticated
from rest_framework.authentication import SessionAuthentication

User = get_user_model()

class RegisterView(APIView):
    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "User registered successfully"}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class LoginView(APIView):
    def post(self, request):
        email = request.data.get("email")
        password = request.data.get("password")
        user = authenticate(request, email=email, password=password)

        if user:
            login(request, user)
            response = JsonResponse({"message": "Login successful"})
            response.set_cookie("auth_token", "some_secure_token", httponly=True, secure=True)
            response.set_cookie("csrftoken", get_token(request))
            return response
        return Response({"error": "Invalid credentials"}, status=status.HTTP_400_BAD_REQUEST)

class UserDetailsView(APIView):
    authentication_classes = [SessionAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        return Response({"email": user.email, "username": user.username})

class LogoutView(APIView):
    def post(self, request):
        logout(request)
        response = Response({"message": "Logged out successfully"})
        response.delete_cookie("auth_token")
        return response
