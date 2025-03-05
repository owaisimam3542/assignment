from django.urls import path
from .views import RegisterView, LoginView, UserDetailsView, LogoutView

urlpatterns = [
    path('api/register/', RegisterView.as_view(), name='register'),
    path('api/login/', LoginView.as_view(), name='login'),
    path('api/me/', UserDetailsView.as_view(), name='user-details'),
    path('api/logout/', LogoutView.as_view(), name='logout'),
]
