from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView

from .views import LoginView, CurrentUserView


urlpatterns = [
    path("login/", LoginView.as_view(), name="login"),
    path("refresh/", TokenRefreshView.as_view(), name="token_refresh"),
    path("me/", CurrentUserView.as_view(), name="current_user"),
]