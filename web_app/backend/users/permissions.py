from rest_framework.permissions import BasePermission

from .models import User


class IsAdminOrAnalyst(BasePermission):
    """Allow changes to OT network evidence only to security staff."""

    message = "Esta operación requiere el rol de administrador o analista."

    def has_permission(self, request, view):
        return (
            request.user.is_authenticated
            and request.user.role in (User.Role.ADMIN, User.Role.ANALYST)
        )
