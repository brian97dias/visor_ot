from rest_framework.permissions import BasePermission, SAFE_METHODS

from users.models import User


class NetworkInterfacePermission(BasePermission):
    """All roles may read; only plant operator and admin register identities."""

    def has_permission(self, request, view):
        if request.method in SAFE_METHODS:
            return request.user.role in (
                User.Role.ADMIN,
                User.Role.ANALYST,
                User.Role.OPERATOR,
            )
        if request.method == "POST":
            return request.user.role in (User.Role.ADMIN, User.Role.OPERATOR)
        return False
