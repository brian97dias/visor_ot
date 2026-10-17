from rest_framework.permissions import BasePermission, SAFE_METHODS

from users.models import User


class AssetPermission(BasePermission):
    """Autorización de negocio para el inventario de activos."""

    def has_permission(self, request, view):
        role = request.user.role

        if request.method in SAFE_METHODS:
            return role in (
                User.Role.ADMIN,
                User.Role.ANALYST,
                User.Role.OPERATOR,
            )

        if request.method == "POST":
            return role in (User.Role.ADMIN, User.Role.OPERATOR)

        if request.method == "PATCH":
            if role == User.Role.ANALYST and "criticality" in request.data:
                return False
            return role in (
                User.Role.ADMIN,
                User.Role.ANALYST,
                User.Role.OPERATOR,
            )

        return False


class SystemPermission(BasePermission):
    """Read: all OT roles. Write: administrators and operators only."""

    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False
        if request.method in SAFE_METHODS:
            return request.user.role in (
                User.Role.ADMIN, User.Role.ANALYST, User.Role.OPERATOR,
            )
        if request.method in ("POST", "PATCH", "DELETE"):
            return request.user.role in (User.Role.ADMIN, User.Role.OPERATOR)
        return False


class AssetArchivePermission(BasePermission):
    """Solo administrador y operador pueden archivar o restaurar activos."""

    def has_permission(self, request, view):
        return (
            request.method == "POST"
            and request.user.role in (User.Role.ADMIN, User.Role.OPERATOR)
        )
