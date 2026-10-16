"""Two-phase inventory XLSX import. No writes during preview."""
import json

from rest_framework import status
from rest_framework.exceptions import ValidationError
from rest_framework.parsers import MultiPartParser
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from users.models import User

from .asset_excel_import import MAX_FILE_BYTES, confirm, preview


class AssetImportPermission(IsAuthenticated):
    def has_permission(self, request, view):
        return (
            super().has_permission(request, view)
            and request.user.role in (User.Role.ADMIN, User.Role.OPERATOR)
        )


def read_excel_upload(request):
    file = request.FILES.get("file")
    if file is None:
        raise ValidationError({"file": "Selecciona un archivo .xlsx."})
    if not file.name.lower().endswith(".xlsx"):
        raise ValidationError({"file": "Solo se admiten archivos .xlsx."})
    if file.size > MAX_FILE_BYTES:
        raise ValidationError({"file": "El Excel supera el límite de 2 MB."})
    return file.read()


class AssetImportPreviewView(APIView):
    permission_classes = [AssetImportPermission]
    parser_classes = [MultiPartParser]

    def post(self, request):
        return Response(preview(read_excel_upload(request)))


class AssetImportConfirmView(APIView):
    permission_classes = [AssetImportPermission]
    parser_classes = [MultiPartParser]

    def post(self, request):
        token = request.data.get("token")
        if not isinstance(token, str) or not token:
            raise ValidationError({"token": "Previsualiza el Excel antes de confirmar."})
        try:
            actions = json.loads(request.data.get("actions", "{}"))
        except (TypeError, ValueError):
            raise ValidationError({"actions": "Selecciona acciones válidas."})
        if not isinstance(actions, dict):
            raise ValidationError({"actions": "Las acciones deben ser un objeto."})
        output = confirm(
            read_excel_upload(request),
            token=token,
            actions=actions,
            user=request.user,
        )
        return Response(output, status=status.HTTP_200_OK)
