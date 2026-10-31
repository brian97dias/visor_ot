"""Authenticated, read-only PDF export of the current OT hardening diagnosis.

The only side effect is the HTTP response. No PDF is persisted on the server,
and no CVE evaluations or external NVD requests are performed.
"""
from io import BytesIO

from django.http import HttpResponse
from django.utils import timezone
from rest_framework.exceptions import ValidationError
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView

from users.permissions import IsAdminOrAnalyst
from .services.hardening_pdf import render_hardening_pdf
from .services.hardening_report_data import collect_hardening_report_data


class HardeningPdfDownloadView(APIView):
    """Export the current approved device-oriented PDF for security staff."""

    permission_classes = [IsAuthenticated, IsAdminOrAnalyst]

    def post(self, request):
        # There is no accepted client-side report override: the backend always
        # uses the current validated inventory and the authenticated identity.
        if request.data:
            raise ValidationError({
                "detail": "La generación del informe no acepta parámetros."
            })

        report = collect_hardening_report_data()
        author = request.user.get_full_name().strip() or request.user.get_username()

        output = BytesIO()
        try:
            render_hardening_pdf(report, output, author=author)
        except ValueError as error:
            # Invalid report contracts must not become a corrupted download.
            raise ValidationError({
                "detail": "El diagnóstico contiene datos no válidos para "
                          "generar el informe. Revisa la integridad del inventario."
            }) from error
        filename = "VISOR_OT_diagnostico_{}.pdf".format(
            timezone.now().strftime("%Y%m%d_%H%M%S")
        )
        response = HttpResponse(
            output.getvalue(), content_type="application/pdf"
        )
        response["Content-Disposition"] = f'attachment; filename="{filename}"'
        response["Cache-Control"] = "private, no-store"
        response["X-Content-Type-Options"] = "nosniff"
        return response
