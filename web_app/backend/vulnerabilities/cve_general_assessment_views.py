"""Read the per-hardware NVD configuration and record append-only decisions."""
from rest_framework import serializers, status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from .views import CpeSearchPermission
from .services.cve_general_assessment import (
    general_assessment_context, record_general_assessment,
)
from .services.cve_system_audit import ensure_system_cve_assessment


class GeneralCveDecisionSerializer(serializers.Serializer):
    configuration_index = serializers.IntegerField(min_value=0)
    verdict = serializers.ChoiceField(choices=("CONFIRMED", "NOT_MATCH", "UNKNOWN", "CONDITIONAL"))
    software_installation_id = serializers.IntegerField(
        min_value=1, allow_null=True, required=False, default=None,
    )
    inventory_declared_complete = serializers.BooleanField(default=False)
    technical_override_acknowledged = serializers.BooleanField(default=False)
    platform_unverified_acknowledged = serializers.BooleanField(default=False)
    justification = serializers.CharField(allow_blank=False, max_length=1000)
    inventory_fingerprint = serializers.RegexField(regex=r"^[a-f0-9]{64}$")
    configuration_fingerprint = serializers.RegexField(regex=r"^[a-f0-9]{64}$")


class GeneralCveAssessmentView(APIView):
    permission_classes = [IsAuthenticated, CpeSearchPermission]

    def get(self, request, cve_id, hardware_id):
        return Response(general_assessment_context(cve_id, hardware_id))

    def post(self, request, cve_id, hardware_id):
        validator = GeneralCveDecisionSerializer(data=request.data)
        validator.is_valid(raise_exception=True)
        assessment = record_general_assessment(
            cve_id, hardware_id, request.user, **validator.validated_data,
        )
        return Response({"assessment": assessment}, status=status.HTTP_201_CREATED)


class AutomaticCveAssessmentView(APIView):
    """Idempotent audit synchronization for verified NVD conclusions.

    GET of the assessment context remains read-only; explicit POST records
    proven positive correspondences or scoped, evidence-backed exclusions.
    A negative configuration does not dismiss other CVE alternatives.
    """
    permission_classes = [IsAuthenticated, CpeSearchPermission]

    def post(self, request, cve_id, hardware_id):
        record, created = ensure_system_cve_assessment(cve_id, hardware_id)
        return Response({
            "created": created,
            "assessment_id": record.pk if record else None,
            "context": general_assessment_context(cve_id, hardware_id),
        })
