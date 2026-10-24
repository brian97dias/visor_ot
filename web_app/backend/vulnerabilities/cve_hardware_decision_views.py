"""Human applicability for entire hardware/CVE, independent from NVD rows."""
from rest_framework import serializers, status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from .views import CpeSearchPermission
from .services.cve_general_assessment import general_assessment_context
from .services.hardware_cve_decision import record_hardware_cve_decision


class HardwareCveDecisionSerializer(serializers.Serializer):
    verdict = serializers.ChoiceField(
        choices=("APPLIES", "NOT_APPLICABLE", "PENDING_REVIEW"))
    justification = serializers.CharField(max_length=2000, trim_whitespace=True)
    evidence_description = serializers.CharField(
        max_length=4000, required=False, allow_blank=True, default="")
    evidence_reference = serializers.CharField(
        max_length=500, required=False, allow_blank=True, default="")
    inventory_fingerprint = serializers.RegexField(regex=r"^[a-f0-9]{64}$")
    nvd_fingerprint = serializers.RegexField(regex=r"^[a-f0-9]{64}$")
    override_confirmed_match = serializers.BooleanField(default=False)


class HardwareCveDecisionView(APIView):
    permission_classes = [IsAuthenticated, CpeSearchPermission]

    def get(self, request, cve_id, hardware_id):
        context = general_assessment_context(cve_id, hardware_id)
        return Response({
            "hardware_review": context["hardware_review"],
            "applicability": context["applicability"],
        })

    def post(self, request, cve_id, hardware_id):
        form = HardwareCveDecisionSerializer(data=request.data)
        form.is_valid(raise_exception=True)
        decision = record_hardware_cve_decision(
            cve_id, hardware_id, request.user, **form.validated_data
        )
        return Response({"decision": decision}, status=status.HTTP_201_CREATED)
