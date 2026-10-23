"""Phase 2: read Phoenix Contact conditions and record an analyst decision."""
from rest_framework import serializers, status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from .services.cve_assessment import assessment_context, record_assessment
from .services.cve_ingestion import EXPERIMENTAL_CVE_ID
from .views import CpeSearchPermission


class CveAssessmentDecisionSerializer(serializers.Serializer):
    firmware_verdict = serializers.ChoiceField(
        choices=["UNKNOWN", "CONFIRMED", "NOT_MATCH"], default="UNKNOWN"
    )
    software_installation_id = serializers.IntegerField(
        required=False, allow_null=True, min_value=1, default=None
    )
    inventory_declared_complete = serializers.BooleanField(default=False)
    justification = serializers.CharField(max_length=1000, allow_blank=False)
    inventory_fingerprint = serializers.RegexField(regex=r"^[a-f0-9]{64}$")
    configuration_fingerprint = serializers.RegexField(regex=r"^[a-f0-9]{64}$")


class ExperimentalCveAssessmentView(APIView):
    permission_classes = [IsAuthenticated, CpeSearchPermission]

    def get(self, request, asset_id, cve_id):
        if cve_id != EXPERIMENTAL_CVE_ID:
            from rest_framework.exceptions import NotFound
            raise NotFound("Solo se permite el CVE experimental.")
        return Response(assessment_context(asset_id))

    def post(self, request, asset_id, cve_id):
        if cve_id != EXPERIMENTAL_CVE_ID:
            from rest_framework.exceptions import NotFound
            raise NotFound("Solo se permite el CVE experimental.")
        serializer = CveAssessmentDecisionSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        fields = serializer.validated_data
        assessment = record_assessment(
            asset_id, request.user,
            firmware_verdict=fields["firmware_verdict"],
            software_installation_id=fields["software_installation_id"],
            inventory_declared_complete=fields["inventory_declared_complete"],
            justification=fields["justification"],
            expected_inventory_fingerprint=fields["inventory_fingerprint"],
            expected_configuration_fingerprint=fields["configuration_fingerprint"],
        )
        return Response({"assessment": assessment}, status=status.HTTP_201_CREATED)
