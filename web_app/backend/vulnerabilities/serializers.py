"""Strictly typed requests for CPE catalogue validation."""
from rest_framework import serializers
from .models import AssetCpe


class CpeDecisionSerializer(serializers.Serializer):
    run_id = serializers.IntegerField(min_value=1)
    cpe_name_id = serializers.UUIDField(required=False)
    status = serializers.ChoiceField(choices=AssetCpe.Validation.choices)
    justification = serializers.CharField(
        required=False, allow_blank=True, trim_whitespace=True, max_length=1000
    )

    def validate(self, attrs):
        if self.context.get("creating") and "cpe_name_id" not in attrs:
            raise serializers.ValidationError({
                "cpe_name_id": "Selecciona un candidato obtenido de NVD."
            })
        # Justification is optional for every decision. When supplied it is
        # stored in AssetCpe and the immutable AssetCpeDecision audit trail.
        return attrs
