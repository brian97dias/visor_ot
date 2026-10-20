"""Strictly typed requests for CPE catalogue validation."""
from rest_framework import serializers
from .models import AssetCpe


class CpeDecisionSerializer(serializers.Serializer):
    run_id = serializers.IntegerField(min_value=1, required=False)
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
        if attrs["status"] == AssetCpe.Validation.REOPENED:
            if self.context.get("creating"):
                raise serializers.ValidationError({
                    "status": "Reabrir requiere una asociación previamente revisada."
                })
            if "run_id" in attrs:
                raise serializers.ValidationError({
                    "run_id": "La reapertura utiliza la evidencia histórica de la asociación."
                })
        elif "run_id" not in attrs:
            raise serializers.ValidationError({
                "run_id": "Selecciona una búsqueda completada para registrar la decisión."
            })
        # The reason remains optional, including when re-opening a decision.
        return attrs
