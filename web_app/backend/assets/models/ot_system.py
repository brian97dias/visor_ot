"""Functional OT systems are distinct from individual hardware/software assets."""
from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models


class OTSystem(models.Model):
    class Criticality(models.TextChoices):
        UNDEFINED = "UNDEFINED", "Sin definir"
        LOW = "LOW", "Baja"
        MEDIUM = "MEDIUM", "Media"
        HIGH = "HIGH", "Alta"

    class Status(models.TextChoices):
        ACTIVE = "ACTIVE", "Activo"
        ARCHIVED = "ARCHIVED", "Archivado"

    name = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    criticality = models.CharField(
        max_length=20, choices=Criticality.choices, default=Criticality.UNDEFINED,
    )
    criticality_justification = models.TextField(blank=True)
    impact = models.TextField(blank=True)
    status = models.CharField(
        max_length=20, choices=Status.choices, default=Status.ACTIVE, db_index=True,
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.PROTECT,
        related_name="created_ot_systems",
    )
    updated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL,
        null=True, blank=True, related_name="updated_ot_systems",
    )
    archived_at = models.DateTimeField(null=True, blank=True)
    archived_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL,
        null=True, blank=True, related_name="archived_ot_systems",
    )

    class Meta:
        ordering = ["name", "id"]
        constraints = [
            models.CheckConstraint(
                condition=(
                    models.Q(status="ACTIVE", archived_at__isnull=True)
                    | models.Q(status="ARCHIVED", archived_at__isnull=False)
                ),
                name="ot_system_archive_timestamp_consistency",
            ),
        ]

    def clean(self):
        super().clean()
        self.name = (self.name or "").strip()
        if not self.name:
            raise ValidationError({"name": "El nombre del sistema es obligatorio."})

    def __str__(self):
        return self.name
