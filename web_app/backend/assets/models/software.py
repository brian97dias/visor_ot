"""An inventoriable software product/variant, independent of installations."""

from django.core.exceptions import ValidationError
from django.db import models
from django.db.models import Q
from django.db.models.functions import Lower, Trim

from .asset import Asset
from ..software_validation import normalize_software_fields


class Software(models.Model):
    class SoftwareType(models.TextChoices):
        FIRMWARE = "FIRMWARE", "Firmware"
        OS = "OS", "Sistema operativo"
        APPLICATION = "APPLICATION", "Aplicación"

    asset = models.OneToOneField(
        "assets.Asset",
        on_delete=models.CASCADE,
        related_name="software",
        primary_key=True,
    )
    software_type = models.CharField(
        max_length=20, choices=SoftwareType.choices,
    )
    manufacturer = models.CharField(max_length=200, blank=True)
    product = models.CharField(max_length=200)
    version = models.CharField(max_length=100, blank=True)

    class Meta:
        constraints = [
            models.CheckConstraint(
                condition=~Q(product=""),
                name="software_requires_product",
            ),
            models.UniqueConstraint(
                Lower(Trim("manufacturer")),
                Lower(Trim("product")),
                Lower(Trim("version")),
                condition=~Q(manufacturer="") & ~Q(version=""),
                name="unique_known_software_variant_ci",
            ),
        ]

    def clean_fields(self, exclude=None):
        # Normalize *before* validating required/length fields and constraints.
        self.manufacturer, self.product, self.version = normalize_software_fields(
            self.manufacturer, self.product, self.version
        )
        super().clean_fields(exclude=exclude)

    def clean(self):
        super().clean()
        if self.asset_id and self.asset.asset_type != Asset.AssetType.SOFTWARE:
            raise ValidationError({
                "asset": "Software solo puede relacionarse con un activo SOFTWARE."
            })

    def save(self, *args, **kwargs):
        self.manufacturer, self.product, self.version = normalize_software_fields(
            self.manufacturer, self.product, self.version
        )
        super().save(*args, **kwargs)

    @property
    def active_hardware(self):
        """Hosts with a current installation, excluding past unlinked records."""
        from .hardware import Hardware

        return Hardware.objects.filter(
            software_installations__software=self,
            software_installations__unlinked_at__isnull=True,
        ).distinct()

    def __str__(self):
        version = self.version or "versión desconocida"
        return f"{self.product} ({version})"
