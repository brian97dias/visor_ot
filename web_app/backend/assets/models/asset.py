from decimal import Decimal

from django.conf import settings
from django.core.validators import MinValueValidator
from django.db import models


class Asset(models.Model):
    class AssetType(models.TextChoices):
        HARDWARE = "HARDWARE", "Hardware"
        SOFTWARE = "SOFTWARE", "Software"

    class Criticality(models.TextChoices):
        UNDEFINED = "UNDEFINED", "Sin definir"
        LOW = "LOW", "Baja"
        MEDIUM = "MEDIUM", "Media"
        HIGH = "HIGH", "Alta"

    class Currency(models.TextChoices):
        COP = "COP", "Peso colombiano"
        USD = "USD", "Dólar estadounidense"
        EUR = "EUR", "Euro"
        INR = "INR", "Rupia india"
        AUD = "AUD", "Dólar australiano"

    class InventoryStatus(models.TextChoices):
        ACTIVE = "ACTIVE", "En inventario"
        ARCHIVED = "ARCHIVED", "Archivado"

    name = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    asset_type = models.CharField(max_length=20, choices=AssetType.choices, db_index=True)
    criticality = models.CharField(
        max_length=20,
        choices=Criticality.choices,
        default=Criticality.UNDEFINED,
    )
    impact = models.TextField(blank=True)
    replacement_cost = models.DecimalField(
        max_digits=14,
        decimal_places=2,
        null=True,
        blank=True,
        validators=[MinValueValidator(Decimal("0.00"))],
    )
    replacement_currency = models.CharField(
        max_length=3, choices=Currency.choices, blank=True
    )

    inventory_status = models.CharField(
        max_length=20,
        choices=InventoryStatus.choices,
        default=InventoryStatus.ACTIVE,
        db_index=True,
    )
    archived_at = models.DateTimeField(null=True, blank=True)
    archived_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="archived_assets",
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="created_assets",
    )
    updated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="updated_assets",
    )

    class Meta:
        ordering = ["name", "id"]
        constraints = [
            models.CheckConstraint(
                condition=(
                    models.Q(replacement_cost__isnull=True, replacement_currency="")
                    | (
                        models.Q(replacement_cost__isnull=False)
                        & ~models.Q(replacement_currency="")
                    )
                ),
                name="asset_cost_requires_currency",
            ),
        ]

    def __str__(self):
        return self.name
