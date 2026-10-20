"""Verified NVD product catalogue and audited analyst-to-asset associations."""
from django.conf import settings
from django.db import models


class Cpe(models.Model):
    """Official NVD CPE identity, reusable by many inventory assets."""
    cpe_name_id = models.UUIDField(unique=True)
    cpe_name = models.CharField(max_length=500)
    title = models.CharField(max_length=400)
    deprecated = models.BooleanField(default=False)
    nvd_created_at = models.DateTimeField(null=True, blank=True)
    nvd_modified_at = models.DateTimeField(null=True, blank=True)
    fetched_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["title", "pk"]

    def __str__(self):
        return self.title


class AssetCpe(models.Model):
    """A human decision; existence alone never implies a confirmed match."""
    class Validation(models.TextChoices):
        PENDING = "PENDING", "Pendiente"
        CONFIRMED = "CONFIRMED", "Confirmado"
        REJECTED = "REJECTED", "Rechazado"

    asset = models.ForeignKey(
        "assets.Asset", on_delete=models.PROTECT, related_name="cpe_associations"
    )
    cpe = models.ForeignKey(Cpe, on_delete=models.PROTECT, related_name="asset_associations")
    source_run = models.ForeignKey(
        "vulnerabilities.CpeSearchRun", on_delete=models.PROTECT,
        related_name="reviewed_associations"
    )
    validation_status = models.CharField(
        max_length=12, choices=Validation.choices, default=Validation.PENDING
    )
    justification = models.TextField(blank=True)
    validated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, on_delete=models.SET_NULL,
        related_name="validated_cpe_associations"
    )
    validated_at = models.DateTimeField()
    validated_identity_fingerprint = models.CharField(max_length=64)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["cpe__title", "pk"]
        constraints = [
            models.UniqueConstraint(fields=["asset", "cpe"], name="uniq_asset_cpe"),
        ]


class AssetCpeDecision(models.Model):
    """Append-only audit history of explicit analyst decisions."""
    association = models.ForeignKey(
        AssetCpe, on_delete=models.PROTECT, related_name="decision_history"
    )
    previous_status = models.CharField(max_length=12, blank=True)
    new_status = models.CharField(max_length=12, choices=AssetCpe.Validation.choices)
    justification = models.TextField(blank=True)
    source_run = models.ForeignKey(
        "vulnerabilities.CpeSearchRun", on_delete=models.PROTECT,
        related_name="cpe_decisions"
    )
    identity_fingerprint = models.CharField(max_length=64)
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, on_delete=models.SET_NULL,
        related_name="cpe_decision_actions"
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["created_at", "pk"]
