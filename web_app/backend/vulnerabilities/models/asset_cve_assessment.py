"""Append-only analyst evaluations of one NVD configuration against hardware."""
from django.conf import settings
from django.db import models


class AssetCveAssessment(models.Model):
    class Status(models.TextChoices):
        APPLIES = "APPLIES", "Aplica"
        PENDING_REVIEW = "PENDING_REVIEW", "Pendiente de revisión"
        NOT_APPLICABLE = "NOT_APPLICABLE", "No aplica"

    hardware = models.ForeignKey(
        "assets.Hardware", on_delete=models.PROTECT,
        related_name="cve_assessments",
    )
    cve = models.ForeignKey(
        "vulnerabilities.Cve", on_delete=models.PROTECT,
        related_name="asset_assessments",
    )
    configuration_index = models.PositiveIntegerField()
    configuration_snapshot = models.JSONField(default=dict)
    configuration_fingerprint = models.CharField(max_length=64)
    status = models.CharField(max_length=16, choices=Status.choices)
    criteria_evidence = models.JSONField(default=dict)
    software_installation = models.ForeignKey(
        "assets.SoftwareInstallation", null=True, blank=True,
        on_delete=models.PROTECT, related_name="cve_assessments",
    )
    inventory_fingerprint = models.CharField(max_length=64)
    justification = models.TextField()
    decided_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL,
        null=True, related_name="cve_assessments",
    )
    decided_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-decided_at", "-pk"]
        indexes = [
            models.Index(fields=["hardware", "cve", "decided_at"],
                         name="cve_hardware_history_idx"),
        ]

    def __str__(self):
        return f"{self.cve.cve_id} / hardware #{self.hardware_id}: {self.status}"
