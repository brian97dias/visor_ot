"""Append-only human decision for an entire hardware/CVE (not a NVD alternative)."""
from django.conf import settings
from django.db import models


class HardwareCveDecision(models.Model):
    class Status(models.TextChoices):
        APPLIES = "APPLIES", "Aplica"
        NOT_APPLICABLE = "NOT_APPLICABLE", "No aplica"
        PENDING_REVIEW = "PENDING_REVIEW", "Por validar"

    hardware = models.ForeignKey("assets.Hardware", on_delete=models.PROTECT,
                                 related_name="hardware_cve_decisions")
    cve = models.ForeignKey("vulnerabilities.Cve", on_delete=models.PROTECT,
                            related_name="hardware_decisions")
    status = models.CharField(max_length=16, choices=Status.choices)
    justification = models.TextField()
    # Can describe an engineering station, STEP 7/TIA Portal, documents or
    # physical inspection, without claiming a software installation on PLC.
    evidence_description = models.TextField(blank=True)
    evidence_reference = models.CharField(max_length=500, blank=True)
    inventory_fingerprint = models.CharField(max_length=64)
    nvd_fingerprint = models.CharField(max_length=64)
    decided_by = models.ForeignKey(settings.AUTH_USER_MODEL,
        null=True, on_delete=models.SET_NULL, related_name="hardware_cve_decisions")
    decided_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-decided_at", "-pk"]
        indexes = [models.Index(fields=["hardware", "cve", "decided_at"],
                                name="hw_cve_decision_history_idx")]

    def __str__(self):
        return f"{self.cve.cve_id} / hardware #{self.hardware_id}: {self.status}"
