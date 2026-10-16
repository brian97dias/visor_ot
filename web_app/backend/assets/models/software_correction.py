"""Immutable audit trail for technical corrections of software inventory."""
from django.conf import settings
from django.db import models


class SoftwareCorrection(models.Model):
    software = models.ForeignKey(
        "assets.Software", on_delete=models.PROTECT, related_name="corrections",
    )
    changed_at = models.DateTimeField(auto_now_add=True)
    changed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.PROTECT,
        related_name="software_corrections",
    )
    reason = models.TextField()
    identity_before = models.JSONField()
    identity_after = models.JSONField()
    affected_active_installations = models.PositiveIntegerField(default=0)

    class Meta:
        ordering = ("-changed_at", "-pk")

    def __str__(self):
        return f"Corrección software #{self.software_id} ({self.changed_at})"
