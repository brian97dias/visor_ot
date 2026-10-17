"""Audited membership of Hardware in functional OT systems."""
from django.conf import settings
from django.db import models
from django.db.models import Q


class SystemMembership(models.Model):
    system = models.ForeignKey(
        "assets.OTSystem", on_delete=models.PROTECT, related_name="memberships",
    )
    hardware = models.ForeignKey(
        "assets.Hardware", on_delete=models.PROTECT, related_name="system_memberships",
    )
    registered_at = models.DateTimeField(auto_now_add=True)
    registered_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.PROTECT,
        related_name="registered_system_memberships",
    )
    unlinked_at = models.DateTimeField(null=True, blank=True)
    unlinked_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True,
        related_name="unlinked_system_memberships",
    )

    class Meta:
        ordering = ["-registered_at", "-id"]
        constraints = [
            models.UniqueConstraint(
                fields=("system", "hardware"), condition=Q(unlinked_at__isnull=True),
                name="unique_active_system_membership",
            ),
            models.CheckConstraint(
                condition=(
                    Q(unlinked_at__isnull=True, unlinked_by__isnull=True)
                    | Q(unlinked_at__isnull=False)
                ),
                name="system_unlink_actor_requires_date",
            ),
        ]

    @property
    def is_active(self):
        return self.unlinked_at is None

    def __str__(self):
        return f"{self.system_id} -> {self.hardware_id}"
