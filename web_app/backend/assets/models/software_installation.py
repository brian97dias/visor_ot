"""Historical software-to-hardware installation links."""

from django.conf import settings
from django.db import models
from django.db.models import Q


class SoftwareInstallation(models.Model):
    software = models.ForeignKey(
        "assets.Software", on_delete=models.PROTECT,
        related_name="installations",
    )
    hardware = models.ForeignKey(
        "assets.Hardware", on_delete=models.PROTECT,
        related_name="software_installations",
    )
    identity_snapshot = models.JSONField(default=dict)
    registered_at = models.DateTimeField(auto_now_add=True)
    registered_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.PROTECT,
        related_name="registered_software_installations",
    )
    unlinked_at = models.DateTimeField(null=True, blank=True)
    unlinked_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL,
        related_name="unlinked_software_installations",
        null=True, blank=True,
    )

    class Meta:
        ordering = ["-registered_at", "-id"]
        constraints = [
            models.UniqueConstraint(
                fields=("software", "hardware"),
                condition=Q(unlinked_at__isnull=True),
                name="unique_active_software_installation",
            ),
            models.CheckConstraint(
                condition=(
                    Q(unlinked_at__isnull=True, unlinked_by__isnull=True)
                    | Q(unlinked_at__isnull=False)
                ),
                name="software_unlink_actor_requires_date",
            ),
        ]

    @property
    def is_active(self):
        return self.unlinked_at is None

    def __str__(self):
        return f"{self.software} -> {self.hardware}"
