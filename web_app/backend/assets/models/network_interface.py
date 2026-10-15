import re

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models
from django.db.models.functions import Lower


MAC_COLON_PATTERN = re.compile(r"^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$")
MAC_COMPACT_PATTERN = re.compile(r"^[0-9a-f]{12}$")


def normalize_mac(value):
    """Normalize an optional MAC without inventing an address."""
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValidationError("La MAC debe ser una cadena de texto.")

    mac = value.strip().lower().replace("-", ":")
    if not mac:
        return None

    if MAC_COMPACT_PATTERN.fullmatch(mac):
        mac = ":".join(mac[i:i + 2] for i in range(0, 12, 2))

    if not MAC_COLON_PATTERN.fullmatch(mac):
        raise ValidationError(
            "MAC inválida. Utiliza seis pares hexadecimales (AA:BB:CC:DD:EE:FF)."
        )
    return mac


def validate_mac(value):
    normalize_mac(value)


class NetworkInterface(models.Model):
    """Interface inventory identity, distinct from PCAP observations."""

    mac = models.CharField(
        max_length=17,
        null=True,
        blank=True,
        validators=[validate_mac],
    )
    declared_ip = models.GenericIPAddressField(
        null=True,
        blank=True,
    )
    hardware = models.ForeignKey(
        "assets.Hardware",
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="network_interfaces",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="created_network_interfaces",
    )
    identified_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="identified_network_interfaces",
    )
    identified_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["id"]
        constraints = [
            models.UniqueConstraint(
                Lower("mac"),
                condition=models.Q(mac__isnull=False),
                name="unique_network_interface_mac_ci",
            ),
            models.CheckConstraint(
                condition=(
                    (models.Q(mac__isnull=False) & ~models.Q(mac=""))
                    | models.Q(declared_ip__isnull=False)
                ),
                name="network_interface_requires_mac_or_ip",
            ),
        ]

    @property
    def is_identified(self):
        return self.hardware_id is not None

    def clean(self):
        super().clean()
        try:
            self.mac = normalize_mac(self.mac)
        except ValidationError as error:
            raise ValidationError({"mac": error.messages}) from error

        # En formularios, una IP opcional puede llegar como cadena vacía.
        if self.declared_ip == "":
            self.declared_ip = None

        if self.mac is None and self.declared_ip is None:
            raise ValidationError(
                "Registra al menos una MAC o una IP declarada."
            )

    def save(self, *args, **kwargs):
        # Model-level validation is also applied outside DRF.
        self.full_clean()
        return super().save(*args, **kwargs)

    def __str__(self):
        identity = self.mac or self.declared_ip or "sin datos de red"
        return f"Interfaz #{self.pk or 'nueva'} ({identity})"
