from django.core.exceptions import ValidationError
from django.db import models


class Hardware(models.Model):
    class Role(models.TextChoices):
        PLC = "PLC", "PLC"
        RTU = "RTU", "RTU"
        HMI = "HMI", "HMI"
        IED = "IED", "IED"
        SWITCH = "SWITCH", "Switch"
        ROUTER = "ROUTER", "Router"
        GATEWAY = "GATEWAY", "Gateway"
        FIREWALL = "FIREWALL", "Firewall"
        SERVER = "SERVER", "Servidor"
        WORKSTATION = "WORKSTATION", "Estación de trabajo"
        IO_MODULE = "IO_MODULE", "Módulo de entradas/salidas"
        OTHER = "OTHER", "Otro"

    asset = models.OneToOneField(
        "assets.Asset",
        on_delete=models.CASCADE,
        related_name="hardware",
        primary_key=True,
    )
    manufacturer = models.CharField(max_length=200, blank=True)
    model = models.CharField(max_length=200, blank=True)
    cpu_model = models.CharField(max_length=100, blank=True)
    role = models.CharField(max_length=20, choices=Role.choices)
    serial_number = models.CharField(max_length=150, blank=True)
    physical_location = models.CharField(max_length=255, blank=True)
    systems = models.ManyToManyField(
        "assets.OTSystem", through="assets.SystemMembership",
        related_name="member_hardware", blank=True,
    )
    # The M2M manager includes historical links; filter unlinked_at for current memberships.
    software = models.ManyToManyField(
        "assets.Software",
        through="assets.SoftwareInstallation",
        related_name="host_hardware",
        blank=True,
    )

    class Meta:
        constraints = [
            models.CheckConstraint(
                condition=models.Q(role="PLC") | models.Q(cpu_model=""),
                name="hardware_cpu_model_only_plc",
            ),
        ]

    def clean(self):
        super().clean()
        if self.role != self.Role.PLC and self.cpu_model:
            raise ValidationError({
                "cpu_model": "El modelo de CPU solo se registra para hardware con rol PLC."
            })

    @property
    def active_software(self):
        """Only current installations; the plain M2M manager also sees history."""
        from .software import Software

        return Software.objects.filter(
            installations__hardware=self,
            installations__unlinked_at__isnull=True,
        ).distinct()

    def __str__(self):
        return f"{self.asset.name} ({self.get_role_display()})"
