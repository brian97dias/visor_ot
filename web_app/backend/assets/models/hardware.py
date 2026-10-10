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
    role = models.CharField(max_length=20, choices=Role.choices)
    serial_number = models.CharField(max_length=150, blank=True)
    physical_location = models.CharField(max_length=255, blank=True)

    def __str__(self):
        return f"{self.asset.name} ({self.get_role_display()})"
