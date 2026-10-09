from django.conf import settings
from django.db import models


class Ingestion(models.Model):

    class Status(models.TextChoices):
        ACTIVE = "ACTIVE", "Activa"
        EXCLUDED = "EXCLUDED", "Excluida"


    pcap_id = models.CharField(
        max_length=64,
        db_index=True,
    )

    analysis_hash = models.CharField(
        max_length=64,
        null=True,
        blank=True,
        db_index=True,
    )

    filename = models.CharField(
        max_length=255,
    )

    relative_path = models.TextField()

    schema_version = models.CharField(
        max_length=20,
    )

    imported_at = models.DateTimeField(
        auto_now_add=True,
    )

    imported_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="ingestions",
    )

    status = models.CharField(
        max_length=20,
        choices=Status.choices,
        default=Status.ACTIVE,
        db_index=True,
    )

    interfaces_detected = models.PositiveIntegerField()

    communications_detected = models.PositiveIntegerField()


    class Meta:
        ordering = ["-imported_at"]

        constraints = [
            models.UniqueConstraint(
                fields=[
                    "pcap_id",
                    "analysis_hash",
                ],
                name="unique_pcap_analysis",
            ),

            models.UniqueConstraint(
                fields=[
                    "pcap_id",
                ],
                condition=models.Q(
                    status="ACTIVE"
                ),
                name="unique_active_ingestion_per_pcap",
            ),
        ]


class InterfaceObservation(models.Model):

    ingestion = models.ForeignKey(
        Ingestion,
        on_delete=models.CASCADE,
        related_name="interface_observations",
    )

    mac = models.CharField(
        max_length=17,
    )

    ips = models.JSONField(
        default=list,
    )

    first_seen = models.CharField(
        max_length=19,
    )

    last_seen = models.CharField(
        max_length=19,
    )


    def __str__(self):
        return (
            f"{self.mac} - "
            f"Ingestion #{self.ingestion_id}"
        )


class CommunicationObservation(models.Model):

    ingestion = models.ForeignKey(
        Ingestion,
        on_delete=models.CASCADE,
        related_name="communication_observations",
    )

    communication = models.ForeignKey(
        "network.Communication",
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        related_name="observations",
    )

    client_ip = models.GenericIPAddressField()

    server_ip = models.GenericIPAddressField()

    client_macs = models.JSONField(
        null=True,
        blank=True,
    )

    server_macs = models.JSONField(
        null=True,
        blank=True,
    )

    transport_protocol = models.CharField(
        max_length=10,
    )

    service_port = models.PositiveIntegerField()

    service = models.CharField(
        max_length=100,
        null=True,
        blank=True,
    )

    role_source = models.CharField(
        max_length=50,
        null=True,
        blank=True,
    )

    packet_count = models.PositiveBigIntegerField()

    first_seen = models.CharField(
        max_length=19,
    )

    last_seen = models.CharField(
        max_length=19,
    )

    network_scope = models.CharField(
        max_length=50,
        null=True,
        blank=True,
    )


    def __str__(self):
        return (
            f"{self.client_ip} -> "
            f"{self.server_ip}:"
            f"{self.service_port}"
        )
    