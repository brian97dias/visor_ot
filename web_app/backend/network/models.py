from django.conf import settings
from django.db import models


class Communication(models.Model):

    class Status(models.TextChoices):
        UNCLASSIFIED = (
            "NO_CLASIFICADA",
            "No clasificada",
        )

        AUTHORIZED = (
            "AUTORIZADA",
            "Autorizada",
        )

        UNAUTHORIZED = (
            "NO_AUTORIZADA",
            "No autorizada",
        )


    source_ip = models.GenericIPAddressField()

    destination_ip = models.GenericIPAddressField()

    transport_protocol = models.CharField(
        max_length=10,
    )

    service_port = models.PositiveIntegerField()

    service = models.CharField(
        max_length=100,
        null=True,
        blank=True,
    )


    status = models.CharField(
        max_length=20,
        choices=Status.choices,
        default=Status.UNCLASSIFIED,
        db_index=True,
    )


    classified_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="classified_communications",
    )

    classified_at = models.DateTimeField(
        null=True,
        blank=True,
    )


    created_at = models.DateTimeField(
        auto_now_add=True,
    )

    updated_at = models.DateTimeField(
        auto_now=True,
    )


    class Meta:

        ordering = [
            "source_ip",
            "destination_ip",
            "transport_protocol",
            "service_port",
        ]

        constraints = [
            models.UniqueConstraint(
                fields=[
                    "source_ip",
                    "destination_ip",
                    "transport_protocol",
                    "service_port",
                ],
                name="unique_communication_signature",
            ),
        ]


    def __str__(self):

        return (
            f"{self.source_ip} -> "
            f"{self.destination_ip} "
            f"{self.transport_protocol}/"
            f"{self.service_port}"
        )