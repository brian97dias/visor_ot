"""Durable search history, independent of future validated CPE associations."""
from django.conf import settings
from django.db import models


class CpeSearchRun(models.Model):
    class Status(models.TextChoices):
        QUEUED = "QUEUED", "Pendiente"
        RUNNING = "RUNNING", "Consultando NVD"
        COMPLETED = "COMPLETED", "Completada"
        FAILED = "FAILED", "Error"

    class Scope(models.TextChoices):
        SPECIFIC = "SPECIFIC", "Específica"
        BROAD = "BROAD", "Ampliada"

    asset = models.ForeignKey(
        "assets.Asset", on_delete=models.PROTECT, related_name="cpe_searches"
    )
    requested_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, on_delete=models.SET_NULL,
        related_name="requested_cpe_searches"
    )
    status = models.CharField(
        max_length=12, choices=Status.choices, default=Status.QUEUED, db_index=True
    )
    scope = models.CharField(
        max_length=12, choices=Scope.choices, default=Scope.SPECIFIC
    )
    trigger = models.CharField(max_length=12, default="MANUAL")
    identity_snapshot = models.JSONField(default=dict)
    identity_fingerprint = models.CharField(max_length=64, db_index=True)
    queries = models.JSONField(default=list)
    candidates = models.JSONField(default=list)
    result_truncated = models.BooleanField(default=False)
    error_message = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at", "-id"]
        indexes = [
            models.Index(fields=["status", "created_at"], name="cpe_run_queue_idx"),
        ]
