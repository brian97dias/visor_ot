"""A durable NVD CVE discovery run, distinct from analyst decisions.

selected_hardware_ids snapshots the requested scope. Each entry of queries
will describe a distinct official CPE, its source associations, state,
pagination checkpoint and errors, populated by a later worker increment.
"""
from django.conf import settings
from django.db import models


class CveDiscoveryRun(models.Model):
    class Status(models.TextChoices):
        QUEUED = "QUEUED", "En cola"
        RUNNING = "RUNNING", "En ejecución"
        INCOMPLETE = "INCOMPLETE", "Interrumpida; reanudable"
        COMPLETED = "COMPLETED", "Completada"
        FAILED = "FAILED", "Error"

    requested_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, on_delete=models.SET_NULL,
        related_name="requested_cve_discoveries",
    )
    status = models.CharField(
        max_length=12, choices=Status.choices,
        default=Status.QUEUED, db_index=True,
    )
    selected_hardware_ids = models.JSONField(default=list)
    # Fields per query: cpe_name, sources, status, next_start_index,
    # expected_total, retrieved_count, pages_fetched, error_message.
    queries = models.JSONField(default=list)
    error_code = models.CharField(max_length=40, blank=True)
    error_message = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    started_at = models.DateTimeField(null=True, blank=True)
    checkpoint_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at", "-pk"]
        indexes = [
            models.Index(fields=["status", "created_at"],
                         name="cve_discovery_run_queue_idx"),
        ]

    def __str__(self):
        return f"Búsqueda CVE #{self.pk}: {self.status}"
