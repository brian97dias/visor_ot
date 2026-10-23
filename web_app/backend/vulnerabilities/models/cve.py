"""NVD CVE records and durable fetch jobs; not asset applicability decisions."""
from django.db import models
from django.utils import timezone


class Cve(models.Model):
    """One verified NVD record per CVE; the same row queues its refresh."""

    class FetchStatus(models.TextChoices):
        QUEUED = "QUEUED", "Pendiente de NVD"
        RUNNING = "RUNNING", "Recuperando de NVD"
        COMPLETED = "COMPLETED", "Recuperado"
        FAILED = "FAILED", "Error de recuperación"

    cve_id = models.CharField(max_length=20, unique=True)
    description = models.TextField(blank=True)
    descriptions = models.JSONField(default=list)
    # Unmodified official CVE object for CWE, tags and metadata not mapped above.
    # Existing rows start empty until their next successful refresh.
    nvd_record = models.JSONField(default=dict)
    published = models.DateTimeField(null=True, blank=True)
    last_modified = models.DateTimeField(null=True, blank=True)
    severity = models.CharField(max_length=20, blank=True)
    base_score = models.DecimalField(
        max_digits=4, decimal_places=1, null=True, blank=True
    )
    metrics = models.JSONField(default=dict)
    # Store NVD's unmodified AND/OR/nodes/cpeMatch tree including version bounds.
    configurations = models.JSONField(default=list)
    references = models.JSONField(default=list)
    retrieved_at = models.DateTimeField(null=True, blank=True)
    fetch_status = models.CharField(
        max_length=12, choices=FetchStatus.choices,
        default=FetchStatus.QUEUED, db_index=True
    )
    fetch_error = models.TextField(blank=True)
    queued_at = models.DateTimeField(default=timezone.now, db_index=True)
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-queued_at", "pk"]
        indexes = [
            models.Index(fields=["fetch_status", "queued_at"], name="cve_fetch_queue_idx"),
        ]

    def __str__(self):
        return self.cve_id
