"""Shared NVD catalogue queries and immutable per-retrieval evidence.

A product appearing in this catalogue is NOT a validated AssetCpe.
"""
from django.db import models


class CpeQueryCache(models.Model):
    """Identity of a reusable API query, independent of an inventoried asset."""
    strategy = models.CharField(max_length=20)
    parameter = models.CharField(max_length=240)
    query_key = models.CharField(max_length=64, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["pk"]

    def __str__(self):
        return f"{self.strategy}: {self.parameter}"


class CpeQuerySnapshot(models.Model):
    """One versioned NVD traversal; progress is committed page by page."""
    class Status(models.TextChoices):
        QUEUED = "QUEUED", "En cola"
        RUNNING = "RUNNING", "En ejecución"
        INCOMPLETE = "INCOMPLETE", "Interrumpida; reanudable"
        COMPLETED = "COMPLETED", "Completada"
        FAILED = "FAILED", "Error"

    cache = models.ForeignKey(
        CpeQueryCache, on_delete=models.PROTECT, related_name="snapshots"
    )
    status = models.CharField(
        max_length=12, choices=Status.choices, default=Status.QUEUED, db_index=True
    )
    page_size = models.PositiveIntegerField(default=500)
    next_start_index = models.PositiveIntegerField(default=0)
    expected_total = models.PositiveIntegerField(null=True, blank=True)
    retrieved_count = models.PositiveIntegerField(default=0)
    unique_products_count = models.PositiveIntegerField(default=0)
    pages_fetched = models.PositiveIntegerField(default=0)
    nvd_timestamp = models.CharField(max_length=60, blank=True)
    error_code = models.CharField(max_length=40, blank=True)
    error_message = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    started_at = models.DateTimeField(null=True, blank=True)
    checkpoint_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at", "-pk"]
        indexes = [
            models.Index(fields=["status", "created_at"], name="cpe_cache_queue_idx"),
        ]

    def __str__(self):
        return f"Snapshot {self.pk}: {self.cache_id} / {self.status}"


class CpeQueryProduct(models.Model):
    """Product observed in one particular retrieval, with original NVD JSON.

    Unique(snapshot, CPE) is intentional: a retried page must be idempotent.
    Existing snapshots are never overwritten when a query is refreshed.
    """
    snapshot = models.ForeignKey(
        CpeQuerySnapshot, on_delete=models.PROTECT, related_name="products"
    )
    cpe = models.ForeignKey(
        "vulnerabilities.Cpe", on_delete=models.PROTECT, related_name="query_evidence"
    )
    nvd_record = models.JSONField(default=dict)
    discovered_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["snapshot", "cpe"], name="uniq_cpe_snapshot_product"
            ),
        ]
        indexes = [
            models.Index(fields=["snapshot", "cpe"], name="cpe_snapshot_product_idx"),
        ]
