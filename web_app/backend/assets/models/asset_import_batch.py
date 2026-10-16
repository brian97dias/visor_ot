"""Audit summary for confirmed Excel inventory imports.

The uploaded workbook is not retained; only a hash and decisions are stored.
"""
from django.conf import settings
from django.db import models


class AssetImportBatch(models.Model):
    imported_at = models.DateTimeField(auto_now_add=True)
    imported_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.PROTECT,
        related_name="inventory_excel_imports",
    )
    file_sha256 = models.CharField(max_length=64)
    created_count = models.PositiveIntegerField(default=0)
    updated_count = models.PositiveIntegerField(default=0)
    skipped_count = models.PositiveIntegerField(default=0)
    details = models.JSONField(default=dict)

    class Meta:
        ordering = ("-imported_at", "-pk")

    def __str__(self):
        return f"Importación #{self.pk} ({self.imported_at})"
