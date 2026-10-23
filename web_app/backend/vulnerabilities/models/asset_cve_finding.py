"""One discovered candidate per hardware/CVE pair, not an evaluation.

sources is a list of CPE-origin snapshots, preserving the confirmed AssetCpe,
source asset and, for software, active SoftwareInstallation. A CVE found via
two CPEs still produces only one AssetCveFinding. Search history remains
in CveDiscoveryRun and is not replaced by later observations.
"""
from django.db import models
from django.utils import timezone


class AssetCveFinding(models.Model):
    hardware = models.ForeignKey(
        "assets.Hardware", on_delete=models.PROTECT,
        related_name="cve_findings",
    )
    cve = models.ForeignKey(
        "vulnerabilities.Cve", on_delete=models.PROTECT,
        related_name="asset_findings",
    )
    first_discovery_run = models.ForeignKey(
        "vulnerabilities.CveDiscoveryRun", on_delete=models.PROTECT,
        related_name="new_findings",
    )
    last_discovery_run = models.ForeignKey(
        "vulnerabilities.CveDiscoveryRun", on_delete=models.PROTECT,
        related_name="observed_findings",
    )
    sources = models.JSONField(default=list)
    # Snapshot fingerprint only: does not mean the asset is vulnerable.
    evidence_fingerprint = models.CharField(max_length=64, blank=True)
    first_discovered_at = models.DateTimeField(auto_now_add=True)
    last_discovered_at = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ["-last_discovered_at", "-pk"]
        constraints = [
            models.UniqueConstraint(fields=["hardware", "cve"],
                                    name="uniq_hardware_cve_finding"),
        ]
        indexes = [
            models.Index(fields=["cve", "last_discovered_at"],
                         name="cve_finding_by_cve_idx"),
        ]

    def __str__(self):
        return f"{self.cve.cve_id} / hardware #{self.hardware_id} (hallazgo)"
