"""CVE discovery runs and candidate findings; no automatic applicability."""
from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone


class Migration(migrations.Migration):
    dependencies = [
        ("vulnerabilities", "0007_asset_cve_assessment"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.AddField(
            model_name="cve", name="nvd_record",
            field=models.JSONField(default=dict),
        ),
        migrations.CreateModel(
            name="CveDiscoveryRun",
            fields=[
                ("id", models.BigAutoField(
                    auto_created=True, primary_key=True,
                    serialize=False, verbose_name="ID",
                )),
                ("status", models.CharField(
                    max_length=12, default="QUEUED", db_index=True,
                    choices=[
                        ("QUEUED", "En cola"),
                        ("RUNNING", "En ejecución"),
                        ("INCOMPLETE", "Interrumpida; reanudable"),
                        ("COMPLETED", "Completada"),
                        ("FAILED", "Error"),
                    ],
                )),
                ("selected_hardware_ids", models.JSONField(default=list)),
                ("queries", models.JSONField(default=list)),
                ("error_code", models.CharField(max_length=40, blank=True)),
                ("error_message", models.TextField(blank=True)),
                ("created_at", models.DateTimeField(auto_now_add=True, db_index=True)),
                ("started_at", models.DateTimeField(null=True, blank=True)),
                ("checkpoint_at", models.DateTimeField(null=True, blank=True)),
                ("finished_at", models.DateTimeField(null=True, blank=True)),
                ("requested_by", models.ForeignKey(
                    to=settings.AUTH_USER_MODEL, null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    related_name="requested_cve_discoveries",
                )),
            ],
            options={"ordering": ["-created_at", "-pk"]},
        ),
        migrations.CreateModel(
            name="AssetCveFinding",
            fields=[
                ("id", models.BigAutoField(
                    auto_created=True, primary_key=True,
                    serialize=False, verbose_name="ID",
                )),
                ("sources", models.JSONField(default=list)),
                ("evidence_fingerprint", models.CharField(max_length=64, blank=True)),
                ("first_discovered_at", models.DateTimeField(auto_now_add=True)),
                ("last_discovered_at", models.DateTimeField(
                    default=django.utils.timezone.now,
                )),
                ("cve", models.ForeignKey(
                    to="vulnerabilities.cve",
                    on_delete=django.db.models.deletion.PROTECT,
                    related_name="asset_findings",
                )),
                ("hardware", models.ForeignKey(
                    to="assets.hardware",
                    on_delete=django.db.models.deletion.PROTECT,
                    related_name="cve_findings",
                )),
                ("first_discovery_run", models.ForeignKey(
                    to="vulnerabilities.cvediscoveryrun",
                    on_delete=django.db.models.deletion.PROTECT,
                    related_name="new_findings",
                )),
                ("last_discovery_run", models.ForeignKey(
                    to="vulnerabilities.cvediscoveryrun",
                    on_delete=django.db.models.deletion.PROTECT,
                    related_name="observed_findings",
                )),
            ],
            options={"ordering": ["-last_discovered_at", "-pk"]},
        ),
        migrations.AddIndex(
            model_name="cvediscoveryrun",
            index=models.Index(
                fields=["status", "created_at"],
                name="cve_discovery_run_queue_idx",
            ),
        ),
        migrations.AddIndex(
            model_name="assetcvefinding",
            index=models.Index(
                fields=["cve", "last_discovered_at"],
                name="cve_finding_by_cve_idx",
            ),
        ),
        migrations.AddConstraint(
            model_name="assetcvefinding",
            constraint=models.UniqueConstraint(
                fields=("hardware", "cve"),
                name="uniq_hardware_cve_finding",
            ),
        ),
    ]
