from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        ("vulnerabilities", "0006_cve"),
        ("assets", "0010_hardware_cpu_model"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="AssetCveAssessment",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True,
                                           serialize=False, verbose_name="ID")),
                ("configuration_index", models.PositiveIntegerField()),
                ("configuration_snapshot", models.JSONField(default=dict)),
                ("configuration_fingerprint", models.CharField(max_length=64)),
                ("status", models.CharField(max_length=16, choices=[
                    ("APPLIES", "Aplica"),
                    ("PENDING_REVIEW", "Pendiente de revisión"),
                    ("NOT_APPLICABLE", "No aplica"),
                ])),
                ("criteria_evidence", models.JSONField(default=dict)),
                ("inventory_fingerprint", models.CharField(max_length=64)),
                ("justification", models.TextField()),
                ("decided_at", models.DateTimeField(auto_now_add=True)),
                ("cve", models.ForeignKey(on_delete=django.db.models.deletion.PROTECT,
                                           related_name="asset_assessments",
                                           to="vulnerabilities.cve")),
                ("hardware", models.ForeignKey(on_delete=django.db.models.deletion.PROTECT,
                                                related_name="cve_assessments",
                                                to="assets.hardware")),
                ("software_installation", models.ForeignKey(
                    to="assets.softwareinstallation", null=True, blank=True,
                    on_delete=django.db.models.deletion.PROTECT,
                    related_name="cve_assessments")),
                ("decided_by", models.ForeignKey(
                    to=settings.AUTH_USER_MODEL, null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    related_name="cve_assessments")),
            ],
            options={"ordering": ["-decided_at", "-pk"]},
        ),
        migrations.AddIndex(
            model_name="assetcveassessment",
            index=models.Index(fields=["hardware", "cve", "decided_at"],
                               name="cve_hardware_history_idx"),
        ),
    ]
