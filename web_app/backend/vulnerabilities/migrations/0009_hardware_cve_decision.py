"""Human hardware/CVE decisions independent of NVD configuration indices."""
from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        ("vulnerabilities", "0008_cve_discovery_foundations"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="HardwareCveDecision",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True,
                                            serialize=False, verbose_name="ID")),
                ("status", models.CharField(max_length=16, choices=[
                    ("APPLIES", "Aplica"), ("NOT_APPLICABLE", "No aplica"),
                    ("PENDING_REVIEW", "Por validar"),
                ])),
                ("justification", models.TextField()),
                ("evidence_description", models.TextField(blank=True)),
                ("evidence_reference", models.CharField(max_length=500, blank=True)),
                ("inventory_fingerprint", models.CharField(max_length=64)),
                ("nvd_fingerprint", models.CharField(max_length=64)),
                ("decided_at", models.DateTimeField(auto_now_add=True)),
                ("cve", models.ForeignKey(to="vulnerabilities.cve",
                    on_delete=django.db.models.deletion.PROTECT,
                    related_name="hardware_decisions")),
                ("hardware", models.ForeignKey(to="assets.hardware",
                    on_delete=django.db.models.deletion.PROTECT,
                    related_name="hardware_cve_decisions")),
                ("decided_by", models.ForeignKey(to=settings.AUTH_USER_MODEL,
                    null=True, on_delete=django.db.models.deletion.SET_NULL,
                    related_name="hardware_cve_decisions")),
            ],
            options={"ordering": ["-decided_at", "-pk"]},
        ),
        migrations.AddIndex(
            model_name="hardwarecvedecision",
            index=models.Index(fields=["hardware", "cve", "decided_at"],
                name="hw_cve_decision_history_idx"),
        ),
    ]
