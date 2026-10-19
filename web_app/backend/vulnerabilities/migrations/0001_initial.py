from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    initial = True

    dependencies = [
        ("assets", "0010_hardware_cpu_model"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="CpeSearchRun",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("status", models.CharField(max_length=12, default="QUEUED", choices=[
                    ("QUEUED", "Pendiente"), ("RUNNING", "Consultando NVD"),
                    ("COMPLETED", "Completada"), ("FAILED", "Error"),
                ], db_index=True)),
                ("scope", models.CharField(max_length=12, default="SPECIFIC", choices=[
                    ("SPECIFIC", "Específica"), ("BROAD", "Ampliada"),
                ])),
                ("trigger", models.CharField(max_length=12, default="MANUAL")),
                ("identity_snapshot", models.JSONField(default=dict)),
                ("identity_fingerprint", models.CharField(max_length=64, db_index=True)),
                ("queries", models.JSONField(default=list)),
                ("candidates", models.JSONField(default=list)),
                ("result_truncated", models.BooleanField(default=False)),
                ("error_message", models.TextField(blank=True)),
                ("created_at", models.DateTimeField(auto_now_add=True, db_index=True)),
                ("started_at", models.DateTimeField(null=True, blank=True)),
                ("finished_at", models.DateTimeField(null=True, blank=True)),
                ("asset", models.ForeignKey(
                    to="assets.asset", on_delete=django.db.models.deletion.PROTECT,
                    related_name="cpe_searches",
                )),
                ("requested_by", models.ForeignKey(
                    to=settings.AUTH_USER_MODEL, null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    related_name="requested_cpe_searches",
                )),
            ],
            options={"ordering": ["-created_at", "-id"]},
        ),
        migrations.AddIndex(
            model_name="cpesearchrun",
            index=models.Index(
                fields=["status", "created_at"], name="cpe_run_queue_idx",
            ),
        ),
    ]
