from django.db import migrations, models
import django.utils.timezone


class Migration(migrations.Migration):
    dependencies = [
        ("vulnerabilities", "0005_cpe_catalogue_cache"),
    ]

    operations = [
        migrations.CreateModel(
            name="Cve",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True,
                                          serialize=False, verbose_name="ID")),
                ("cve_id", models.CharField(max_length=20, unique=True)),
                ("description", models.TextField(blank=True)),
                ("descriptions", models.JSONField(default=list)),
                ("published", models.DateTimeField(null=True, blank=True)),
                ("last_modified", models.DateTimeField(null=True, blank=True)),
                ("severity", models.CharField(max_length=20, blank=True)),
                ("base_score", models.DecimalField(max_digits=4, decimal_places=1,
                                                   null=True, blank=True)),
                ("metrics", models.JSONField(default=dict)),
                ("configurations", models.JSONField(default=list)),
                ("references", models.JSONField(default=list)),
                ("retrieved_at", models.DateTimeField(null=True, blank=True)),
                ("fetch_status", models.CharField(
                    max_length=12, db_index=True, default="QUEUED",
                    choices=[
                        ("QUEUED", "Pendiente de NVD"),
                        ("RUNNING", "Recuperando de NVD"),
                        ("COMPLETED", "Recuperado"),
                        ("FAILED", "Error de recuperación"),
                    ],
                )),
                ("fetch_error", models.TextField(blank=True)),
                ("queued_at", models.DateTimeField(
                    default=django.utils.timezone.now, db_index=True
                )),
                ("started_at", models.DateTimeField(null=True, blank=True)),
                ("finished_at", models.DateTimeField(null=True, blank=True)),
            ],
            options={"ordering": ["-queued_at", "pk"]},
        ),
        migrations.AddIndex(
            model_name="cve",
            index=models.Index(fields=["fetch_status", "queued_at"],
                               name="cve_fetch_queue_idx"),
        ),
    ]
