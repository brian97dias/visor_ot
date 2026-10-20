from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        ("vulnerabilities", "0004_cpe_nvd_references"),
    ]

    operations = [
        migrations.CreateModel(
            name="CpeQueryCache",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("strategy", models.CharField(max_length=20)),
                ("parameter", models.CharField(max_length=240)),
                ("query_key", models.CharField(max_length=64, unique=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
            ],
            options={"ordering": ["pk"]},
        ),
        migrations.CreateModel(
            name="CpeQuerySnapshot",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("status", models.CharField(
                    choices=[
                        ("QUEUED", "En cola"), ("RUNNING", "En ejecución"),
                        ("INCOMPLETE", "Interrumpida; reanudable"),
                        ("COMPLETED", "Completada"), ("FAILED", "Error")
                    ], db_index=True, default="QUEUED", max_length=12,
                )),
                ("page_size", models.PositiveIntegerField(default=500)),
                ("next_start_index", models.PositiveIntegerField(default=0)),
                ("expected_total", models.PositiveIntegerField(blank=True, null=True)),
                ("retrieved_count", models.PositiveIntegerField(default=0)),
                ("unique_products_count", models.PositiveIntegerField(default=0)),
                ("pages_fetched", models.PositiveIntegerField(default=0)),
                ("nvd_timestamp", models.CharField(blank=True, max_length=60)),
                ("error_code", models.CharField(blank=True, max_length=40)),
                ("error_message", models.TextField(blank=True)),
                ("created_at", models.DateTimeField(auto_now_add=True, db_index=True)),
                ("started_at", models.DateTimeField(blank=True, null=True)),
                ("checkpoint_at", models.DateTimeField(blank=True, null=True)),
                ("finished_at", models.DateTimeField(blank=True, null=True)),
                ("cache", models.ForeignKey(
                    to="vulnerabilities.cpequerycache",
                    on_delete=django.db.models.deletion.PROTECT,
                    related_name="snapshots",
                )),
            ],
            options={"ordering": ["-created_at", "-pk"]},
        ),
        migrations.CreateModel(
            name="CpeQueryProduct",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("nvd_record", models.JSONField(default=dict)),
                ("discovered_at", models.DateTimeField(auto_now_add=True)),
                ("cpe", models.ForeignKey(
                    to="vulnerabilities.cpe", related_name="query_evidence",
                    on_delete=django.db.models.deletion.PROTECT,
                )),
                ("snapshot", models.ForeignKey(
                    to="vulnerabilities.cpequerysnapshot", related_name="products",
                    on_delete=django.db.models.deletion.PROTECT,
                )),
            ],
        ),
        migrations.AddConstraint(
            model_name="cpequeryproduct",
            constraint=models.UniqueConstraint(
                fields=("snapshot", "cpe"), name="uniq_cpe_snapshot_product"
            ),
        ),
        migrations.AddIndex(
            model_name="cpequerysnapshot",
            index=models.Index(
                fields=["status", "created_at"], name="cpe_cache_queue_idx"
            ),
        ),
        migrations.AddIndex(
            model_name="cpequeryproduct",
            index=models.Index(
                fields=["snapshot", "cpe"], name="cpe_snapshot_product_idx"
            ),
        ),
    ]
