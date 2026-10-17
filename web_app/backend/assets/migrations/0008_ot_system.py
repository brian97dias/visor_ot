"""Register functional OT systems without changing existing Asset or Hardware data."""
from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        ("assets", "0007_asset_import_batch"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="OTSystem",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True,
                                           serialize=False, verbose_name="ID")),
                ("name", models.CharField(max_length=200)),
                ("description", models.TextField(blank=True)),
                ("criticality", models.CharField(
                    max_length=20, default="UNDEFINED",
                    choices=[
                        ("UNDEFINED", "Sin definir"), ("LOW", "Baja"),
                        ("MEDIUM", "Media"), ("HIGH", "Alta"),
                    ],
                )),
                ("criticality_justification", models.TextField(blank=True)),
                ("impact", models.TextField(blank=True)),
                ("status", models.CharField(
                    max_length=20, default="ACTIVE", db_index=True,
                    choices=[("ACTIVE", "Activo"), ("ARCHIVED", "Archivado")],
                )),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("archived_at", models.DateTimeField(blank=True, null=True)),
                ("archived_by", models.ForeignKey(
                    blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL,
                    related_name="archived_ot_systems", to=settings.AUTH_USER_MODEL,
                )),
                ("created_by", models.ForeignKey(
                    on_delete=django.db.models.deletion.PROTECT,
                    related_name="created_ot_systems", to=settings.AUTH_USER_MODEL,
                )),
                ("updated_by", models.ForeignKey(
                    blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL,
                    related_name="updated_ot_systems", to=settings.AUTH_USER_MODEL,
                )),
            ],
            options={"ordering": ["name", "id"]},
        ),
        migrations.AddConstraint(
            model_name="otsystem",
            constraint=models.CheckConstraint(
                condition=(
                    models.Q(status="ACTIVE", archived_at__isnull=True)
                    | models.Q(status="ARCHIVED", archived_at__isnull=False)
                ),
                name="ot_system_archive_timestamp_consistency",
            ),
        ),
    ]
