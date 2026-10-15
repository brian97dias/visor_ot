"""Software variants and auditable many-to-many hardware installations."""

from django.conf import settings
from django.db import migrations, models
from django.db.models.functions import Lower, Trim
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        ("assets", "0003_networkinterface"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="Software",
            fields=[
                (
                    "asset",
                    models.OneToOneField(
                        to="assets.asset", on_delete=django.db.models.deletion.CASCADE,
                        related_name="software", primary_key=True, serialize=False,
                    ),
                ),
                (
                    "software_type",
                    models.CharField(
                        max_length=20,
                        choices=[
                            ("FIRMWARE", "Firmware"),
                            ("OS", "Sistema operativo"),
                            ("APPLICATION", "Aplicación"),
                        ],
                    ),
                ),
                ("manufacturer", models.CharField(blank=True, max_length=200)),
                ("product", models.CharField(max_length=200)),
                ("version", models.CharField(blank=True, max_length=100)),
            ],
        ),
        migrations.CreateModel(
            name="SoftwareInstallation",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True, primary_key=True, serialize=False, verbose_name="ID",
                    ),
                ),
                ("registered_at", models.DateTimeField(auto_now_add=True)),
                ("unlinked_at", models.DateTimeField(blank=True, null=True)),
                (
                    "hardware",
                    models.ForeignKey(
                        to="assets.hardware", on_delete=django.db.models.deletion.PROTECT,
                        related_name="software_installations",
                    ),
                ),
                (
                    "software",
                    models.ForeignKey(
                        to="assets.software", on_delete=django.db.models.deletion.PROTECT,
                        related_name="installations",
                    ),
                ),
                (
                    "registered_by",
                    models.ForeignKey(
                        to=settings.AUTH_USER_MODEL,
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="registered_software_installations",
                    ),
                ),
                (
                    "unlinked_by",
                    models.ForeignKey(
                        to=settings.AUTH_USER_MODEL,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="unlinked_software_installations",
                        blank=True, null=True,
                    ),
                ),
            ],
            options={"ordering": ["-registered_at", "-id"]},
        ),
        migrations.AddField(
            model_name="hardware",
            name="software",
            field=models.ManyToManyField(
                blank=True, related_name="host_hardware",
                through="assets.SoftwareInstallation", to="assets.software",
            ),
        ),
        migrations.AddConstraint(
            model_name="software",
            constraint=models.CheckConstraint(
                condition=~models.Q(product=""),
                name="software_requires_product",
            ),
        ),
        migrations.AddConstraint(
            model_name="software",
            constraint=models.UniqueConstraint(
                Lower(Trim("manufacturer")),
                Lower(Trim("product")),
                Lower(Trim("version")),
                condition=~models.Q(manufacturer="") & ~models.Q(version=""),
                name="unique_known_software_variant_ci",
            ),
        ),
        migrations.AddConstraint(
            model_name="softwareinstallation",
            constraint=models.UniqueConstraint(
                fields=("software", "hardware"),
                condition=models.Q(unlinked_at__isnull=True),
                name="unique_active_software_installation",
            ),
        ),
        migrations.AddConstraint(
            model_name="softwareinstallation",
            constraint=models.CheckConstraint(
                condition=(
                    models.Q(unlinked_at__isnull=True, unlinked_by__isnull=True)
                    | models.Q(unlinked_at__isnull=False)
                ),
                name="software_unlink_actor_requires_date",
            ),
        ),
    ]
