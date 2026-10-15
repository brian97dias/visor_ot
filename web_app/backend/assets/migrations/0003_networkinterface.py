from django.conf import settings
from django.db import migrations, models
from django.db.models.functions import Lower
import django.db.models.deletion
import assets.models.network_interface


class Migration(migrations.Migration):
    dependencies = [
        ("assets", "0002_inventory_status_eur"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="NetworkInterface",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                (
                    "mac",
                    models.CharField(
                        max_length=17,
                        null=True,
                        blank=True,
                        validators=[assets.models.network_interface.validate_mac],
                    ),
                ),
                (
                    "declared_ip",
                    models.GenericIPAddressField(null=True, blank=True),
                ),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("identified_at", models.DateTimeField(null=True, blank=True)),
                (
                    "hardware",
                    models.ForeignKey(
                        to="assets.hardware",
                        on_delete=django.db.models.deletion.PROTECT,
                        null=True,
                        blank=True,
                        related_name="network_interfaces",
                    ),
                ),
                (
                    "created_by",
                    models.ForeignKey(
                        to=settings.AUTH_USER_MODEL,
                        on_delete=django.db.models.deletion.SET_NULL,
                        null=True,
                        blank=True,
                        related_name="created_network_interfaces",
                    ),
                ),
                (
                    "identified_by",
                    models.ForeignKey(
                        to=settings.AUTH_USER_MODEL,
                        on_delete=django.db.models.deletion.SET_NULL,
                        null=True,
                        blank=True,
                        related_name="identified_network_interfaces",
                    ),
                ),
            ],
            options={"ordering": ["id"]},
        ),
        migrations.AddConstraint(
            model_name="networkinterface",
            constraint=models.UniqueConstraint(
                Lower("mac"),
                condition=models.Q(mac__isnull=False),
                name="unique_network_interface_mac_ci",
            ),
        ),
        migrations.AddConstraint(
            model_name="networkinterface",
            constraint=models.CheckConstraint(
                condition=(
                    (models.Q(mac__isnull=False) & ~models.Q(mac=""))
                    | models.Q(declared_ip__isnull=False)
                ),
                name="network_interface_requires_mac_or_ip",
            ),
        ),
    ]
