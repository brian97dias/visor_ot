"""Introduce auditable N:M OTSystem / Hardware memberships."""
from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        ("assets", "0008_ot_system"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="SystemMembership",
            fields=[
                ("id", models.BigAutoField(
                    auto_created=True, primary_key=True, serialize=False, verbose_name="ID",
                )),
                ("registered_at", models.DateTimeField(auto_now_add=True)),
                ("unlinked_at", models.DateTimeField(null=True, blank=True)),
                ("hardware", models.ForeignKey(
                    to="assets.hardware", on_delete=django.db.models.deletion.PROTECT,
                    related_name="system_memberships",
                )),
                ("system", models.ForeignKey(
                    to="assets.otsystem", on_delete=django.db.models.deletion.PROTECT,
                    related_name="memberships",
                )),
                ("registered_by", models.ForeignKey(
                    to=settings.AUTH_USER_MODEL, on_delete=django.db.models.deletion.PROTECT,
                    related_name="registered_system_memberships",
                )),
                ("unlinked_by", models.ForeignKey(
                    to=settings.AUTH_USER_MODEL, on_delete=django.db.models.deletion.SET_NULL,
                    related_name="unlinked_system_memberships", null=True, blank=True,
                )),
            ],
            options={"ordering": ["-registered_at", "-id"]},
        ),
        migrations.AddField(
            model_name="hardware", name="systems", field=models.ManyToManyField(
                to="assets.otsystem", through="assets.SystemMembership",
                related_name="member_hardware", blank=True,
            ),
        ),
        migrations.AddConstraint(
            model_name="systemmembership",
            constraint=models.UniqueConstraint(
                fields=("system", "hardware"),
                condition=models.Q(unlinked_at__isnull=True),
                name="unique_active_system_membership",
            ),
        ),
        migrations.AddConstraint(
            model_name="systemmembership",
            constraint=models.CheckConstraint(
                condition=(
                    models.Q(unlinked_at__isnull=True, unlinked_by__isnull=True)
                    | models.Q(unlinked_at__isnull=False)
                ),
                name="system_unlink_actor_requires_date",
            ),
        ),
    ]
