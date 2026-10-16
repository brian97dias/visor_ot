"""Record historical software identities and audit technical corrections.

Existing installations have no trustworthy installation-time identity stored.
Their snapshots are backfilled with the software data available *at migration*
and explicitly marked as such. No historical correctness is inferred.
"""
from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


def backfill_current_identity(apps, schema_editor):
    SoftwareInstallation = apps.get_model("assets", "SoftwareInstallation")
    for installation in SoftwareInstallation.objects.select_related("software").iterator():
        sw = installation.software
        installation.identity_snapshot = {
            "software_type": sw.software_type,
            "manufacturer": sw.manufacturer,
            "product": sw.product,
            "version": sw.version,
            "_source": "migration_current_value_not_verified",
        }
        installation.save(update_fields=["identity_snapshot"])


class Migration(migrations.Migration):
    dependencies = [
        ("assets", "0004_software_domain"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.AddField(
            model_name="softwareinstallation",
            name="identity_snapshot",
            field=models.JSONField(default=dict),
        ),
        migrations.CreateModel(
            name="SoftwareCorrection",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("changed_at", models.DateTimeField(auto_now_add=True)),
                ("reason", models.TextField()),
                ("identity_before", models.JSONField()),
                ("identity_after", models.JSONField()),
                ("affected_active_installations", models.PositiveIntegerField(default=0)),
                ("software", models.ForeignKey(
                    to="assets.software", on_delete=django.db.models.deletion.PROTECT,
                    related_name="corrections",
                )),
                ("changed_by", models.ForeignKey(
                    to=settings.AUTH_USER_MODEL, on_delete=django.db.models.deletion.PROTECT,
                    related_name="software_corrections",
                )),
            ],
            options={"ordering": ("-changed_at", "-pk")},
        ),
        migrations.RunPython(backfill_current_identity, migrations.RunPython.noop),
    ]
