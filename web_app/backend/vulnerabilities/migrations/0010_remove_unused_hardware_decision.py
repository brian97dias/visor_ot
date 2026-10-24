"""Safely remove the unnecessary hardware-level decision table from phase 2.

Preserve the already-applied 0009 migration in database history. Refuse to
discard human decisions if this table was actually used.
"""
from django.db import migrations


def ensure_no_decisions(apps, schema_editor):
    Decision = apps.get_model("vulnerabilities", "HardwareCveDecision")
    if Decision.objects.using(schema_editor.connection.alias).exists():
        raise RuntimeError(
            "No se elimina HardwareCveDecision: hay decisiones humanas guardadas. "
            "Exporta y concilia esos registros antes de aplicar la migración."
        )


class Migration(migrations.Migration):
    dependencies = [("vulnerabilities", "0009_hardware_cve_decision")]
    operations = [
        migrations.RunPython(ensure_no_decisions, migrations.RunPython.noop),
        migrations.DeleteModel(name="HardwareCveDecision"),
    ]
