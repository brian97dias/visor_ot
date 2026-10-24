"""Extend existing append-only NVD decision status for analyst conditional applicability."""
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("vulnerabilities", "0010_remove_unused_hardware_decision")]

    operations = [
        migrations.AlterField(
            model_name="assetcveassessment",
            name="status",
            field=models.CharField(max_length=24, choices=[
                ("APPLIES", "Aplica"),
                ("APPLIES_CONDITIONAL", "Aplica condicionada"),
                ("PENDING_REVIEW", "Pendiente de revisión"),
                ("NOT_APPLICABLE", "No aplica"),
            ]),
        ),
    ]
