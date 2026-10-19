"""Store optional CPU designation for PLC hardware only."""
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("assets", "0009_system_membership"),
    ]

    operations = [
        migrations.AddField(
            model_name="hardware",
            name="cpu_model",
            field=models.CharField(max_length=100, blank=True),
        ),
        migrations.AddConstraint(
            model_name="hardware",
            constraint=models.CheckConstraint(
                condition=models.Q(role="PLC") | models.Q(cpu_model=""),
                name="hardware_cpu_model_only_plc",
            ),
        ),
    ]
