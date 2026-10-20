from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("vulnerabilities", "0002_cpe_validation"),
    ]

    operations = [
        migrations.AlterField(
            model_name="assetcpe",
            name="validation_status",
            field=models.CharField(
                max_length=12, default="PENDING",
                choices=[
                    ("PENDING", "Pendiente"),
                    ("CONFIRMED", "Confirmado"),
                    ("REJECTED", "Rechazado"),
                    ("REOPENED", "Revisión reabierta"),
                ],
            ),
        ),
        migrations.AlterField(
            model_name="assetcpedecision",
            name="new_status",
            field=models.CharField(
                max_length=12,
                choices=[
                    ("PENDING", "Pendiente"),
                    ("CONFIRMED", "Confirmado"),
                    ("REJECTED", "Rechazado"),
                    ("REOPENED", "Revisión reabierta"),
                ],
            ),
        ),
    ]
