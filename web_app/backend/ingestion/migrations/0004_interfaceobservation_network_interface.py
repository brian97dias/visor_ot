from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        ("ingestion", "0003_communicationobservation_communication"),
        ("assets", "0003_networkinterface"),
    ]

    operations = [
        migrations.AddField(
            model_name="interfaceobservation",
            name="network_interface",
            field=models.ForeignKey(
                to="assets.networkinterface",
                null=True,
                blank=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="observations",
            ),
        ),
    ]
