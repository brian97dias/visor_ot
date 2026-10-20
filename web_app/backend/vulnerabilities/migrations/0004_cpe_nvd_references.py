from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        ("vulnerabilities", "0003_cpe_reopened"),
    ]
    operations = [
        migrations.AddField(
            model_name="cpe",
            name="nvd_references",
            field=models.JSONField(default=list, blank=True),
        ),
        migrations.AddField(
            model_name="cpe",
            name="references_source_run",
            field=models.ForeignKey(
                to="vulnerabilities.cpesearchrun", null=True, blank=True,
                on_delete=django.db.models.deletion.PROTECT,
                related_name="referenced_catalogue_cpes",
            ),
        ),
    ]
