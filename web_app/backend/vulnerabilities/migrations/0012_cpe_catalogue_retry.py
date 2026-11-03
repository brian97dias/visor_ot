"""Persist bounded NVD catalogue retry state across worker restarts."""
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("vulnerabilities", "0011_conditional_cve_assessment")]

    operations = [
        migrations.AddField(
            model_name="cpequerysnapshot",
            name="automatic_retry_count",
            field=models.PositiveSmallIntegerField(default=0),
        ),
        migrations.AddField(
            model_name="cpequerysnapshot",
            name="retry_after",
            field=models.DateTimeField(null=True, blank=True),
        ),
    ]
