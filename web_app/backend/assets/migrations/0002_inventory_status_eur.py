# Hand-authored migration for inventory lifecycle and the EUR currency option.
from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        ("assets", "0001_initial"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.AddField(
            model_name="asset",
            name="inventory_status",
            field=models.CharField(
                max_length=20,
                db_index=True,
                choices=[("ACTIVE", "En inventario"), ("ARCHIVED", "Archivado")],
                default="ACTIVE",
            ),
        ),
        migrations.AddField(
            model_name="asset",
            name="archived_at",
            field=models.DateTimeField(null=True, blank=True),
        ),
        migrations.AddField(
            model_name="asset",
            name="archived_by",
            field=models.ForeignKey(
                to=settings.AUTH_USER_MODEL,
                on_delete=django.db.models.deletion.SET_NULL,
                null=True,
                blank=True,
                related_name="archived_assets",
            ),
        ),
        migrations.AlterField(
            model_name="asset",
            name="replacement_currency",
            field=models.CharField(
                max_length=3,
                blank=True,
                choices=[
                    ("COP", "Peso colombiano"),
                    ("USD", "Dólar estadounidense"),
                    ("EUR", "Euro"),
                ],
            ),
        ),
    ]
