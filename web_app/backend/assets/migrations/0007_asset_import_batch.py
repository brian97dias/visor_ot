from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        ("assets", "0006_asset_extra_currencies"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="AssetImportBatch",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True,
                    serialize=False, verbose_name="ID")),
                ("imported_at", models.DateTimeField(auto_now_add=True)),
                ("file_sha256", models.CharField(max_length=64)),
                ("created_count", models.PositiveIntegerField(default=0)),
                ("updated_count", models.PositiveIntegerField(default=0)),
                ("skipped_count", models.PositiveIntegerField(default=0)),
                ("details", models.JSONField(default=dict)),
                ("imported_by", models.ForeignKey(
                    on_delete=django.db.models.deletion.PROTECT,
                    related_name="inventory_excel_imports",
                    to=settings.AUTH_USER_MODEL,
                )),
            ],
            options={"ordering": ("-imported_at", "-pk")},
        ),
    ]
