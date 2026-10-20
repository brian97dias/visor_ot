from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        ("vulnerabilities", "0001_initial"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]
    operations = [
        migrations.CreateModel(
            name="Cpe",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("cpe_name_id", models.UUIDField(unique=True)),
                ("cpe_name", models.CharField(max_length=500)),
                ("title", models.CharField(max_length=400)),
                ("deprecated", models.BooleanField(default=False)),
                ("nvd_created_at", models.DateTimeField(blank=True, null=True)),
                ("nvd_modified_at", models.DateTimeField(blank=True, null=True)),
                ("fetched_at", models.DateTimeField(auto_now=True)),
            ],
            options={"ordering": ["title", "pk"]},
        ),
        migrations.CreateModel(
            name="AssetCpe",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("validation_status", models.CharField(
                    choices=[("PENDING", "Pendiente"), ("CONFIRMED", "Confirmado"), ("REJECTED", "Rechazado")],
                    default="PENDING", max_length=12
                )),
                ("justification", models.TextField(blank=True)),
                ("validated_at", models.DateTimeField()),
                ("validated_identity_fingerprint", models.CharField(max_length=64)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("asset", models.ForeignKey(
                    on_delete=django.db.models.deletion.PROTECT,
                    related_name="cpe_associations", to="assets.asset"
                )),
                ("cpe", models.ForeignKey(
                    on_delete=django.db.models.deletion.PROTECT,
                    related_name="asset_associations", to="vulnerabilities.cpe"
                )),
                ("source_run", models.ForeignKey(
                    on_delete=django.db.models.deletion.PROTECT,
                    related_name="reviewed_associations", to="vulnerabilities.cpesearchrun"
                )),
                ("validated_by", models.ForeignKey(
                    null=True, on_delete=django.db.models.deletion.SET_NULL,
                    related_name="validated_cpe_associations", to=settings.AUTH_USER_MODEL
                )),
            ],
            options={"ordering": ["cpe__title", "pk"]},
        ),
        migrations.AddConstraint(
            model_name="assetcpe",
            constraint=models.UniqueConstraint(fields=("asset", "cpe"), name="uniq_asset_cpe"),
        ),
        migrations.CreateModel(
            name="AssetCpeDecision",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("previous_status", models.CharField(blank=True, max_length=12)),
                ("new_status", models.CharField(
                    choices=[("PENDING", "Pendiente"), ("CONFIRMED", "Confirmado"), ("REJECTED", "Rechazado")],
                    max_length=12
                )),
                ("justification", models.TextField(blank=True)),
                ("identity_fingerprint", models.CharField(max_length=64)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("association", models.ForeignKey(
                    on_delete=django.db.models.deletion.PROTECT,
                    related_name="decision_history", to="vulnerabilities.assetcpe"
                )),
                ("source_run", models.ForeignKey(
                    on_delete=django.db.models.deletion.PROTECT,
                    related_name="cpe_decisions", to="vulnerabilities.cpesearchrun"
                )),
                ("actor", models.ForeignKey(
                    null=True, on_delete=django.db.models.deletion.SET_NULL,
                    related_name="cpe_decision_actions", to=settings.AUTH_USER_MODEL
                )),
            ],
            options={"ordering": ["created_at", "pk"]},
        ),
    ]
