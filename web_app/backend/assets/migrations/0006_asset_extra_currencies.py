from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("assets", "0005_software_corrections")]

    operations = [
        migrations.AlterField(
            model_name="asset",
            name="replacement_currency",
            field=models.CharField(
                blank=True,
                choices=[
                    ("COP", "Peso colombiano"),
                    ("USD", "Dólar estadounidense"),
                    ("EUR", "Euro"),
                    ("INR", "Rupia india"),
                    ("AUD", "Dólar australiano"),
                ],
                max_length=3,
            ),
        ),
    ]
