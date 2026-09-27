from django.contrib.auth.models import AbstractUser
from django.db import models


class User(AbstractUser):

    class Role(models.TextChoices):
        ADMIN = "ADMIN", "Administrador"
        ANALYST = "ANALYST", "Analista de ciberseguridad OT"
        OPERATOR = "OPERATOR", "Operador de planta"

    role = models.CharField(
        max_length=20,
        choices=Role.choices,
        default=Role.OPERATOR,
    )