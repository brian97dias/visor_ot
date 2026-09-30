from django.contrib import admin
from django.contrib.auth.admin import UserAdmin

from .models import User


@admin.register(User)
class CustomUserAdmin(UserAdmin):
    fieldsets = UserAdmin.fieldsets + (
        ("Visual OT", {
            "fields": ("role",),
        }),
    )

    add_fieldsets = UserAdmin.add_fieldsets + (
        ("Visual OT", {
            "fields": ("role","email"),
        }),
    )

    list_display = (
        "username",
        "email",
        "role",
        "is_staff",
        "is_active",
    )