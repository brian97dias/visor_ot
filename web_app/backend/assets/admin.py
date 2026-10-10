from django.contrib import admin

from .models import Asset, Hardware


class HardwareInline(admin.StackedInline):
    model = Hardware
    extra = 0
    max_num = 1


@admin.register(Asset)
class AssetAdmin(admin.ModelAdmin):
    list_display = ("name", "asset_type", "criticality", "created_by", "created_at")
    list_filter = ("asset_type", "criticality")
    search_fields = ("name", "description")
    readonly_fields = ("created_at", "updated_at", "created_by", "updated_by")
    inlines = [HardwareInline]

    def save_model(self, request, obj, form, change):
        if not change:
            obj.created_by = request.user
        obj.updated_by = request.user
        super().save_model(request, obj, form, change)
