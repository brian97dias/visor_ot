from django.urls import path

from .views import (
    AssetArchiveView,
    AssetDetailView,
    AssetListCreateView,
    AssetRestoreView,
)


urlpatterns = [
    path("", AssetListCreateView.as_view(), name="asset-list-create"),
    path("<int:asset_id>/", AssetDetailView.as_view(), name="asset-detail"),
    path("<int:asset_id>/archive/", AssetArchiveView.as_view(), name="asset-archive"),
    path("<int:asset_id>/restore/", AssetRestoreView.as_view(), name="asset-restore"),
]
