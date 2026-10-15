from django.urls import path

from .interface_views import (
    InterfaceDetailView, InterfaceListCreateView,
    InterfaceIdentifyView, InterfaceUnlinkView,
)

from .views import (
    AssetArchiveView,
    AssetDetailView,
    AssetListCreateView,
    AssetRestoreView,
)


urlpatterns = [
    path("interfaces/", InterfaceListCreateView.as_view(), name="interface-list-create"),
    path("interfaces/<int:interface_id>/", InterfaceDetailView.as_view(), name="interface-detail"),
    path("interfaces/<int:interface_id>/identify/", InterfaceIdentifyView.as_view(), name="interface-identify"),
    path("interfaces/<int:interface_id>/unlink/", InterfaceUnlinkView.as_view(), name="interface-unlink"),
    path("", AssetListCreateView.as_view(), name="asset-list-create"),
    path("<int:asset_id>/", AssetDetailView.as_view(), name="asset-detail"),
    path("<int:asset_id>/archive/", AssetArchiveView.as_view(), name="asset-archive"),
    path("<int:asset_id>/restore/", AssetRestoreView.as_view(), name="asset-restore"),
]
