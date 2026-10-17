from django.urls import path
from .asset_import_views import AssetImportPreviewView, AssetImportConfirmView

from .interface_views import (
    InterfaceDetailView, InterfaceListCreateView,
    InterfaceIdentifyView, InterfaceUnlinkView, AssetInterfaceAssignView,
)

from .software_installation_views import (
    HardwareSoftwareInstallationView, HardwareSoftwareUnlinkView,
    SoftwareHistoryView, SoftwareHardwareInstallationView,
    SoftwareHardwareUnlinkView,
)

from .system_views import (
    SystemListCreateView, SystemDetailView, SystemArchiveView, SystemRestoreView,
)

from .views import (
    AssetArchiveView,
    AssetExportExcelView,
    AssetDetailView,
    AssetListCreateView,
    AssetRestoreView,
)


urlpatterns = [
    path("systems/", SystemListCreateView.as_view(), name="ot-system-list-create"),
    path("systems/<int:system_id>/", SystemDetailView.as_view(), name="ot-system-detail"),
    path("systems/<int:system_id>/archive/", SystemArchiveView.as_view(), name="ot-system-archive"),
    path("systems/<int:system_id>/restore/", SystemRestoreView.as_view(), name="ot-system-restore"),
    path("interfaces/", InterfaceListCreateView.as_view(), name="interface-list-create"),
    path("interfaces/<int:interface_id>/", InterfaceDetailView.as_view(), name="interface-detail"),
    path("interfaces/<int:interface_id>/identify/", InterfaceIdentifyView.as_view(), name="interface-identify"),
    path("interfaces/<int:interface_id>/unlink/", InterfaceUnlinkView.as_view(), name="interface-unlink"),
    path("", AssetListCreateView.as_view(), name="asset-list-create"),
    path("export/excel/", AssetExportExcelView.as_view(), name="asset-export-excel"),
    path("import/preview/", AssetImportPreviewView.as_view(), name="asset-import-preview"),
    path("import/confirm/", AssetImportConfirmView.as_view(), name="asset-import-confirm"),
    path("<int:asset_id>/interfaces/", AssetInterfaceAssignView.as_view(), name="asset-interface-assign"),
    path("<int:asset_id>/software-installations/", HardwareSoftwareInstallationView.as_view(), name="asset-software-installations"),
    path("<int:asset_id>/software-history/", SoftwareHistoryView.as_view(), name="asset-software-history"),
    path("<int:asset_id>/hardware-installations/", SoftwareHardwareInstallationView.as_view(), name="software-hardware-installations"),
    path("<int:asset_id>/hardware-installations/<int:installation_id>/", SoftwareHardwareUnlinkView.as_view(), name="software-hardware-unlink"),
    path("<int:asset_id>/software-installations/<int:installation_id>/", HardwareSoftwareUnlinkView.as_view(), name="asset-software-unlink"),
    path("<int:asset_id>/", AssetDetailView.as_view(), name="asset-detail"),
    path("<int:asset_id>/archive/", AssetArchiveView.as_view(), name="asset-archive"),
    path("<int:asset_id>/restore/", AssetRestoreView.as_view(), name="asset-restore"),
]
