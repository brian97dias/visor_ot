"""CPE search endpoints, scoped to the existing inventory Asset identifiers."""
from django.urls import path

from .views import CpeSearchStartView, CpeSearchLatestView, CpeSearchDetailView, CpeOverviewView
from .association_views import AssetCpeListCreateView, AssetCpeDecisionView
from .bulk_views import CpeBulkSearchView
from .external_cpe_views import ExternalCpeVerificationListView, ExternalCpeVerificationDetailView
from .cve_assessment_views import ExperimentalCveAssessmentView
from .cve_catalogue_views import (
    CveCatalogueView, CveCatalogueDetailView, CveCatalogueHardwareView,
)
from .cve_discovery_views import (
    CveDiscoveryListCreateView, CveDiscoveryDetailView,
    CveDiscoveryFindingListView,
)

app_name = "vulnerabilities"
urlpatterns = [
    path("cves/", CveCatalogueView.as_view(), name="cve-catalogue"),
    path("cves/<str:cve_id>/", CveCatalogueDetailView.as_view(), name="cve-catalogue-detail"),
    path("cves/<str:cve_id>/hardware/", CveCatalogueHardwareView.as_view(), name="cve-catalogue-hardware"),
    path("cve-discoveries/", CveDiscoveryListCreateView.as_view(), name="cve-discovery-list"),
    path("cve-discoveries/<int:run_id>/", CveDiscoveryDetailView.as_view(), name="cve-discovery-detail"),
    path("cve-discoveries/<int:run_id>/findings/", CveDiscoveryFindingListView.as_view(), name="cve-discovery-findings"),
    path("cpe-overview/", CpeOverviewView.as_view(), name="cpe-overview"),
    path("assets/<int:asset_id>/cve-assessments/<str:cve_id>/", ExperimentalCveAssessmentView.as_view(), name="asset-cve-assessment"),
    path("cpe-searches/bulk/", CpeBulkSearchView.as_view(), name="cpe-search-bulk"),
    path("assets/<int:asset_id>/cpes/", AssetCpeListCreateView.as_view(), name="asset-cpes"),
    path("assets/<int:asset_id>/cpes/<int:association_id>/", AssetCpeDecisionView.as_view(), name="asset-cpe-review"),
    path("assets/<int:asset_id>/cpe-verifications/", ExternalCpeVerificationListView.as_view(), name="cpe-verifications"),
    path("assets/<int:asset_id>/cpe-verifications/<int:run_id>/", ExternalCpeVerificationDetailView.as_view(), name="cpe-verification-detail"),
    path("assets/<int:asset_id>/cpe-searches/", CpeSearchStartView.as_view(), name="cpe-search-start"),
    path("assets/<int:asset_id>/cpe-searches/latest/", CpeSearchLatestView.as_view(), name="cpe-search-latest"),
    path("assets/<int:asset_id>/cpe-searches/<int:run_id>/", CpeSearchDetailView.as_view(), name="cpe-search-detail"),
]
