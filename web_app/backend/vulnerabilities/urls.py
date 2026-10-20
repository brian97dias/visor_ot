"""CPE search endpoints, scoped to the existing inventory Asset identifiers."""
from django.urls import path

from .views import CpeSearchStartView, CpeSearchLatestView, CpeSearchDetailView, CpeOverviewView
from .association_views import AssetCpeListCreateView, AssetCpeDecisionView
from .bulk_views import CpeBulkSearchView

app_name = "vulnerabilities"
urlpatterns = [
    path("cpe-overview/", CpeOverviewView.as_view(), name="cpe-overview"),
    path("cpe-searches/bulk/", CpeBulkSearchView.as_view(), name="cpe-search-bulk"),
    path("assets/<int:asset_id>/cpes/", AssetCpeListCreateView.as_view(), name="asset-cpes"),
    path("assets/<int:asset_id>/cpes/<int:association_id>/", AssetCpeDecisionView.as_view(), name="asset-cpe-review"),
    path("assets/<int:asset_id>/cpe-searches/", CpeSearchStartView.as_view(), name="cpe-search-start"),
    path("assets/<int:asset_id>/cpe-searches/latest/", CpeSearchLatestView.as_view(), name="cpe-search-latest"),
    path("assets/<int:asset_id>/cpe-searches/<int:run_id>/", CpeSearchDetailView.as_view(), name="cpe-search-detail"),
]
