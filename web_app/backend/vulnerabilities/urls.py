"""CPE search endpoints, scoped to the existing inventory Asset identifiers."""
from django.urls import path

from .views import CpeSearchStartView, CpeSearchLatestView, CpeSearchDetailView, CpeOverviewView

app_name = "vulnerabilities"
urlpatterns = [
    path("cpe-overview/", CpeOverviewView.as_view(), name="cpe-overview"),
    path("assets/<int:asset_id>/cpe-searches/", CpeSearchStartView.as_view(), name="cpe-search-start"),
    path("assets/<int:asset_id>/cpe-searches/latest/", CpeSearchLatestView.as_view(), name="cpe-search-latest"),
    path("assets/<int:asset_id>/cpe-searches/<int:run_id>/", CpeSearchDetailView.as_view(), name="cpe-search-detail"),
]
