from django.urls import path

from .views import (
    IngestionDetailView,
    IngestionExcludeView,
    IngestionListView,
    PcapAnalysisView,
    PcapAnalyzeView,
    PcapImportView,
    PcapListView,
)

urlpatterns = [
    path(
        "pcaps/",
        PcapListView.as_view(),
        name="pcap-list",
    ),

    path(
        "pcaps/<str:pcap_id>/analyze/",
        PcapAnalyzeView.as_view(),
        name="pcap-analyze",
    ),

    path(
        "pcaps/<str:pcap_id>/analysis/",
        PcapAnalysisView.as_view(),
        name="pcap-analysis",
    ),
    path(
    "pcaps/<str:pcap_id>/import/",
    PcapImportView.as_view(),
    name="pcap-import",
    ),

    path(
        "imports/",
        IngestionListView.as_view(),
        name="ingestion-list",
    ),

    path(
        "imports/<int:ingestion_id>/",
        IngestionDetailView.as_view(),
        name="ingestion-detail",
    ),

    path(
        "imports/<int:ingestion_id>/exclude/",
        IngestionExcludeView.as_view(),
        name="ingestion-exclude",
    ),
]