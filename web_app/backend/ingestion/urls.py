from django.urls import path

from .views import (
    PcapAnalysisView,
    PcapAnalyzeView,
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
]