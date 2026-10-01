from django.urls import path

from .views import (
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
]