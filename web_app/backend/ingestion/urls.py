from django.urls import path

from .views import PcapListView


urlpatterns = [
    path(
        "pcaps/",
        PcapListView.as_view(),
        name="pcap-list",
    ),
]