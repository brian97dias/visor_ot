from django.urls import path

from .views import (
    CommunicationClassificationView,
    CommunicationDetailView,
    CommunicationListView,
)


urlpatterns = [

    path(
        "communications/",
        CommunicationListView.as_view(),
        name="communication-list",
    ),

    path(
        "communications/<int:communication_id>/",
        CommunicationDetailView.as_view(),
        name="communication-detail",
    ),

    path(
        "communications/<int:communication_id>/classification/",
        CommunicationClassificationView.as_view(),
        name="communication-classification",
    ),
]