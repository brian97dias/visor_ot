from django.db.models import (
    BigIntegerField,
    Count,
    Max,
    Min,
    Q,
    Sum,
    Value,
)

from django.db.models.functions import Coalesce

from django.shortcuts import get_object_or_404
from django.utils import timezone

from rest_framework.permissions import (
    IsAuthenticated,
)
from rest_framework.response import Response
from rest_framework.views import APIView

from ingestion.models import Ingestion
from users.permissions import IsAdminOrAnalyst

from .models import Communication

from .serializers import (
    CommunicationClassificationSerializer,
    CommunicationDetailSerializer,
    CommunicationListSerializer,
)


def get_communications_queryset():

    active_evidence = Q(
        observations__ingestion__status=(
            Ingestion.Status.ACTIVE
        )
    )


    return (
        Communication.objects
        .annotate(

            active_evidence_count=Count(
                "observations",
                filter=active_evidence,
                distinct=True,
            ),

            packets_observed=Coalesce(
                Sum(
                    "observations__packet_count",
                    filter=active_evidence,
                ),
                Value(0),
                output_field=BigIntegerField(),
            ),

            first_seen=Min(
                "observations__first_seen",
                filter=active_evidence,
            ),

            last_seen=Max(
                "observations__last_seen",
                filter=active_evidence,
            ),
        )
    )


class CommunicationListView(APIView):

    permission_classes = [
        IsAuthenticated,
    ]


    def get(
        self,
        request,
    ):

        queryset = (
            get_communications_queryset()
        )


        include_inactive = (
            request.query_params.get(
                "include_inactive",
                "false",
            ).lower()
            == "true"
        )


        if not include_inactive:

            queryset = queryset.filter(
                active_evidence_count__gt=0
            )


        serializer = (
            CommunicationListSerializer(
                queryset,
                many=True,
            )
        )


        return Response({
            "communications":
                serializer.data
        })


class CommunicationDetailView(APIView):

    permission_classes = [
        IsAuthenticated,
    ]


    def get(
        self,
        request,
        communication_id,
    ):

        communication = get_object_or_404(
            get_communications_queryset()
            .select_related(
                "classified_by"
            ),
            id=communication_id,
        )


        serializer = (
            CommunicationDetailSerializer(
                communication
            )
        )


        return Response(
            serializer.data
        )


class CommunicationClassificationView(
    APIView
):

    permission_classes = [
        IsAdminOrAnalyst,
    ]


    def patch(
        self,
        request,
        communication_id,
    ):

        communication = get_object_or_404(
            Communication,
            id=communication_id,
        )


        serializer = (
            CommunicationClassificationSerializer(
                data=request.data
            )
        )

        serializer.is_valid(
            raise_exception=True
        )


        communication.status = (
            serializer.validated_data[
                "status"
            ]
        )

        communication.classified_by = (
            request.user
        )

        communication.classified_at = (
            timezone.now()
        )


        communication.save(
            update_fields=[
                "status",
                "classified_by",
                "classified_at",
                "updated_at",
            ]
        )


        communication = get_object_or_404(
            get_communications_queryset()
            .select_related(
                "classified_by"
            ),
            id=communication.id,
        )


        return Response(
            CommunicationDetailSerializer(
                communication
            ).data
        )