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
from django.core.paginator import Paginator

from django.shortcuts import get_object_or_404
from django.utils import timezone

from rest_framework.permissions import (
    IsAuthenticated,
)
from rest_framework.response import Response
from rest_framework.exceptions import ValidationError
from rest_framework.views import APIView

from ingestion.models import Ingestion
from users.permissions import IsAdminOrAnalyst

from .models import Communication
from .endpoint_resolution import resolve_communication_endpoints

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
    permission_classes = [IsAuthenticated]

    def get(self, request):
        filters = request.query_params

        include_inactive = filters.get("include_inactive", "false").lower() == "true"
        status_filter = filters.get("status", "ALL")
        search = filters.get("search", "").strip()[:100]

        if status_filter != "ALL" and status_filter not in Communication.Status.values:
            raise ValidationError({"status": "Clasificación no válida."})

        try:
            page_number = int(filters.get("page", "1"))
            min_packets = int(
                filters.get("min_packets", "0" if include_inactive else "1")
            )
        except (ValueError, TypeError) as error:
            raise ValidationError({
                "detail": "page y min_packets deben ser números enteros."
            }) from error

        if page_number < 1 or min_packets < 0:
            raise ValidationError({
                "detail": "page debe ser positivo y min_packets no puede ser negativo."
            })

        queryset = get_communications_queryset()

        if not include_inactive:
            queryset = queryset.filter(active_evidence_count__gt=0)

        if status_filter != "ALL":
            queryset = queryset.filter(status=status_filter)

        if search:
            criteria = (
                Q(source_ip__icontains=search)
                | Q(destination_ip__icontains=search)
                | Q(transport_protocol__icontains=search)
                | Q(service__icontains=search)
            )
            if search.isdecimal():
                criteria |= Q(service_port=int(search))
            queryset = queryset.filter(criteria)

        if min_packets:
            queryset = queryset.filter(packets_observed__gte=min_packets)

        paginator = Paginator(queryset.order_by("id"), 25)
        page = paginator.get_page(page_number)
        page_items = list(page.object_list)
        endpoint_resolutions = resolve_communication_endpoints(page_items)

        return Response({
            "count": paginator.count,
            "page": page.number,
            "page_size": 25,
            "results": CommunicationListSerializer(
                page_items, many=True,
                context={"endpoint_resolutions": endpoint_resolutions},
            ).data,
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
                communication,
                context={
                    "endpoint_resolutions": resolve_communication_endpoints(
                        [communication]
                    )
                },
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
                communication,
                context={
                    "endpoint_resolutions": resolve_communication_endpoints(
                        [communication]
                    )
                },
            ).data
        )