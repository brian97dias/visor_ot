from django.core.paginator import Paginator
from django.db.models import CharField, Q
from django.db.models.functions import Cast
from django.shortcuts import get_object_or_404

from rest_framework.exceptions import ValidationError
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import CommunicationObservation, Ingestion, InterfaceObservation
from .serializers import (
    CommunicationObservationSerializer,
    InterfaceObservationSerializer,
)
from .services.analyzer_client import (
    PassiveAnalyzerAnalysisNotFound,
    PassiveAnalyzerUnavailable,
    get_pcap_analysis_observations,
)
from rest_framework import status


PAGE_SIZE = 25


def read_filters(request):
    kind = request.query_params.get("type", "interfaces")
    if kind not in ("interfaces", "communications"):
        raise ValidationError({"type": "Valores permitidos: interfaces, communications."})
    try:
        page = int(request.query_params.get("page", "1"))
        min_packets = int(request.query_params.get("min_packets", "1"))
    except (ValueError, TypeError) as error:
        raise ValidationError({"detail": "page y min_packets deben ser enteros."}) from error

    if page < 1 or min_packets < 1:
        raise ValidationError({"detail": "page y min_packets deben ser positivos."})
    return kind, page, request.query_params.get("search", "").strip()[:100], min_packets


class IngestionObservationsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, ingestion_id):
        ingestion = get_object_or_404(Ingestion, pk=ingestion_id)
        kind, page, search, min_packets = read_filters(request)

        if kind == "interfaces":
            queryset = InterfaceObservation.objects.filter(ingestion=ingestion)
            if search:
                queryset = queryset.annotate(
                    ips_search=Cast("ips", output_field=CharField())
                ).filter(Q(mac__icontains=search) | Q(ips_search__icontains=search))
            serializer_class = InterfaceObservationSerializer
        else:
            queryset = CommunicationObservation.objects.filter(ingestion=ingestion)
            if search:
                queryset = queryset.annotate(
                    src_search=Cast("client_ip", output_field=CharField()),
                    dst_search=Cast("server_ip", output_field=CharField()),
                ).filter(
                    Q(src_search__icontains=search)
                    | Q(dst_search__icontains=search)
                    | Q(service__icontains=search)
                    | Q(transport_protocol__icontains=search)
                    | (Q(service_port=int(search)) if search.isdecimal() else Q(pk__isnull=True))
                )
            queryset = queryset.filter(packet_count__gte=min_packets)
            serializer_class = CommunicationObservationSerializer

        paginator = Paginator(queryset.order_by("id"), PAGE_SIZE)
        records = paginator.get_page(page)
        return Response({
            "count": paginator.count,
            "page": records.number,
            "page_size": PAGE_SIZE,
            "results": serializer_class(records.object_list, many=True).data,
        })


class PcapAnalysisObservationsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, pcap_id):
        kind, page, search, min_packets = read_filters(request)
        try:
            data = get_pcap_analysis_observations(
                pcap_id, kind=kind, page=page,
                search=search, min_packets=min_packets,
            )
        except PassiveAnalyzerAnalysisNotFound as error:
            return Response({"detail": str(error)}, status=status.HTTP_404_NOT_FOUND)
        except PassiveAnalyzerUnavailable as error:
            return Response({"detail": str(error)}, status=status.HTTP_503_SERVICE_UNAVAILABLE)
        return Response(data)
