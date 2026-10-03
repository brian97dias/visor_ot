from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.status import (
    HTTP_404_NOT_FOUND,
    HTTP_503_SERVICE_UNAVAILABLE,
    HTTP_404_NOT_FOUND,
    HTTP_503_SERVICE_UNAVAILABLE,
)
from rest_framework.views import APIView

from .services.analyzer_client import (
    PassiveAnalyzerAnalysisNotFound,
    PassiveAnalyzerPcapNotFound,
    PassiveAnalyzerUnavailable,
    analyze_pcap,
    get_pcap_analysis,
    get_pcaps,
)

from django.shortcuts import get_object_or_404

from .models import Ingestion

from .serializers import (
    IngestionDetailSerializer,
    IngestionListSerializer,
)

from .services.json_importer import (
    ImportValidationError,
    import_analysis,
)


class PcapAnalysisView(APIView):

    permission_classes = [
        IsAuthenticated,
    ]


    def get(
        self,
        request,
        pcap_id,
    ):

        try:

            data = get_pcap_analysis(
                pcap_id
            )


        except PassiveAnalyzerAnalysisNotFound as error:

            return Response(
                {
                    "detail": str(error),
                },
                status=HTTP_404_NOT_FOUND,
            )


        except PassiveAnalyzerUnavailable as error:

            return Response(
                {
                    "detail": str(error),
                },
                status=HTTP_503_SERVICE_UNAVAILABLE,
            )


        return Response(data)

class PcapAnalyzeView(APIView):

    permission_classes = [
        IsAuthenticated,
    ]


    def post(
        self,
        request,
        pcap_id,
    ):

        try:

            data = analyze_pcap(
                pcap_id
            )


        except PassiveAnalyzerPcapNotFound as error:

            return Response(
                {
                    "detail": str(error),
                },
                status=HTTP_404_NOT_FOUND,
            )


        except PassiveAnalyzerUnavailable as error:

            return Response(
                {
                    "detail": str(error),
                },
                status=HTTP_503_SERVICE_UNAVAILABLE,
            )


        return Response(data)


class PcapListView(APIView):

    permission_classes = [
        IsAuthenticated,
    ]


    def get(self, request):

        try:
            data = get_pcaps()

        except PassiveAnalyzerUnavailable as error:

            return Response(
                {
                    "detail": str(error),
                },
                status=HTTP_503_SERVICE_UNAVAILABLE,
            )


        return Response(data)

class PcapImportView(APIView):

    permission_classes = [
        IsAuthenticated,
    ]


    def post(
        self,
        request,
        pcap_id,
    ):

        try:

            ingestion = import_analysis(
                pcap_id=pcap_id,
                user=request.user,
            )


        except ImportValidationError as error:

            return Response(
                {
                    "detail": str(error),
                },
                status=HTTP_400_BAD_REQUEST,
            )


        except PassiveAnalyzerAnalysisNotFound as error:

            return Response(
                {
                    "detail": str(error),
                },
                status=HTTP_404_NOT_FOUND,
            )


        except PassiveAnalyzerUnavailable as error:

            return Response(
                {
                    "detail": str(error),
                },
                status=HTTP_503_SERVICE_UNAVAILABLE,
            )


        serializer = (
            IngestionDetailSerializer(
                ingestion
            )
        )


        return Response(
            serializer.data,
            status=HTTP_201_CREATED,
        )


class IngestionListView(APIView):

    permission_classes = [
        IsAuthenticated,
    ]


    def get(
        self,
        request,
    ):

        ingestions = (
            Ingestion.objects
            .select_related(
                "imported_by"
            )
            .all()
        )


        serializer = (
            IngestionListSerializer(
                ingestions,
                many=True,
            )
        )


        return Response(
            {
                "ingestions":
                    serializer.data
            }
        )


class IngestionDetailView(APIView):

    permission_classes = [
        IsAuthenticated,
    ]


    def get(
        self,
        request,
        ingestion_id,
    ):

        ingestion = get_object_or_404(
            Ingestion.objects
            .select_related(
                "imported_by"
            )
            .prefetch_related(
                "interface_observations",
                "communication_observations",
            ),
            id=ingestion_id,
        )


        serializer = (
            IngestionDetailSerializer(
                ingestion
            )
        )


        return Response(
            serializer.data
        )


class IngestionExcludeView(APIView):

    permission_classes = [
        IsAuthenticated,
    ]


    def post(
        self,
        request,
        ingestion_id,
    ):

        ingestion = get_object_or_404(
            Ingestion,
            id=ingestion_id,
        )


        ingestion.status = (
            Ingestion.Status.EXCLUDED
        )

        ingestion.save(
            update_fields=[
                "status",
            ]
        )


        serializer = (
            IngestionListSerializer(
                ingestion
            )
        )


        return Response(
            serializer.data
        )

    