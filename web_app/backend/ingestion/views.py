from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from django.db import transaction
from rest_framework.status import (
    HTTP_200_OK,
    HTTP_201_CREATED,
    HTTP_400_BAD_REQUEST,
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
    calculate_analysis_hash,
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


    def get(
        self,
        request,
    ):

        try:

            data = get_pcaps()


            ingestion_rows = (
                Ingestion.objects
                .filter(
                    pcap_id__in=[
                        pcap["id"]
                        for pcap
                        in data.get(
                            "pcaps",
                            [],
                        )
                    ]
                )
                .values(
                    "id",
                    "pcap_id",
                    "analysis_hash",
                    "status",
                )
            )


            ingestions_by_pcap = {}


            for ingestion in ingestion_rows:

                ingestions_by_pcap.setdefault(
                    ingestion["pcap_id"],
                    [],
                ).append(
                    ingestion
                )


            for pcap in data.get(
                "pcaps",
                [],
            ):

                pcap[
                    "import_status"
                ] = "NOT_IMPORTED"

                pcap[
                    "ingestion_id"
                ] = None


                histories = (
                    ingestions_by_pcap.get(
                        pcap["id"],
                        [],
                    )
                )


                if not histories:
                    continue


                
                # Solo necesitamos consultar
                # el análisis actual cuando
                # este PCAP tiene historial
                # de importaciones.
                
                if (
                    pcap["status"]
                    != "ANALYZED"
                ):

                    active = next(
                        (
                            item
                            for item
                            in histories
                            if item["status"]
                            == Ingestion.Status.ACTIVE
                        ),
                        None,
                    )


                    if active:

                        pcap[
                            "import_status"
                        ] = "IMPORTED"

                        pcap[
                            "ingestion_id"
                        ] = active["id"]


                    continue


                analysis = (
                    get_pcap_analysis(
                        pcap["id"]
                    )
                )


                current_hash = (
                    calculate_analysis_hash(
                        analysis
                    )
                )


                same_analysis = next(
                    (
                        item
                        for item
                        in histories
                        if (
                            item[
                                "analysis_hash"
                            ]
                            == current_hash
                        )
                    ),
                    None,
                )


                active = next(
                    (
                        item
                        for item
                        in histories
                        if item["status"]
                        == Ingestion.Status.ACTIVE
                    ),
                    None,
                )


                if same_analysis:

                    pcap[
                        "ingestion_id"
                    ] = same_analysis[
                        "id"
                    ]


                    if (
                        same_analysis[
                            "status"
                        ]
                        == Ingestion.Status.ACTIVE
                    ):

                        pcap[
                            "import_status"
                        ] = "IMPORTED"

                    else:

                        pcap[
                            "import_status"
                        ] = "EXCLUDED"


                elif active:

                    pcap[
                        "import_status"
                    ] = "UPDATE_AVAILABLE"

                    pcap[
                        "ingestion_id"
                    ] = active[
                        "id"
                    ]


        except PassiveAnalyzerUnavailable as error:

            return Response(
                {
                    "detail": str(error),
                },
                status=HTTP_503_SERVICE_UNAVAILABLE,
            )


        return Response(
            data
        )

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

            ingestion, import_result = (
                import_analysis(
                    pcap_id=pcap_id,
                    user=request.user,
                )
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


        response_data = dict(
            serializer.data
        )


        response_data[
            "import_result"
        ] = import_result


        status_code = (
            HTTP_201_CREATED
            if import_result == "CREATED"
            else HTTP_200_OK
        )


        return Response(
            response_data,
            status=status_code,
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

class IngestionActivateView(APIView):

    permission_classes = [
        IsAuthenticated,
    ]


    def post(
        self,
        request,
        ingestion_id,
    ):

        with transaction.atomic():

            ingestion = get_object_or_404(
                Ingestion.objects.select_for_update(),
                id=ingestion_id,
            )


            Ingestion.objects.filter(
                pcap_id=ingestion.pcap_id,
                status=Ingestion.Status.ACTIVE,
            ).exclude(
                pk=ingestion.pk
            ).update(
                status=Ingestion.Status.EXCLUDED
            )


            ingestion.status = (
                Ingestion.Status.ACTIVE
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