from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.status import (
    HTTP_404_NOT_FOUND,
    HTTP_503_SERVICE_UNAVAILABLE,
)
from rest_framework.views import APIView

from .services.analyzer_client import (
    PassiveAnalyzerPcapNotFound,
    PassiveAnalyzerUnavailable,
    analyze_pcap,
    get_pcaps,
)

from .services.analyzer_client import (
    PassiveAnalyzerUnavailable,
    get_pcaps,
)

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