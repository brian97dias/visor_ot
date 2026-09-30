from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.status import HTTP_503_SERVICE_UNAVAILABLE
from rest_framework.views import APIView

from .services.analyzer_client import (
    PassiveAnalyzerUnavailable,
    get_pcaps,
)


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