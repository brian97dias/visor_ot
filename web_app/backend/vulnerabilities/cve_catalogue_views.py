"""A global catalogue of official CVE records, not a vulnerability verdict.

GET /cves/ lists each verified CVE once with a number of related hardware
candidate findings. GET /cves/<id>/ gives the original NVD metadata and a
paginated hardware list. No NVD access, writes or heuristic applicability.
"""
from django.db.models import Count, Q
from django.shortcuts import get_object_or_404
from rest_framework import serializers
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from vulnerabilities.models import AssetCveFinding, Cve
from .services.cve_discovery import build_cve_discovery_plan
from .views import CpeSearchPermission


PAGE_SIZE = 15
MAX_PAGE_SIZE = 100
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")


class CveCatalogueFilterSerializer(serializers.Serializer):
    q = serializers.CharField(required=False, max_length=120, allow_blank=True)
    severity = serializers.ChoiceField(
        choices=("ALL", *SEVERITIES), default="ALL",
    )
    page = serializers.IntegerField(min_value=1, default=1)
    page_size = serializers.IntegerField(
        min_value=1, max_value=MAX_PAGE_SIZE, default=PAGE_SIZE,
    )


class CveCatalogueHardwareFilterSerializer(serializers.Serializer):
    page = serializers.IntegerField(min_value=1, default=1)
    page_size = serializers.IntegerField(
        min_value=1, max_value=MAX_PAGE_SIZE, default=PAGE_SIZE,
    )


def _cve_brief(cve):
    return {
        "cve_id": cve.cve_id,
        "description": cve.description,
        "severity": cve.severity or "UNKNOWN",
        "base_score": cve.base_score,
        "published": cve.published,
        "last_modified": cve.last_modified,
        "retrieved_at": cve.retrieved_at,
        "hardware_count": cve.hardware_count,
        # Correlation from NVD CPE is not an asset applicability decision.
        "relationship_kind": "CANDIDATE",
    }


class CveCatalogueView(APIView):
    permission_classes = [IsAuthenticated, CpeSearchPermission]

    def get(self, request):
        params = CveCatalogueFilterSerializer(data=request.query_params)
        params.is_valid(raise_exception=True)
        values = params.validated_data
        query = Cve.objects.filter(
            fetch_status=Cve.FetchStatus.COMPLETED,
        ).annotate(hardware_count=Count("asset_findings", distinct=True))
        search = values.get("q", "").strip()
        if search:
            query = query.filter(
                Q(cve_id__icontains=search) | Q(description__icontains=search)
            )
        severity = values["severity"]
        if severity == "UNKNOWN":
            query = query.filter(severity="")
        elif severity != "ALL":
            query = query.filter(severity=severity)
        count = query.count()
        page = values["page"]
        page_size = values["page_size"]
        offset = (page - 1) * page_size
        results = query.order_by("-published", "cve_id")[
            offset:offset + page_size
        ]
        return Response({
            "count": count, "page": page, "page_size": page_size,
            "results": [_cve_brief(cve) for cve in results],
        })


class CveCatalogueDetailView(APIView):
    permission_classes = [IsAuthenticated, CpeSearchPermission]

    def get(self, request, cve_id):
        cve = get_object_or_404(
            Cve.objects.filter(fetch_status=Cve.FetchStatus.COMPLETED)
                .annotate(hardware_count=Count("asset_findings", distinct=True)),
            cve_id=cve_id,
        )
        # The original NVD configuration is kept intact; this endpoint never
        # infers that a hardware is affected from an OR or a platform match.
        return Response({"cve": {
            **_cve_brief(cve),
            "descriptions": cve.descriptions,
            "metrics": cve.metrics,
            "configurations": cve.configurations,
            "references": cve.references,
        }})


class CveCatalogueHardwareView(APIView):
    permission_classes = [IsAuthenticated, CpeSearchPermission]

    def get(self, request, cve_id):
        get_object_or_404(
            Cve, cve_id=cve_id, fetch_status=Cve.FetchStatus.COMPLETED,
        )
        params = CveCatalogueHardwareFilterSerializer(data=request.query_params)
        params.is_valid(raise_exception=True)
        values = params.validated_data
        found = AssetCveFinding.objects.filter(
            cve__cve_id=cve_id,
        ).select_related("hardware__asset", "last_discovery_run")
        count = found.count()
        offset = (values["page"] - 1) * values["page_size"]
        rows = list(found.order_by("hardware_id", "pk")[
            offset:offset + values["page_size"]
        ])
        # Only check the current inventory for the visible page. A historical
        # CPE association must never be mistaken for still current evidence.
        fingerprints = (
            build_cve_discovery_plan([r.hardware_id for r in rows])[
                "evidence_fingerprints"
            ] if rows else {}
        )
        return Response({
            "cve_id": cve_id,
            "count": count,
            "page": values["page"],
            "page_size": values["page_size"],
            "results": [{
                "finding_id": r.pk,
                "hardware_id": r.hardware_id,
                "hardware_name": r.hardware.asset.name,
                "sources": r.sources,
                "candidate_status": "CANDIDATE",
                "evidence_status": (
                    "CURRENT" if (
                        fingerprints.get(str(r.hardware_id))
                        == r.evidence_fingerprint
                    ) else "STALE"
                ),
                "first_discovery_run_id": r.first_discovery_run_id,
                "last_discovery_run_id": r.last_discovery_run_id,
                "last_discovered_at": r.last_discovered_at,
            } for r in rows],
        })
