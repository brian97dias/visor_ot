"""Authenticated, read-only progress/results and explicit CVE search enqueue.

Never invokes NVD or executes a search from a web request. Candidate findings
are NOT analyst applicability decisions. The finding-list endpoint returns the
latest materialized projection per hardware/CVE, not a historical snapshot of
every past run. Historical NVD IDs remain in each run's durable query checkpoints.
"""
from django.shortcuts import get_object_or_404
from rest_framework import serializers, status
from rest_framework.exceptions import ValidationError
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from vulnerabilities.models import AssetCveFinding, CveDiscoveryRun
from .services.cve_discovery import build_cve_discovery_plan, MAX_CVE_DISCOVERY_HARDWARE
from .services.cve_discovery_worker import enqueue_cve_discovery
from .views import CpeSearchPermission


class CveDiscoveryStartSerializer(serializers.Serializer):
    hardware_ids = serializers.ListField(
        child=serializers.IntegerField(min_value=1),
        allow_empty=False, max_length=MAX_CVE_DISCOVERY_HARDWARE,
    )

    def validate_hardware_ids(self, identifiers):
        return list(dict.fromkeys(identifiers))


class CveDiscoveryRunListSerializer(serializers.Serializer):
    limit = serializers.IntegerField(min_value=1, max_value=50, default=20)


class CveFindingQuerySerializer(serializers.Serializer):
    page = serializers.IntegerField(min_value=1, default=1)
    page_size = serializers.IntegerField(min_value=1, max_value=100, default=20)
    hardware_id = serializers.IntegerField(min_value=1, required=False)


def serialize_cve_discovery_run(run, *, detail=False):
    queries = run.queries
    completed = sum(q.get("status") == "COMPLETED" for q in queries)
    hardware_ids = sorted({
        source["hardware_id"]
        for query in queries for source in query.get("sources", [])
    })
    result = {
        "run_id": run.pk,
        "status": run.status,
        "selected_hardware_ids": run.selected_hardware_ids,
        "eligible_hardware_ids": hardware_ids,
        "requested_by_id": run.requested_by_id,
        "created_at": run.created_at,
        "started_at": run.started_at,
        "checkpoint_at": run.checkpoint_at,
        "finished_at": run.finished_at,
        "error_code": run.error_code,
        "error_message": run.error_message,
        "query_count": len(queries),
        "completed_queries": completed,
        "retrieved_occurrences": sum(q.get("retrieved_count", 0) for q in queries),
        "pages_fetched": sum(q.get("pages_fetched", 0) for q in queries),
        # A completed empty query is NOT an asset-level NOT_APPLICABLE verdict.
        "result_kind": "CANDIDATE_DISCOVERY",
    }
    if detail:
        result["queries"] = [
            {
                "cpe_name": q.get("cpe_name"),
                "status": q.get("status"),
                "next_start_index": q.get("next_start_index"),
                "expected_total": q.get("expected_total"),
                "retrieved_count": q.get("retrieved_count", 0),
                "pages_fetched": q.get("pages_fetched", 0),
                "error_message": q.get("error_message", ""),
                "hardware_ids": sorted({
                    source["hardware_id"] for source in q.get("sources", [])
                }),
            }
            for q in queries
        ]
    return result


class CveDiscoveryListCreateView(APIView):
    permission_classes = [IsAuthenticated, CpeSearchPermission]

    def get(self, request):
        params = CveDiscoveryRunListSerializer(data=request.query_params)
        params.is_valid(raise_exception=True)
        limit = params.validated_data["limit"]
        runs = CveDiscoveryRun.objects.order_by("-created_at", "-pk")[:limit]
        return Response({
            "runs": [serialize_cve_discovery_run(run) for run in runs],
        })

    def post(self, request):
        # DRF serializers otherwise silently ignore unexpected writable fields.
        if not isinstance(request.data, dict) or set(request.data) != {"hardware_ids"}:
            raise ValidationError({
                "hardware_ids": "Solo se admite una lista hardware_ids."
            })
        serializer = CveDiscoveryStartSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            run, reused = enqueue_cve_discovery(
                serializer.validated_data["hardware_ids"], request.user
            )
        except ValueError as error:
            raise ValidationError({"hardware_ids": str(error)}) from error
        return Response({
            "run_id": run.pk,
            "status": run.status,
            "reused": reused,
            "run": serialize_cve_discovery_run(run),
        }, status=status.HTTP_202_ACCEPTED)


class CveDiscoveryDetailView(APIView):
    permission_classes = [IsAuthenticated, CpeSearchPermission]

    def get(self, request, run_id):
        run = get_object_or_404(CveDiscoveryRun, pk=run_id)
        return Response({"run": serialize_cve_discovery_run(run, detail=True)})


class CveDiscoveryFindingListView(APIView):
    permission_classes = [IsAuthenticated, CpeSearchPermission]

    def get(self, request, run_id):
        run = get_object_or_404(CveDiscoveryRun, pk=run_id)
        params = CveFindingQuerySerializer(data=request.query_params)
        params.is_valid(raise_exception=True)
        values = params.validated_data
        current = AssetCveFinding.objects.filter(
            last_discovery_run=run,
        ).select_related("hardware__asset", "cve")
        if "hardware_id" in values:
            if values["hardware_id"] not in run.selected_hardware_ids:
                raise ValidationError({
                    "hardware_id": "El hardware no pertenece a esta búsqueda."
                })
            current = current.filter(hardware_id=values["hardware_id"])
        total = current.count()
        offset = (values["page"] - 1) * values["page_size"]
        findings = list(current.order_by(
            "cve__cve_id", "hardware_id", "pk"
        )[offset:offset + values["page_size"]])

        # A stored finding may outlive its confirmed CPE or software link.
        # Compare its observed fingerprint to the live inventory before
        # representing it as current evidence. This read has no side effects.
        current_fingerprints = {}
        if findings:
            hardware_ids = sorted({finding.hardware_id for finding in findings})
            plan = build_cve_discovery_plan(hardware_ids)
            current_fingerprints = plan["evidence_fingerprints"]

        results = []
        for finding in findings:
            cve = finding.cve
            live = current_fingerprints.get(str(finding.hardware_id))
            results.append({
                "finding_id": finding.pk,
                "cve_id": cve.cve_id,
                "description": cve.description,
                "severity": cve.severity,
                "base_score": cve.base_score,
                "published": cve.published,
                "last_modified": cve.last_modified,
                "hardware_id": finding.hardware_id,
                "hardware_name": finding.hardware.asset.name,
                "sources": finding.sources,
                "candidate_status": "CANDIDATE",
                "evidence_status": (
                    "CURRENT" if live and live == finding.evidence_fingerprint
                    else "STALE"
                ),
                "first_discovery_run_id": finding.first_discovery_run_id,
                "last_discovery_run_id": finding.last_discovery_run_id,
                "first_discovered_at": finding.first_discovered_at,
                "last_discovered_at": finding.last_discovered_at,
            })
        return Response({
            "run_id": run.pk,
            "run_status": run.status,
            # Materialized candidate rows are keyed by hardware and CVE:
            # later runs can supersede their last_discovery_run association.
            "scope": "LATEST_MATERIALIZED_FINDINGS_FOR_RUN",
            "count": total,
            "page": values["page"],
            "page_size": values["page_size"],
            "results": results,
        })
