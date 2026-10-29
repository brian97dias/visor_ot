"""A global catalogue of official CVE records, not a vulnerability verdict.

GET /cves/ lists each verified CVE once with a number of related hardware
candidate findings. GET /cves/<id>/ gives the original NVD metadata and a
paginated hardware list. No NVD access, writes or heuristic applicability.
"""
from django.db.models import Q
from django.shortcuts import get_object_or_404
from rest_framework import serializers
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from vulnerabilities.models import AssetCveAssessment, AssetCveFinding, Cve
from .services.cve_discovery import build_cve_discovery_plan
from .services.cve_catalogue_status import CATALOGUE_STATES, catalogue_statuses
from .services.cve_applicability import resolve_applicability
from .services.cve_technical_status import (
    TECHNICAL_FILTERS, technical_statuses, related_assets_for_cves,
)
from .views import CpeSearchPermission


PAGE_SIZE = 15
MAX_PAGE_SIZE = 100
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")


class CveCatalogueFilterSerializer(serializers.Serializer):
    q = serializers.CharField(required=False, max_length=120, allow_blank=True)
    severity = serializers.ChoiceField(
        choices=("ALL", *SEVERITIES), default="ALL",
    )
    status = serializers.ChoiceField(
        choices=("ALL", *CATALOGUE_STATES), default="ALL",
    )
    technical = serializers.ChoiceField(
        choices=("ALL", *TECHNICAL_FILTERS), default="ALL",
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


def _description_es(cve):
    """NVD Spanish first; do not mislabel unverified translations as official."""
    for row in cve.descriptions or []:
        if (isinstance(row, dict) and str(row.get("lang", "")).lower() == "es"
                and isinstance(row.get("value"), str) and row["value"].strip()):
            return row["value"].strip(), "NVD_ES"
    if (cve.cve_id == "CVE-2021-33540"
            and "Phoenix Contact" in cve.description):
        return (
            "En determinados dispositivos de las familias Phoenix Contact "
            "AXL F BK e IL BK existe un acceso FTP no documentado, protegido "
            "por contraseña, al directorio raíz.",
            "TRADUCCION_ORIENTATIVA",
        )
    return "Descripción en español no disponible en NVD.", "NO_DISPONIBLE"


def _asset_counts(cves):
    """Count distinct hardware IDs in findings OR historical assessments."""
    ids = [item.pk for item in cves]
    counts = {pk: set() for pk in ids}
    for cve_pk, hardware_pk in AssetCveFinding.objects.filter(
        cve_id__in=ids
    ).values_list("cve_id", "hardware_id"):
        counts[cve_pk].add(hardware_pk)
    for cve_pk, hardware_pk in AssetCveAssessment.objects.filter(
        cve_id__in=ids
    ).values_list("cve_id", "hardware_id"):
        counts[cve_pk].add(hardware_pk)
    return {pk: len(values) for pk, values in counts.items()}


def _catalogue_applicability(analyst_status, related_assets):
    """Aggregate per-hardware evidence, not merely the first positive.

    A global catalogue CVE is NOT_APPLICABLE only if every linked hardware
    has independently proved all NVD alternatives excluded. An indeterminate
    hardware remains pending; one positive outranks negatives. Manual
    decisions still follow resolve_applicability's precedence.
    """
    # Audit lifecycle and CVE applicability are distinct. Preserve STALE
    # explicitly instead of disguising outdated conclusions as PENDING_REVIEW.
    if analyst_status == "STALE":
        return {"status": "STALE", "source": "NONE"}
    scoped = [row.get("scoped_applicability") for row in related_assets]
    if scoped and all(isinstance(row, dict) for row in scoped):
        statuses = [row.get("status") for row in scoped]
        if "APPLIES" in statuses:
            conclusion = "APPLIES"
        elif "APPLIES_CONDITIONAL" in statuses:
            conclusion = "APPLIES_CONDITIONAL"
        elif all(value == "NOT_APPLICABLE" for value in statuses):
            conclusion = "NOT_APPLICABLE"
        else:
            conclusion = "PENDING_REVIEW"
        origin = (
            "ANALYST" if any(row.get("status") == conclusion
                             and row.get("source") == "ANALYST" for row in scoped)
            else "SYSTEM" if conclusion not in ("PENDING_REVIEW", "IN_REVIEW")
                 else "NONE"
        )
        # A current HUMAN review with no proven positive is not an untouched
        # candidate. Preserve its audit lifecycle in the catalogue and filters.
        if analyst_status == "IN_REVIEW" and conclusion == "PENDING_REVIEW":
            return {"status": "IN_REVIEW", "source": "NONE"}
        if (analyst_status in ("APPLIES", "APPLIES_CONDITIONAL",
                               "NOT_APPLICABLE") and conclusion == "PENDING_REVIEW"):
            # Legacy CVE assessment rows are fingerprinted by the older
            # scenario; their contextual software projection can be empty.
            return {"status": analyst_status, "source": "ANALYST"}
        return {"status": conclusion, "source": origin}
    positive = next((row.get("automatic_evidence") for row in related_assets
                     if row.get("automatic_evidence")), None)
    negatives = (
        [row for row in related_assets
         if row.get("technical_result") == "EXCLUDED"
         and row.get("automatic_negative_evidence") is not None]
        if related_assets else []
    )
    all_excluded = len(negatives) == len(related_assets) and bool(related_assets)
    technical = (
        "COMPATIBLE" if positive else
        "EXCLUDED" if all_excluded else "INDETERMINATE"
    )
    negative_proof = (
        {"hardware": [{
            "hardware_id": row["hardware_id"],
            "evidence": row["automatic_negative_evidence"],
        } for row in negatives]}
        if all_excluded else None
    )
    return resolve_applicability(
        technical, analyst_status, automatic_evidence=positive,
        automatic_negative=negative_proof,
    )


def _summary_bucket(status):
    """Three user-facing CVE applicability groups, retaining legacy audit states."""
    return status if status in (
        "APPLIES", "APPLIES_CONDITIONAL", "NOT_APPLICABLE"
    ) else "PENDING_REVIEW"


def _catalogue_summary():
    """Global counts, independent of the list's search, filters and pagination.

    Reuse the same conservative effective-applicability logic as the table;
    counting raw human audit records would double-count system assessments.
    """
    cves = list(Cve.objects.filter(fetch_status=Cve.FetchStatus.COMPLETED))
    summary = {"total": len(cves), "applies": 0, "applies_conditional": 0,
               "not_applicable": 0, "pending_review": 0, "validated": 0}
    if not cves:
        return summary
    analyst = catalogue_statuses(cves)
    related = related_assets_for_cves(cves)
    for cve in cves:
        effective = _catalogue_applicability(analyst[cve.pk], related[cve.pk])
        bucket = _summary_bucket(effective["status"])
        if bucket == "APPLIES":
            summary["applies"] += 1
        elif bucket == "APPLIES_CONDITIONAL":
            summary["applies_conditional"] += 1
        elif bucket == "NOT_APPLICABLE":
            summary["not_applicable"] += 1
        else:
            summary["pending_review"] += 1
    summary["validated"] = (summary["applies"] + summary["applies_conditional"]
                            + summary["not_applicable"])
    return summary


def _cve_brief(cve, hardware_count=0, evaluation_status="PENDING_REVIEW",
               technical_result="INDETERMINATE", related_assets=None,
               applicability=None):
    description, source = _description_es(cve)
    return {
        "cve_id": cve.cve_id,
        "description": description,
        "description_source": source,
        "severity": cve.severity or "UNKNOWN",
        "base_score": cve.base_score,
        "published": cve.published,
        "last_modified": cve.last_modified,
        "retrieved_at": cve.retrieved_at,
        "hardware_count": hardware_count,
        "selected_assets_count": hardware_count,
        "related_assets": related_assets if related_assets is not None else [],
        "evaluation_status": evaluation_status,
        "applicability_status": (applicability or {}).get(
            "status", "PENDING_REVIEW"
        ),
        "applicability_source": (applicability or {}).get("source", "NONE"),
        # Contract for future hardening reporting: no false confirmed counts.
        "hardening_category": (
            "CONFIRMED" if (applicability or {}).get("status") == "APPLIES"
            else "CONDITIONAL" if (applicability or {}).get("status") == "APPLIES_CONDITIONAL"
            else "NONE"
        ),
        "technical_result": technical_result,
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
        )
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
        ordered = query.order_by("-published", "cve_id")
        page = values["page"]
        page_size = values["page_size"]
        offset = (page - 1) * page_size
        selected_status = values["status"]
        selected_technical = values["technical"]
        if selected_status == "ALL" and selected_technical == "ALL":
            count = ordered.count()
            results = list(ordered[offset:offset + page_size])
            statuses = catalogue_statuses(results)
            technicals = technical_statuses(results)
            assets = related_assets_for_cves(results)
            applicability = {
                cve.pk: _catalogue_applicability(statuses[cve.pk], assets[cve.pk])
                for cve in results
            }
        else:
            # Effective applicability is derived BEFORE pagination. A missing
            # installed application never proves a negative CVE result.
            candidates = list(ordered)
            statuses = catalogue_statuses(candidates)
            technicals = technical_statuses(candidates)
            assets = related_assets_for_cves(candidates)
            applicability = {
                cve.pk: _catalogue_applicability(statuses[cve.pk], assets[cve.pk])
                for cve in candidates
            }
            filtered = [
                cve for cve in candidates
                if (selected_status == "ALL" or
                    (selected_status == "PENDING_REVIEW" and
                     _summary_bucket(applicability[cve.pk]["status"]) == "PENDING_REVIEW") or
                    applicability[cve.pk]["status"] == selected_status)
                and (selected_technical == "ALL" or
                     technicals[cve.pk] == selected_technical or
                     (selected_technical == "ATTENTION" and
                      applicability[cve.pk]["status"] != "NOT_APPLICABLE"))
            ]
            count = len(filtered)
            results = filtered[offset:offset + page_size]
        counts = _asset_counts(results)
        return Response({
            "count": count, "page": page, "page_size": page_size,
            "summary": _catalogue_summary(),
            "results": [_cve_brief(
                cve, counts[cve.pk], statuses[cve.pk], technicals[cve.pk],
                assets[cve.pk], applicability[cve.pk],
            ) for cve in results],
        })


class CveCatalogueDetailView(APIView):
    permission_classes = [IsAuthenticated, CpeSearchPermission]

    def get(self, request, cve_id):
        cve = get_object_or_404(
            Cve.objects.filter(fetch_status=Cve.FetchStatus.COMPLETED),
            cve_id=cve_id,
        )
        # The original NVD configuration is kept intact; this endpoint never
        # infers that a hardware is affected from an OR or a platform match.
        analyst = catalogue_statuses([cve])[cve.pk]
        related = related_assets_for_cves([cve])[cve.pk]
        return Response({"cve": {
            **_cve_brief(
                cve, _asset_counts([cve])[cve.pk], analyst,
                technical_statuses([cve])[cve.pk], related,
                _catalogue_applicability(analyst, related),
            ),
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
        found = {
            finding.hardware_id: finding
            for finding in AssetCveFinding.objects.filter(
                cve__cve_id=cve_id,
            ).select_related("hardware__asset")
        }
        reviewed_ids = set(AssetCveAssessment.objects.filter(
            cve__cve_id=cve_id,
        ).values_list("hardware_id", flat=True))
        hardware_ids = sorted(set(found) | reviewed_ids)
        count = len(hardware_ids)
        offset = (values["page"] - 1) * values["page_size"]
        visible_ids = hardware_ids[offset:offset + values["page_size"]]
        from assets.models import Hardware
        hardware = Hardware.objects.select_related("asset").in_bulk(visible_ids)
        fingerprints = (
            build_cve_discovery_plan(visible_ids)["evidence_fingerprints"]
            if visible_ids else {}
        )
        results = []
        for hardware_id in visible_ids:
            finding = found.get(hardware_id)
            hw = hardware[hardware_id]
            live = fingerprints.get(str(hardware_id))
            results.append({
                "finding_id": finding.pk if finding else None,
                "hardware_id": hardware_id,
                "hardware_name": hw.asset.name,
                "sources": finding.sources if finding else [],
                "candidate_status": (
                    "CANDIDATE" if finding else "PREVIOUSLY_ASSESSED"
                ),
                "has_assessment": hardware_id in reviewed_ids,
                "evidence_status": (
                    "CURRENT" if finding and live and
                    live == finding.evidence_fingerprint else "STALE"
                ),
                "first_discovery_run_id": (
                    finding.first_discovery_run_id if finding else None
                ),
                "last_discovery_run_id": (
                    finding.last_discovery_run_id if finding else None
                ),
                "last_discovered_at": (
                    finding.last_discovered_at if finding else None
                ),
            })
        return Response({
            "cve_id": cve_id, "count": count,
            "page": values["page"],
            "page_size": values["page_size"],
            "results": results,
        })
