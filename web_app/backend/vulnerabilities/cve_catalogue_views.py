"""Official CVE catalogue, projected into independently evaluated hardware rows.

GET /cves/ lists CVE/hardware pairs (without duplicating the official NVD
record). GET /cves/<id>/ still returns the original record and its hardware
list. No NVD access, writes or heuristic applicability.
"""
from django.db.models import Q
from django.shortcuts import get_object_or_404
from rest_framework import serializers
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from assets.models import Asset, Hardware, SoftwareInstallation
from vulnerabilities.models import AssetCveAssessment, AssetCveFinding, Cve
from .services.cve_discovery import (
    build_cve_discovery_plan, hardware_discovery_pairs,
    has_hardware_discovery_source,
)
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
    for cve_pk, hardware_pk in hardware_discovery_pairs(ids):
        counts[cve_pk].add(hardware_pk)
    for cve_pk, hardware_pk in AssetCveAssessment.objects.filter(
        cve_id__in=ids
    ).values_list("cve_id", "hardware_id"):
        counts[cve_pk].add(hardware_pk)
    return {pk: len(values) for pk, values in counts.items()}


def _cve_ids_for_evaluated_asset_name(search):
    """Find CVEs already related to named inventory assets, before pagination.

    Only use hardware-origin candidate findings or an existing hardware CVE
    assessment. Software is searchable when the current catalogue actually
    shows that installation as evaluated evidence; a generic installation
    alone must not claim a CVE association.
    """
    active = Asset.InventoryStatus.ACTIVE
    matched_hardware = set(Hardware.objects.filter(
        asset__name__icontains=search,
        asset__inventory_status=active,
    ).values_list("pk", flat=True))
    matched_software = set(Asset.objects.filter(
        name__icontains=search,
        asset_type=Asset.AssetType.SOFTWARE,
        inventory_status=active,
    ).values_list("pk", flat=True))
    software_hardware = set(SoftwareInstallation.objects.filter(
        software__asset_id__in=matched_software,
        software__asset__inventory_status=active,
        hardware__asset__inventory_status=active,
        unlinked_at__isnull=True,
    ).values_list("hardware_id", flat=True)) if matched_software else set()

    candidate_hardware = matched_hardware | software_hardware
    if not candidate_hardware:
        return set()
    related_pairs = {
        (cve_id, hardware_id)
        for cve_id, hardware_id, sources in AssetCveFinding.objects.filter(
            hardware_id__in=candidate_hardware,
        ).values_list("cve_id", "hardware_id", "sources")
        if has_hardware_discovery_source(sources, hardware_id)
    }
    related_pairs.update(AssetCveAssessment.objects.filter(
        hardware_id__in=candidate_hardware,
    ).values_list("cve_id", "hardware_id"))

    matched_ids = {
        cve_id for cve_id, hardware_id in related_pairs
        if hardware_id in matched_hardware
    }
    if matched_software and software_hardware:
        # Reuse the existing provenance-aware catalogue projection, including
        # current evidence, rather than equating 'installed' with 'vulnerable'.
        candidate_ids = {
            cve_id for cve_id, hardware_id in related_pairs
            if hardware_id in software_hardware
        }
        candidates = list(Cve.objects.filter(
            pk__in=candidate_ids, fetch_status=Cve.FetchStatus.COMPLETED,
        ))
        contexts = related_assets_for_cves(candidates)
        for cve in candidates:
            if any(
                asset.get("asset_type") == "SOFTWARE"
                and asset.get("asset_id") in matched_software
                for context in contexts[cve.pk]
                for asset in context.get("assets", [])
            ):
                matched_ids.add(cve.pk)
    return matched_ids


def _catalogue_applicability(analyst_status, related_assets):
    """Aggregate per-hardware evidence, not merely the first positive.

    A global catalogue CVE is NOT_APPLICABLE only if every linked hardware
    has independently proved all NVD alternatives excluded. An indeterminate
    hardware remains pending; one positive outranks negatives. Manual
    decisions still follow resolve_applicability's precedence.
    """
    # A stale historical decision is audit evidence, NOT current
    # applicability. The catalogue must show "Por validar", just like detail.
    scoped = [row.get("scoped_applicability") for row in related_assets]
    # A current hardware-scoped human conclusion supersedes an older legacy
    # stale review; otherwise the existing STALE filter remains authoritative.
    if analyst_status == "STALE" and not any(
        isinstance(row, dict) and row.get("source") == "ANALYST"
        and row.get("status") in ("APPLIES", "APPLIES_CONDITIONAL",
                                  "NOT_APPLICABLE")
        for row in scoped
    ):
        return {"status": "PENDING_REVIEW", "source": "NONE",
                "revalidation_required": True}
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
            return {"status": "PENDING_REVIEW", "source": "NONE"}
        # Never resurrect a historical analyst verdict when the scoped
        # evaluator cannot substantiate it. The common fingerprint validator
        # must establish its currency first.
        if conclusion in ("STALE", "IN_REVIEW"):
            return {"status": "PENDING_REVIEW", "source": "NONE",
                    "revalidation_required": True}
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


def _catalogue_summaries():
    """Distinct official CVEs and independently scoped hardware-CVE metrics.

    Preserve the original distinct-CVE summary for API consumers, but expose
    pair-level counts separately so the interface never labels an aggregate
    finding as the status of every hardware.
    """
    cves = list(Cve.objects.filter(fetch_status=Cve.FetchStatus.COMPLETED))
    summary = {"total": len(cves), "applies": 0, "applies_conditional": 0,
               "not_applicable": 0, "pending_review": 0, "validated": 0}
    evaluations = {
        "total": 0, "applies": 0, "applies_conditional": 0,
        "not_applicable": 0, "pending_review": 0, "validated": 0,
    }
    if not cves:
        return summary, evaluations
    analyst = catalogue_statuses(cves)
    related = related_assets_for_cves(cves)
    for cve in cves:
        effective = _catalogue_applicability(analyst[cve.pk], related[cve.pk])
        summary[_summary_bucket(effective["status"]).lower()] += 1
        for context in related[cve.pk]:
            scoped = context.get("scoped_applicability") or {}
            bucket = _summary_bucket(scoped.get("status")).lower()
            evaluations[bucket] += 1
            evaluations["total"] += 1
    for group in (summary, evaluations):
        group["validated"] = (group["applies"] + group["applies_conditional"]
                              + group["not_applicable"])
    return summary, evaluations


def _catalogue_summary():
    """Backwards-compatible summary of distinct official NVD CVEs."""
    return _catalogue_summaries()[0]


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
        # A current analyst Hardware-CVE verdict governs BOTH badges in the
        # catalogue. Per-configuration legacy progress must not contradict it.
        "evaluation_status": (
            applicability["status"]
            if (applicability or {}).get("source") == "ANALYST"
            else evaluation_status
        ),
        "applicability_status": (applicability or {}).get(
            "status", "PENDING_REVIEW"
        ),
        "applicability_source": (applicability or {}).get("source", "NONE"),
        "revalidation_required": bool(
            (applicability or {}).get("revalidation_required")
        ),
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
        query = Cve.objects.filter(fetch_status=Cve.FetchStatus.COMPLETED)
        search = values.get("q", "").strip()
        if search:
            related_ids = _cve_ids_for_evaluated_asset_name(search)
            query = query.filter(
                Q(cve_id__icontains=search)
                | Q(description__icontains=search)
                | Q(pk__in=related_ids)
            )
        severity = values["severity"]
        if severity == "UNKNOWN":
            query = query.filter(severity="")
        elif severity != "ALL":
            query = query.filter(severity=severity)

        # Expand BEFORE status filtering and pagination: one displayed result
        # is exactly one CVE/hardware evaluation, not an aggregate verdict.
        cves = list(query.order_by("-published", "cve_id"))
        related = related_assets_for_cves(cves)
        statuses = catalogue_statuses(cves)
        named_hardware = set(Hardware.objects.filter(
            asset__name__icontains=search,
            asset__inventory_status=Asset.InventoryStatus.ACTIVE,
        ).values_list("pk", flat=True)) if search else set()
        selected_status = values["status"]
        selected_technical = values["technical"]
        term = search.casefold()
        rows = []

        for cve in cves:
            contexts = related[cve.pk]
            matches_metadata = (
                not search or term in cve.cve_id.casefold()
                or term in (cve.description or "").casefold()
            )
            # Retain a metadata-only CVE as a single unassociated row. It
            # cannot claim any hardware-specific validation.
            for context in contexts or [None]:
                if not matches_metadata:
                    if context is None:
                        continue
                    if (context["hardware_id"] not in named_hardware
                            and not any(
                                term in (asset.get("name") or "").casefold()
                                for asset in context.get("assets", [])
                            )):
                        continue
                scoped = (context or {}).get("scoped_applicability") or {}
                state = scoped.get("status", "PENDING_REVIEW")
                technical = (context or {}).get(
                    "technical_result", "INDETERMINATE"
                )
                if (selected_status != "ALL"
                        and not (
                            selected_status == "PENDING_REVIEW"
                            and _summary_bucket(state) == "PENDING_REVIEW"
                        ) and state != selected_status):
                    continue
                if (selected_technical != "ALL"
                        and selected_technical != technical
                        and not (
                            selected_technical == "ATTENTION"
                            and state != "NOT_APPLICABLE"
                        )):
                    continue
                rows.append((cve, context, state, technical, len(contexts)))

        count = len(rows)
        page = values["page"]
        page_size = values["page_size"]
        offset = (page - 1) * page_size
        shown = rows[offset:offset + page_size]
        payload = []
        for cve, context, state, technical, context_count in shown:
            scoped = (context or {}).get("scoped_applicability") or {
                "status": "PENDING_REVIEW", "source": "NONE",
            }
            # Legacy evaluation_status is retained for a one-hardware CVE,
            # including STALE/IN_REVIEW badges. Multi-hardware decisions may
            # NEVER inherit a different hardware's analyst status.
            evaluation = (
                statuses[cve.pk] if context_count <= 1 and context is not None
                else state
            )
            item = _cve_brief(
                cve, 1 if context else 0, evaluation, technical,
                [context] if context else [], scoped,
            )
            item["hardware_id"] = context["hardware_id"] if context else None
            item["row_key"] = (
                f"{cve.cve_id}:hardware:{context['hardware_id']}"
                if context else f"{cve.cve_id}:unassociated"
            )
            payload.append(item)

        summary, evaluation_summary = _catalogue_summaries()
        return Response({
            "count": count, "page": page, "page_size": page_size,
            "summary": summary, "evaluation_summary": evaluation_summary,
            "results": payload,
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
            if has_hardware_discovery_source(finding.sources, finding.hardware_id)
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
