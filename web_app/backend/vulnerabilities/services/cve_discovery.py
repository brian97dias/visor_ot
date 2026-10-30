"""Read-only CPE eligibility and deduplicated CVE discovery query planning.

A CVE search uses ONLY confirmed and current hardware CPEs. Installed software,
its CPEs and versions remain evidence for subsequent per-hardware applicability,
not independent CVE discovery queries. Discovery does not imply applicability.

No network I/O, job creation, inventory mutation or CVE assessment takes
place here. The future enqueue/worker must re-check current evidence before
using a persisted plan: a stored fingerprint is a snapshot, not authorization.
"""
import hashlib
import json
from collections import defaultdict

from assets.models import Asset, Hardware
from vulnerabilities.models import AssetCpe
from .identity import fingerprint, hardware_identity

MAX_CVE_DISCOVERY_HARDWARE = 100


def _digest(value):
    return hashlib.sha256(json.dumps(
        value, sort_keys=True, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")).hexdigest()


def _valid_part(cpe_name, origin):
    """Conservative official CPE 2.3 part check; never generate CPEs from names."""
    if not isinstance(cpe_name, str):
        return False
    parts = cpe_name.split(":")
    if len(parts) != 13 or parts[:2] != ["cpe", "2.3"]:
        return False
    expected = ("h",) if origin == "HARDWARE" else ("a", "o")
    return (parts[2] in expected and all(parts[i] and parts[i] != "*"
            for i in (3, 4)))


def _current_associations(associations, identity, origin):
    """Filter already-confirmed associations against *current* asset identity."""
    return [
        assoc for assoc in associations
        if assoc.validated_identity_fingerprint == identity
        and not assoc.cpe.deprecated
        and _valid_part(assoc.cpe.cpe_name, origin)
    ]


def _source(hardware_id, assoc, origin, identity, installation=None):
    source = {
        "origin": origin,
        "hardware_id": hardware_id,
        "asset_id": assoc.asset_id,
        "asset_cpe_id": assoc.pk,
        "cpe_name_id": str(assoc.cpe.cpe_name_id),
        "cpe_name": assoc.cpe.cpe_name,
        "identity_fingerprint": identity,
        "validated_at": assoc.validated_at.isoformat(),
    }
    if installation is not None:
        source["installation_id"] = installation.pk
    return source


def has_hardware_discovery_source(sources):
    """Current discovery candidates require explicit hardware h:CPE provenance.

    Historical SOFTWARE-only findings remain in storage for audit.
    """
    return isinstance(sources, list) and any(
        isinstance(source, dict)
        and source.get("origin") == "HARDWARE"
        and _valid_part(source.get("cpe_name"), "HARDWARE")
        for source in sources
    )


def hardware_discovery_pairs(cve_ids):
    """Read-only (Cve PK, Hardware PK) with hardware-query provenance."""
    from vulnerabilities.models import AssetCveFinding

    return {
        (cve_pk, hardware_pk)
        for cve_pk, hardware_pk, sources in AssetCveFinding.objects.filter(
            cve_id__in=cve_ids
        ).values_list("cve_id", "hardware_id", "sources")
        if has_hardware_discovery_source(sources)
    }


def build_cve_discovery_plan(hardware_ids):
    """Return a deterministic, read-only plan for up to 100 selected hardware.

    Contract:
    - selected_hardware_ids: input order, deduplicated.
    - eligible_hardware_ids: active hardware with >=1 current confirmed h:CPE.
    - skipped: explicit reason for missing, archived or not-yet-eligible assets.
    - queries: one entry per distinct official hardware CPE across the selection;
      each carries hardware-only provenance and existing checkpoints.
    - evidence_fingerprints: SHA256 per eligible hardware over current hardware
      CPE sources. Installed software changes do not invalidate a discovery
      query (they are handled separately by the applicability evaluator).
    """
    if not isinstance(hardware_ids, (list, tuple)):
        raise ValueError("Selecciona una lista de identificadores de hardware.")
    if not hardware_ids:
        raise ValueError("Selecciona al menos un hardware.")
    if any(type(pk) is not int or pk < 1 for pk in hardware_ids):
        raise ValueError("Los identificadores deben ser enteros positivos.")
    ids = list(dict.fromkeys(hardware_ids))
    if len(ids) > MAX_CVE_DISCOVERY_HARDWARE:
        raise ValueError("Selecciona como máximo 100 hardware por búsqueda.")

    hardware = Hardware.objects.select_related("asset").in_bulk(ids)
    # Differentiate an unknown ID from an existing Software/other asset ID.
    known_asset_ids = set(Asset.objects.filter(
        pk__in=ids
    ).values_list("pk", flat=True))
    active = {
        pk: hw for pk, hw in hardware.items()
        if hw.asset.inventory_status == Asset.InventoryStatus.ACTIVE
    }
    # Only hardware associations can authorize a CVE discovery query.
    # SoftwareInstallation / confirmed software CPEs are read later by the
    # CVE applicability evaluator, never by the discovery planner.
    associations = AssetCpe.objects.filter(
        asset_id__in=active,
        validation_status=AssetCpe.Validation.CONFIRMED,
        cpe__deprecated=False,
    ).select_related("cpe").order_by("asset_id", "pk")
    associations_by_asset = defaultdict(list)
    for association in associations:
        associations_by_asset[association.asset_id].append(association)

    plan = {
        "selected_hardware_ids": ids,
        "eligible_hardware_ids": [],
        "skipped": [],
        "queries": [],
        "evidence_fingerprints": {},
    }
    queries_by_name = {}

    for hardware_id in ids:
        hw = hardware.get(hardware_id)
        if hw is None:
            plan["skipped"].append({
                "hardware_id": hardware_id,
                "reason": "NOT_HARDWARE" if hardware_id in known_asset_ids
                          else "NOT_FOUND",
            })
            continue
        if hw.asset.inventory_status != Asset.InventoryStatus.ACTIVE:
            plan["skipped"].append({
                "hardware_id": hardware_id, "reason": "ARCHIVED",
            })
            continue
        hw_identity = fingerprint(hardware_identity(hw.asset))
        hw_cpes = _current_associations(
            associations_by_asset[hardware_id], hw_identity, "HARDWARE"
        )
        if not hw_cpes:
            plan["skipped"].append({
                "hardware_id": hardware_id,
                "reason": "NO_CURRENT_CONFIRMED_HARDWARE_CPE",
            })
            continue

        sources = [
            _source(hardware_id, assoc, "HARDWARE", hw_identity)
            for assoc in hw_cpes
        ]
        # Discovery is driven by confirmed hardware identity only.
        # Software changes are handled by the applicability evaluator.
        sources.sort(key=lambda row: (
            row["origin"], row["asset_id"], row.get("installation_id", 0),
            row["asset_cpe_id"]
        ))
        plan["eligible_hardware_ids"].append(hardware_id)
        plan["evidence_fingerprints"][str(hardware_id)] = _digest({
            "hardware_identity": hw_identity,
            "confirmed_hardware_cpe_sources": sources,
        })

        for source in sources:
            cpe_name = source["cpe_name"]
            if cpe_name not in queries_by_name:
                queries_by_name[cpe_name] = {
                    "cpe_name": cpe_name,
                    "sources": [],
                    "status": "QUEUED",
                    "next_start_index": 0,
                    "expected_total": None,
                    "retrieved_count": 0,
                    "pages_fetched": 0,
                    "error_message": "",
                }
            queries_by_name[cpe_name]["sources"].append(source)

    # Stable serialization for deduplication/checkpoint persistence.
    for name in sorted(queries_by_name):
        entry = queries_by_name[name]
        entry["sources"].sort(key=lambda row: (
            row["hardware_id"], row["origin"], row["asset_id"],
            row.get("installation_id", 0), row["asset_cpe_id"]
        ))
        plan["queries"].append(entry)
    return plan
