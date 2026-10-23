"""Read-only CPE eligibility and deduplicated CVE discovery query planning.

A CVE search begins with active hardware having a current, explicitly
confirmed *hardware* CPE. Additional query CPEs come only from current
software installations on that hardware and current, confirmed *software*
CPEs. Discovery does not imply vulnerability applicability.

No network I/O, job creation, inventory mutation or CVE assessment takes
place here. The future enqueue/worker must re-check current evidence before
using a persisted plan: a stored fingerprint is a snapshot, not authorization.
"""
import hashlib
import json
from collections import defaultdict

from assets.models import Asset, Hardware, SoftwareInstallation
from vulnerabilities.models import AssetCpe
from .identity import fingerprint, hardware_identity, software_identity

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


def build_cve_discovery_plan(hardware_ids):
    """Return a deterministic, read-only plan for up to 100 selected hardware.

    Contract:
    - selected_hardware_ids: input order, deduplicated.
    - eligible_hardware_ids: active hardware with >=1 current confirmed h:CPE.
    - skipped: explicit reason for missing, archived or not-yet-eligible assets.
    - queries: one entry per DISTINCT official CPE name across the selection;
      each carries all source hardware/software associations plus checkpoints.
    - evidence_fingerprints: SHA256 per eligible hardware over relevant current
      associations and active installation identities. The worker must compare
      this against the live inventory before issuing a request.
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
    active = {
        pk: hw for pk, hw in hardware.items()
        if hw.asset.inventory_status == Asset.InventoryStatus.ACTIVE
    }
    installations = list(SoftwareInstallation.objects.filter(
        hardware_id__in=active,
        unlinked_at__isnull=True,
        software__asset__inventory_status=Asset.InventoryStatus.ACTIVE,
    ).select_related("software", "software__asset").order_by(
        "hardware_id", "pk"
    ))
    installed_by_hardware = defaultdict(list)
    for installation in installations:
        installed_by_hardware[installation.hardware_id].append(installation)

    asset_ids = set(active) | {row.software_id for row in installations}
    associations = AssetCpe.objects.filter(
        asset_id__in=asset_ids,
        validation_status=AssetCpe.Validation.CONFIRMED,
        cpe__deprecated=False,
    ).select_related("cpe").order_by("asset_id", "pk")
    associations_by_asset = defaultdict(list)
    for association in associations:
        associations_by_asset[association.asset_id].append(association)

    software_identities = {}
    for installation in installations:
        asset_id = installation.software_id
        if asset_id not in software_identities:
            try:
                software_identities[asset_id] = fingerprint(
                    software_identity(installation.software.asset)
                )
            except (ValueError, AttributeError):
                # Invalid software identity is never treated as a confirmed CPE.
                software_identities[asset_id] = None

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
                "hardware_id": hardware_id, "reason": "NOT_HARDWARE",
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
        installed_identity_basis = []
        for installation in installed_by_hardware[hardware_id]:
            identity = software_identities[installation.software_id]
            installed_identity_basis.append({
                "installation_id": installation.pk,
                "software_id": installation.software_id,
                "identity_fingerprint": identity,
            })
            if identity is None:
                continue
            sw_cpes = _current_associations(
                associations_by_asset[installation.software_id],
                identity, "SOFTWARE"
            )
            sources.extend(
                _source(hardware_id, assoc, "SOFTWARE", identity, installation)
                for assoc in sw_cpes
            )

        # Include current installation identities even if a software asset has
        # no confirmed CPE; adding/removing it must make a snapshot outdated.
        sources.sort(key=lambda row: (
            row["origin"], row["asset_id"], row.get("installation_id", 0),
            row["asset_cpe_id"]
        ))
        plan["eligible_hardware_ids"].append(hardware_id)
        plan["evidence_fingerprints"][str(hardware_id)] = _digest({
            "hardware_identity": hw_identity,
            "active_software_installations": installed_identity_basis,
            "confirmed_cpe_sources": sources,
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
