"""Pure device-centred diagnosis projection for the existing hardening JSON v1.

P1/P2/P3 are editorial REVIEW priorities, never new CVSS or risk values.
The legacy contract is retained for reproducible comparison with the old PDF.
No database access and no NVD applicability evaluation happen here.
"""
from collections import defaultdict


SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
CRITICALITIES = ("HIGH", "MEDIUM", "LOW")
SEVERITY_RANK = {name: 4 - index for index, name in enumerate(SEVERITIES)}
PRIORITY_MATRIX = {
    "HIGH":   {"CRITICAL": "P1", "HIGH": "P1", "MEDIUM": "P2", "LOW": "P3"},
    "MEDIUM": {"CRITICAL": "P1", "HIGH": "P2", "MEDIUM": "P2", "LOW": "P3"},
    "LOW":    {"CRITICAL": "P2", "HIGH": "P2", "MEDIUM": "P3", "LOW": "P3"},
}
PRIORITY_SORT = {"P1": 0, "P2": 1, "P3": 2, None: 3}


def extract_nvd_cvss(metrics):
    """Select the same NVD metric family as cve_ingestion._cvss_summary.

    Preserve literal metric values and version. Do not infer exploitation,
    environmental risk or a vector when NVD has not supplied one.
    """
    if not isinstance(metrics, dict):
        return None
    for family, version in (
        ("cvssMetricV40", "4.0"),
        ("cvssMetricV31", "3.1"),
        ("cvssMetricV30", "3.0"),
        ("cvssMetricV2", "2.0"),
    ):
        rows = metrics.get(family)
        if not isinstance(rows, list):
            continue
        choices = [row for row in rows if isinstance(row, dict)]
        choices.sort(key=lambda row: row.get("type") != "Primary")
        for choice in choices:
            raw = choice.get("cvssData")
            if not isinstance(raw, dict):
                continue
            # The existing ingester ignores metric records without a valid
            # score. Mirror that check to ensure CVSS metadata is coherent.
            try:
                score = float(raw.get("baseScore"))
            except (TypeError, ValueError, OverflowError):
                continue
            if not 0 <= score <= 10:
                continue
            keys = (
                "attackVector", "attackComplexity", "privilegesRequired",
                "userInteraction", "scope", "confidentialityImpact",
                "integrityImpact", "availabilityImpact", "accessVector",
                "accessComplexity", "authentication",
            )
            return {
                "version": raw.get("version") or version,
                "vector": raw.get("vectorString"),
                "source": choice.get("source"),
                "base_score": str(raw.get("baseScore")),
                "base_severity": raw.get("baseSeverity") or choice.get("baseSeverity"),
                "metrics": {key: raw[key] for key in keys if key in raw},
            }
    return None


def _score(value):
    try:
        return float(value)
    except (ValueError, TypeError, OverflowError):
        return -1.0


def _observation(code, description, **refs):
    return {"code": code, "description": description, **refs}


def build_hardening_diagnosis(report, communication_by_hardware=None):
    """Build a version-1 additive projection without mutating input objects."""
    hardware = {row["id"]: row for row in report.get("hardware", [])}
    systems = {row["id"]: row for row in report.get("systems", [])}
    software = {row["id"]: row for row in report.get("software", [])}
    applicable = defaultdict(dict)

    for finding in report.get("applicable_vulnerabilities", []):
        hid = finding.get("hardware_id")
        if hid in hardware and finding.get("applicability_status") == "APPLIES":
            applicable[hid].setdefault(finding.get("cve_id"), finding)

    communication_by_hardware = communication_by_hardware or {}
    devices = []
    observations = []
    for hid, findings_by_cve in applicable.items():
        hw = hardware[hid]
        findings = sorted(findings_by_cve.values(), key=lambda row: (
            -SEVERITY_RANK.get(str(row.get("severity") or "").upper(), 0),
            -_score(row.get("cvss_base_score")),
            row.get("cve_id") or "",
        ))
        strongest = findings[0]
        severity = str(strongest.get("severity") or "").upper()
        if severity not in SEVERITY_RANK:
            severity = None
        criticality = str(hw.get("criticality") or "").upper()
        priority = PRIORITY_MATRIX.get(criticality, {}).get(severity)
        max_score = max((_score(f.get("cvss_base_score")) for f in findings), default=-1)
        system_ids = sorted(sid for sid in set(hw.get("system_ids") or []) if sid in systems)
        traffic = communication_by_hardware.get(hid, {})
        installed_software = [
            {
                **installation,
                "confirmed_cpes": software.get(
                    installation.get("software_asset_id"), {}
                ).get("confirmed_cpes", []),
                "software_description": software.get(
                    installation.get("software_asset_id"), {}
                ).get("description"),
            }
            for installation in hw.get("software_installations") or []
        ]
        device = {
            "hardware_id": hid,
            "device_ref": f"HW-{hid}",
            "hardware": hw,
            "installed_software": installed_software,
            "system_ids": system_ids,
            "systems": [systems[sid] for sid in system_ids],
            "priority": priority if system_ids else None,
            "priority_basis": {
                "hardware_criticality": criticality,
                "max_cvss_severity": severity,
                "max_cvss_base_score": str(max_score) if max_score >= 0 else None,
            },
            "applicable_cve_count": len(findings),
            "findings": findings,
            "attributed_communications": traffic.get("communications", []),
            "communications_evidence_status": traffic.get(
                "status", "NOT_COLLECTED"
            ),
            "communications_search_limited": traffic.get("search_limited", False),
        }
        devices.append(device)
        if not system_ids:
            observations.append(_observation(
                "MISSING_OT_SYSTEM",
                "Este hardware tiene CVE aplicables, pero carece de un "
                "sistema OT activo asociado. Sus hallazgos se presentan en "
                "el apéndice y no reciben prioridad P1/P2/P3.",
                hardware_id=hid,
            ))
        elif priority is None:
            observations.append(_observation(
                "PRIORITY_UNCLASSIFIED",
                "No se dispone de criticidad y severidad CVSS suficiente "
                "para asignar una prioridad de revisión.",
                hardware_id=hid,
            ))
        for finding in findings:
            if finding.get("applicability_source") != "ANALYST":
                continue
            reviews = finding.get("justifications") or []
            if any(
                not isinstance(row.get("justification"), str)
                or len(row["justification"].strip()) < 20
                for row in reviews if isinstance(row, dict)
            ):
                observations.append(_observation(
                    "BRIEF_ANALYST_JUSTIFICATION",
                    "La justificación humana vigente es breve; su "
                    "suficiencia técnica requiere revisión, sin modificar "
                    "el veredicto registrado.",
                    hardware_id=hid, cve_id=finding.get("cve_id"),
                ))

    devices.sort(key=lambda item: (
        not bool(item["system_ids"]),  # contextualized diagnoses come first
        PRIORITY_SORT.get(item["priority"], 3),
        -SEVERITY_RANK.get(item["priority_basis"]["max_cvss_severity"], 0),
        -_score(item["priority_basis"]["max_cvss_base_score"]),
        -item["applicable_cve_count"],
        item["hardware_id"],
    ))
    for index, device in enumerate(devices, 1):
        device["display_number"] = index

    contextualized_devices = [device for device in devices if device["system_ids"]]
    unassociated_hardware = [device for device in devices if not device["system_ids"]]
    selected_systems = [
        {**system, "prioritized_hardware_ids": [
            device["hardware_id"] for device in devices
            if system["id"] in device["system_ids"]
        ]}
        for system in report.get("systems", [])
        if any(system["id"] in device["system_ids"] for device in devices)
    ]

    conditional = [
        finding for finding in report.get("conditional_vulnerabilities", [])
        if finding.get("applicability_status") == "APPLIES_CONDITIONAL"
    ]
    for finding in conditional:
        hid = finding.get("hardware_id")
        if hid not in hardware:
            continue
        sw_versions = sorted({
            str(row["version"])
            for row in hardware[hid].get("software_installations") or []
            if row.get("version")
        })
        reviews = finding.get("justifications") or []
        if sw_versions and any(
            "versi" in str(row.get("justification") or "").lower()
            for row in reviews if isinstance(row, dict)
        ):
            observations.append(_observation(
                "CONDITIONAL_VERSION_REVIEW",
                "La evaluación condicionada menciona incertidumbre de "
                "versión mientras el inventario registra versiones. "
                "Comprobar si se refieren al mismo contexto; no es una "
                "contradicción ni modifica el veredicto automáticamente.",
                hardware_id=hid, cve_id=finding.get("cve_id"),
                inventoried_versions=sw_versions,
            ))

    matrix = []
    for criticality in CRITICALITIES:
        cells = []
        for severity in SEVERITIES:
            cells.append({
                "cvss_severity": severity,
                "priority": PRIORITY_MATRIX[criticality][severity],
                "hardware_ids": [
                    device["hardware_id"] for device in contextualized_devices
                    if device["priority_basis"]["hardware_criticality"] == criticality
                    and device["priority_basis"]["max_cvss_severity"] == severity
                ],
            })
        matrix.append({"hardware_criticality": criticality, "cells": cells})

    # Matrix priorities count contextualized hardware only. Unassociated
    # applicable CVEs remain visible in the appendix and overall totals.
    counts = {priority: sum(d["priority"] == priority for d in contextualized_devices)
              for priority in ("P1", "P2", "P3")}
    counts["UNCLASSIFIED"] = sum(d["priority"] is None for d in contextualized_devices)
    return {
        "version": 1,
        "unit": "HARDWARE_WITH_CURRENT_APPLIES",
        "priority_type": "EDITORIAL_REVIEW_ORDER_NOT_RISK",
        "summary": {
            "active_hardware": len(hardware),
            "hardware_with_applicable_cves": len(devices),
            "hardware_with_applicable_cves_with_system": len(contextualized_devices),
            "hardware_with_applicable_cves_without_system": len(unassociated_hardware),
            "applicable_hardware_cve_pairs_with_system": sum(
                d["applicable_cve_count"] for d in contextualized_devices
            ),
            "applicable_hardware_cve_pairs_without_system": sum(
                d["applicable_cve_count"] for d in unassociated_hardware
            ),
            "hardware_without_identified_applies": len(hardware) - len(devices),
            "systems_with_prioritized_hardware": len(selected_systems),
            "applicable_hardware_cve_pairs": sum(
                d["applicable_cve_count"] for d in devices
            ),
            "conditional_hardware_cve_pairs": len(conditional),
            "priority_counts": counts,
        },
        "priority_matrix": matrix,
        "prioritized_hardware": devices,
        "unassociated_hardware": unassociated_hardware,
        "prioritized_systems": selected_systems,
        "conditional_vulnerabilities": conditional,
        "inventory_coverage": {
            "active_hardware": len(hardware),
            "active_software": len(software),
            "registered_systems": len(systems),
            "confirmed_cpes": report.get("summary", {}).get("confirmed_cpes", 0),
        },
        "evidence_observations": observations,
    }
