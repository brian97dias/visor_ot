import hashlib
import json
import os
import tempfile

from pathlib import Path

from config import OUTPUT_DIRECTORY

from pcap_identity import (
    get_pcap_id,
    get_relative_path,
)

def build_output(
    pcap_path,
    interfaces,
    communications,
):

    pcap_id = get_pcap_id(
        pcap_path
    )

    relative_path = get_relative_path(
        pcap_path
    )    

    output_interfaces = []

    for mac in sorted(interfaces):

        interface = interfaces[mac]

        output_interfaces.append({
            "mac": interface["mac"],
            "ips": sorted(interface["ips"]),
            "first_seen": interface["first_seen"],
            "last_seen": interface["last_seen"],
        })


    output_communications = []

    for communication in communications.values():

        output_communications.append(
            communication.copy()
        )


    return {
        "schema_version": "0.2",

        "capture": {
            "pcap_id": pcap_id,
            "filename": Path(pcap_path).name,
            "relative_path": relative_path,
        },

        "interfaces": output_interfaces,

        "communications": output_communications,
    }


def save_output(
    pcap_path,
    interfaces,
    communications,
):

    output = build_output(
        pcap_path,
        interfaces,
        communications,
    )


    OUTPUT_DIRECTORY.mkdir(
        parents=True,
        exist_ok=True
    )


    pcap_id = get_pcap_id(
        pcap_path
    )


    output_file = (
        OUTPUT_DIRECTORY
        / f"{pcap_id}.json"
    )


    with output_file.open(
        "w",
        encoding="utf-8",
    ) as file:

        json.dump(
            output,
            file,
            indent=2,
            ensure_ascii=False,
        )


    _save_hash_metadata(
        pcap_id, calculate_analysis_hash(output), output_file
    )

    return output_file

def load_output(pcap_id):

    output_file = (
        OUTPUT_DIRECTORY
        / f"{pcap_id}.json"
    )


    if not output_file.is_file():
        return None


    with output_file.open(
        "r",
        encoding="utf-8",
    ) as file:

        output = json.load(file)


    return output


def calculate_analysis_hash(analysis):
    """Use the exact canonical JSON algorithm used by Django imports."""
    canonical_json = json.dumps(
        analysis,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()


def _save_hash_metadata(pcap_id, analysis_hash, output_file):
    """Cache the digest alongside the analysis; never alter the analysis JSON."""
    stat = output_file.stat()
    metadata = {
        "analysis_hash": analysis_hash,
        "size": stat.st_size,
        "mtime_ns": stat.st_mtime_ns,
    }

    metadata_path = OUTPUT_DIRECTORY / f"{pcap_id}.meta.json"
    temp_path = None

    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=OUTPUT_DIRECTORY,
            prefix=f".{pcap_id}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temp_path = Path(handle.name)
            json.dump(metadata, handle)

        os.replace(temp_path, metadata_path)
    except OSError:
        # Read-only output directories can still serve analysis data.
        # In that case the hash will be recalculated on the next request.
        pass
    finally:
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)


def get_analysis_hash(pcap_id):
    """Return a cached digest; backfill metadata for legacy JSON once."""
    output_file = OUTPUT_DIRECTORY / f"{pcap_id}.json"
    if not output_file.is_file():
        return None

    stat = output_file.stat()
    metadata_file = OUTPUT_DIRECTORY / f"{pcap_id}.meta.json"

    if metadata_file.is_file():
        try:
            with metadata_file.open("r", encoding="utf-8") as file:
                metadata = json.load(file)
            digest = metadata.get("analysis_hash")
            if (
                isinstance(digest, str)
                and len(digest) == 64
                and metadata.get("size") == stat.st_size
                and metadata.get("mtime_ns") == stat.st_mtime_ns
            ):
                return digest
        except (OSError, ValueError, TypeError):
            pass

    # First read of a legacy analysis or a file changed externally:
    # compute once and save metadata for the next catalogue request.
    analysis = load_output(pcap_id)
    digest = calculate_analysis_hash(analysis)
    _save_hash_metadata(pcap_id, digest, output_file)
    return digest
