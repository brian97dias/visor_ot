import json

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


    return output_file