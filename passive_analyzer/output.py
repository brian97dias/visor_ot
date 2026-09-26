import json

from pathlib import Path


def build_output(
    pcap_path,
    interfaces,
    communications,
):

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
        "schema_version": "0.1",

        "capture": {
            "filename": Path(pcap_path).name,
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


    output_directory = (
        Path(__file__).resolve().parent
        / "output"
    )

    output_directory.mkdir(
        exist_ok=True
    )


    output_file = (
        output_directory
        / f"{Path(pcap_path).stem}.json"
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