from config import (
    PCAP_DIRECTORY,
    OUTPUT_DIRECTORY,
)

from pcap_identity import (
    get_pcap_id,
    get_relative_path,
)


PCAP_EXTENSIONS = {
    ".pcap",
    ".pcapng",
}

def get_pcap_by_id(pcap_id):

    if not PCAP_DIRECTORY.exists():
        return None


    for pcap_path in PCAP_DIRECTORY.rglob("*"):

        if not pcap_path.is_file():
            continue


        if (
            pcap_path.suffix.lower()
            not in PCAP_EXTENSIONS
        ):
            continue


        if get_pcap_id(pcap_path) == pcap_id:
            return pcap_path


    return None

def get_pcap_status(pcap_path):

    pcap_id = get_pcap_id(
        pcap_path
    )

    output_file = (
        OUTPUT_DIRECTORY
        / f"{pcap_id}.json"
    )


    if output_file.is_file():
        return "ANALYZED"


    return "PENDING"


def list_pcaps():

    if not PCAP_DIRECTORY.exists():
        return []

    pcaps = []


    for pcap_path in sorted(
        PCAP_DIRECTORY.rglob("*")
    ):

        if not pcap_path.is_file():
            continue


        if (
            pcap_path.suffix.lower()
            not in PCAP_EXTENSIONS
        ):
            continue


        relative_path = get_relative_path(
            pcap_path
        )

        pcap_id = get_pcap_id(
            pcap_path
        )


        pcaps.append({
            "id": pcap_id,
            "filename": pcap_path.name,
            "relative_path": relative_path,
            "status": get_pcap_status(
                pcap_path
            ),
        })


    return pcaps