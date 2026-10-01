from config import (
    PCAP_DIRECTORY,
    OUTPUT_DIRECTORY,
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


        if pcap_path.stem == pcap_id:
            return pcap_path


    return None


def get_pcap_status(pcap_path):

    output_file = (
        OUTPUT_DIRECTORY
        / f"{pcap_path.stem}.json"
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


        relative_path = (
            pcap_path
            .relative_to(PCAP_DIRECTORY)
            .as_posix()
        )


        pcaps.append({
            "id": pcap_path.stem,
            "filename": pcap_path.name,
            "relative_path": relative_path,
            "status": get_pcap_status(
                pcap_path
            ),
        })


    return pcaps