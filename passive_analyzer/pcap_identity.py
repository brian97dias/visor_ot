import hashlib

from config import PCAP_DIRECTORY


def get_relative_path(pcap_path):
    return (
        pcap_path
        .resolve()
        .relative_to(
            PCAP_DIRECTORY.resolve()
        )
        .as_posix()
    )


def build_pcap_id(relative_path):
    return hashlib.sha256(
        relative_path.encode("utf-8")
    ).hexdigest()[:16]


def get_pcap_id(pcap_path):
    relative_path = get_relative_path(
        pcap_path
    )

    return build_pcap_id(
        relative_path
    )