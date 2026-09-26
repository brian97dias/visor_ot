import argparse

from pathlib import Path

from analyzer import analyze_pcap
from output import save_output


def parse_arguments():

    parser = argparse.ArgumentParser(
        description="Analizador pasivo de capturas PCAP/PCAPNG"
    )

    parser.add_argument(
        "pcap",
        type=Path,
        help="Ruta al archivo PCAP o PCAPNG que se desea analizar",
    )

    args = parser.parse_args()

    pcap_path = (
        args.pcap
        .expanduser()
        .resolve()
    )


    if not pcap_path.is_file():

        parser.error(
            f"El archivo no existe o no es accesible: {pcap_path}"
        )


    if pcap_path.suffix.lower() not in {
        ".pcap",
        ".pcapng",
    }:

        parser.error(
            "El archivo debe tener extensión .pcap o .pcapng"
        )


    return pcap_path


def main():

    pcap_path = parse_arguments()


    interfaces, communications = analyze_pcap(
        pcap_path
    )


    print(
        f"Interfaces detectadas: {len(interfaces)}"
    )

    for interface in interfaces.values():
        print(interface)


    print(
        f"\nComunicaciones detectadas: {len(communications)}"
    )

    for communication in communications.values():
        print(communication)


    output_file = save_output(
        pcap_path,
        interfaces,
        communications,
    )


    print(
        f"\nObservaciones guardadas en: {output_file}"
    )


if __name__ == "__main__":
    main()