from ipaddress import ip_address

from config import INTERNAL_NETWORKS


def is_observed_local_ip(
    ip,
    ip_to_macs,
):
    return ip in ip_to_macs


def get_internal_network(ip):

    address = ip_address(ip)

    for network in INTERNAL_NETWORKS:
        if address in network:
            return network

    return None


def classify_network_scope(
    client_ip,
    server_ip,
    ip_to_macs,
):

    client_is_local = is_observed_local_ip(
        client_ip,
        ip_to_macs,
    )

    server_is_local = is_observed_local_ip(
        server_ip,
        ip_to_macs,
    )


    # Tenemos evidencia ARP de ambos extremos.
    if client_is_local and server_is_local:
        return "local_segment"


    client_internal_network = get_internal_network(
        client_ip
    )

    server_internal_network = get_internal_network(
        server_ip
    )


    # Ambos pertenecen a infraestructura interna
    # configurada.
    if client_internal_network and server_internal_network:
        return "internal_routed"


    # Un extremo está observado localmente
    # y el otro no.
    if client_is_local != server_is_local:

        external_ip = (
            server_ip
            if client_is_local
            else client_ip
        )

        if ip_address(external_ip).is_global:
            return "external_public"


        if get_internal_network(external_ip):
            return "internal_routed"


    return "unknown"