from network.models import Communication


def consolidate_communication_observations(
    observations,
):

    linked = 0
    created = 0


    for observation in observations:

        communication, was_created = (
            Communication.objects.get_or_create(

                source_ip=observation.client_ip,

                destination_ip=observation.server_ip,

                transport_protocol=(
                    observation
                    .transport_protocol
                    .upper()
                ),

                service_port=(
                    observation.service_port
                ),

                defaults={
                    "service":
                        observation.service,
                },
            )
        )


        if was_created:
            created += 1


        # Si antes no conocíamos el servicio
        # y una nueva evidencia sí lo conoce,
        # enriquecemos la comunicación.
        if (
            not communication.service
            and observation.service
        ):

            communication.service = (
                observation.service
            )

            communication.save(
                update_fields=[
                    "service",
                ]
            )


        if (
            observation.communication_id
            != communication.id
        ):

            observation.communication = (
                communication
            )

            observation.save(
                update_fields=[
                    "communication",
                ]
            )

            linked += 1


    return {
        "communications_created": created,
        "observations_linked": linked,
    }


def consolidate_all_observations():

    from ingestion.models import (
        CommunicationObservation,
    )


    observations = (
        CommunicationObservation.objects
        .select_related(
            "communication"
        )
        .all()
    )


    return (
        consolidate_communication_observations(
            observations
        )
    )