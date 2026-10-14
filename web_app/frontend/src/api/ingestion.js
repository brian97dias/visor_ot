import {
    authenticatedFetch,
} from "./client";


export async function getPcaps() {

    const response =
        await authenticatedFetch(
            "/api/ingestion/pcaps/"
        );


    let data = {};


    try {

        data =
            await response.json();

    } catch {
        // Respuesta sin JSON válido.
    }


    if (!response.ok) {

        throw new Error(
            data.detail ||
            "No fue posible obtener los PCAP."
        );

    }


    return data.pcaps;
}


export async function analyzePcap(
    pcapId
) {

    const response =
        await authenticatedFetch(
            `/api/ingestion/pcaps/${encodeURIComponent(pcapId)}/analyze/`,
            {
                method: "POST",
            }
        );


    let data = {};


    try {

        data =
            await response.json();

    } catch {
        // Respuesta sin JSON válido.
    }


    if (!response.ok) {

        throw new Error(
            data.detail ||
            "No fue posible analizar el PCAP."
        );

    }


    return data;
}

export async function getPcapAnalysis(
    pcapId
) {

    const response =
        await authenticatedFetch(
            `/api/ingestion/pcaps/${encodeURIComponent(pcapId)}/analysis/`
        );


    let data = {};


    try {

        data =
            await response.json();

    } catch {
        // Respuesta sin JSON válido.
    }


    if (!response.ok) {

        throw new Error(
            data.detail ||
            "No fue posible obtener el análisis."
        );

    }


    return data;
}

export async function importPcapObservations(
    pcapId
) {

    const response =
        await authenticatedFetch(
            `/api/ingestion/pcaps/${encodeURIComponent(pcapId)}/import/`,
            {
                method: "POST",
            }
        );


        let data = {};


        try {

            data = await response.json();

        } catch {

            throw new Error(
                "El servidor devolvió una respuesta inválida."
            );

        }


    if (!response.ok) {

        throw new Error(
            data.detail ||
            "No fue posible importar las observaciones."
        );

    }


    return data;
}


export async function getIngestions() {

    const response =
        await authenticatedFetch(
            "/api/ingestion/imports/"
        );


    const data =
        await response.json();


    if (!response.ok) {

        throw new Error(
            data.detail ||
            "No fue posible obtener las importaciones."
        );

    }


    return data.ingestions;
}


export async function getIngestion(
    ingestionId
) {

    const response =
        await authenticatedFetch(
            `/api/ingestion/imports/${ingestionId}/`
        );


    const data =
        await response.json();


    if (!response.ok) {

        throw new Error(
            data.detail ||
            "No fue posible obtener la importación."
        );

    }


    return data;
}


export async function excludeIngestion(
    ingestionId
) {

    const response =
        await authenticatedFetch(
            `/api/ingestion/imports/${ingestionId}/exclude/`,
            {
                method: "POST",
            }
        );


    const data =
        await response.json();


    if (!response.ok) {

        throw new Error(
            data.detail ||
            "No fue posible excluir la importación."
        );

    }


    return data;
}

export async function activateIngestion(
    ingestionId
) {

    const response =
        await authenticatedFetch(
            `/api/ingestion/imports/${ingestionId}/activate/`,
            {
                method: "POST",
            }
        );


    const data =
        await response.json();


    if (!response.ok) {

        throw new Error(
            data.detail ||
            "No fue posible reactivar la importación."
        );

    }


    return data;
}
export async function getObservationPage(source, id, { kind, page, search, minPackets }) {
    const params = new URLSearchParams({
        type: kind,
        page: String(page),
        search,
        min_packets: String(minPackets),
    });
    const route = source === "analysis"
        ? `/api/ingestion/pcaps/${encodeURIComponent(id)}/analysis/observations/`
        : `/api/ingestion/imports/${encodeURIComponent(id)}/observations/`;

    const response = await authenticatedFetch(route + "?" + params.toString());
    let data = {};
    try {
        data = await response.json();
    } catch {
        throw new Error("El servidor devolvió una respuesta inválida.");
    }
    if (!response.ok) {
        const detail = typeof data.detail === "string"
            ? data.detail
            : "No fue posible consultar las observaciones.";
        throw new Error(detail);
    }
    if (!Array.isArray(data.results)) {
        throw new Error("La respuesta no contiene las observaciones paginadas.");
    }
    return data;
}
