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


    const data =
        await response.json();


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