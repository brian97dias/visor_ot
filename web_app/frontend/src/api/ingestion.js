const API_URL = import.meta.env.VITE_API_URL;


export async function getPcaps(accessToken) {
    const response = await fetch(
        `${API_URL}/api/ingestion/pcaps/`,
        {
            headers: {
                Authorization: `Bearer ${accessToken}`,
            },
        }
    );

    let data = {};

    try {
        data = await response.json();
    } catch {
        // La respuesta no contenía JSON válido.
    }

    if (!response.ok) {
        throw new Error(
            data.detail ||
            "No fue posible obtener los PCAP."
        );
    }

    return data.pcaps;
}