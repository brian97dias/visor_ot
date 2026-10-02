const API_URL = import.meta.env.VITE_API_URL;


async function refreshAccessToken() {

    const refreshToken =
        sessionStorage.getItem(
            "refresh_token"
        );


    if (!refreshToken) {
        throw new Error(
            "La sesión ha expirado."
        );
    }


    const response = await fetch(
        `${API_URL}/api/auth/refresh/`,
        {
            method: "POST",

            headers: {
                "Content-Type":
                    "application/json",
            },

            body: JSON.stringify({
                refresh: refreshToken,
            }),
        }
    );


    if (!response.ok) {

        sessionStorage.clear();

        throw new Error(
            "La sesión ha expirado."
        );
    }


    const data =
        await response.json();


    sessionStorage.setItem(
        "access_token",
        data.access
    );


    /*
     * Lo dejamos preparado por si
     * en el futuro configuramos rotación
     * de refresh tokens.
     */
    if (data.refresh) {

        sessionStorage.setItem(
            "refresh_token",
            data.refresh
        );

    }


    return data.access;
}


export async function authenticatedFetch(
    path,
    options = {}
) {

    let accessToken =
        sessionStorage.getItem(
            "access_token"
        );


    if (!accessToken) {

        throw new Error(
            "No existe una sesión activa."
        );

    }


    const buildOptions = (token) => ({
        ...options,

        headers: {
            ...options.headers,

            Authorization:
                `Bearer ${token}`,
        },
    });


    let response = await fetch(
        `${API_URL}${path}`,
        buildOptions(accessToken)
    );


    /*
     * El access pudo haber expirado.
     *
     * Intentamos refrescarlo UNA sola vez.
     */
    if (response.status === 401) {

        accessToken =
            await refreshAccessToken();


        response = await fetch(
            `${API_URL}${path}`,
            buildOptions(accessToken)
        );

    }


    return response;
}


export { API_URL };