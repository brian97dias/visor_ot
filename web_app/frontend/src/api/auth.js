import {
    API_URL,
    authenticatedFetch,
} from "./client";


export async function login(username, password) {
    const response = await fetch(
        `${API_URL}/api/auth/login/`,
        {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({
                username,
                password,
            }),
        }
    );

    if (!response.ok) {
        throw new Error(
            "Usuario o contraseña incorrectos"
        );
    }

    return response.json();
}


export async function getCurrentUser() {
    const response =
        await authenticatedFetch(
            "/api/auth/me/"
        );

    if (!response.ok) {
        throw new Error(
            "La sesión no es válida"
        );
    }

    return response.json();
}