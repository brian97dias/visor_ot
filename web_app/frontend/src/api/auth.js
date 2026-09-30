const API_URL = import.meta.env.VITE_API_URL;


export async function login(username, password) {
    const response = await fetch(`${API_URL}/api/auth/login/`, {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
        },
        body: JSON.stringify({
            username,
            password,
        }),
    });

    if (!response.ok) {
        throw new Error("Usuario o contraseña incorrectos");
    }

    return response.json();
}


export async function getCurrentUser(accessToken) {
    const response = await fetch(`${API_URL}/api/auth/me/`, {
        headers: {
            Authorization: `Bearer ${accessToken}`,
        },
    });

    if (!response.ok) {
        throw new Error("La sesión no es válida");
    }

    return response.json();
}