import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";

import { getCurrentUser } from "../api/auth";


function Dashboard() {
    const navigate = useNavigate();

    const [user, setUser] = useState(null);
    const [error, setError] = useState("");


    useEffect(() => {
        async function loadUser() {
            const accessToken =
                sessionStorage.getItem("access_token");

            try {
                const userData =
                    await getCurrentUser(accessToken);

                setUser(userData);

            } catch {
                sessionStorage.clear();

                setError(
                    "Tu sesión ha expirado."
                );
            }
        }

        loadUser();
    }, []);


    const logout = () => {
        sessionStorage.clear();
        navigate("/login");
    };


    if (error) {
        return (
            <main className="dashboard-page">
                <p>{error}</p>

                <button onClick={logout}>
                    Volver al login
                </button>
            </main>
        );
    }


    if (!user) {
        return (
            <main className="dashboard-page">
                <p>Cargando sesión...</p>
            </main>
        );
    }


    return (
        <main className="dashboard-page">

            <section className="dashboard-card">

                <span className="login-product">
                    VISUAL OT
                </span>

                <h1>
                    Bienvenido, {user.username}
                </h1>

                <p>
                    Sesión iniciada correctamente.
                </p>

                <div className="user-information">
                    <p>
                        <strong>Correo:</strong>{" "}
                        {user.email}
                    </p>

                    <p>
                        <strong>Rol:</strong>{" "}
                        {user.role}
                    </p>
                </div>

                <button onClick={logout}>
                    Cerrar sesión
                </button>

            </section>

        </main>
    );
}

export default Dashboard;