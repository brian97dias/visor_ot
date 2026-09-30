import { useState } from "react";
import { useNavigate } from "react-router-dom";

import { login } from "../api/auth";


function Login() {
    const navigate = useNavigate();

    const [username, setUsername] = useState("");
    const [password, setPassword] = useState("");

    const [error, setError] = useState("");
    const [loading, setLoading] = useState(false);


    const handleSubmit = async (event) => {
        event.preventDefault();

        setError("");
        setLoading(true);

        try {
            const data = await login(username, password);

            sessionStorage.setItem(
                "access_token",
                data.access
            );

            sessionStorage.setItem(
                "refresh_token",
                data.refresh
            );

            sessionStorage.setItem(
                "user",
                JSON.stringify(data.user)
            );

            navigate("/dashboard");

        } catch (error) {
            setError(error.message);

        } finally {
            setLoading(false);
        }
    };


    return (
        <main className="login-page">

            <section className="login-card">

                <div className="login-header">
                    <span className="login-product">
                        VISUAL OT
                    </span>

                    <h1>
                        Iniciar sesión
                    </h1>

                    <p>
                        Plataforma de gestión y visibilidad
                        de activos OT
                    </p>
                </div>


                <form
                    className="login-form"
                    onSubmit={handleSubmit}
                >

                    <div className="form-group">
                        <label htmlFor="username">
                            Usuario
                        </label>

                        <input
                            id="username"
                            type="text"
                            value={username}
                            onChange={(event) =>
                                setUsername(event.target.value)
                            }
                            autoComplete="username"
                            required
                        />
                    </div>


                    <div className="form-group">
                        <label htmlFor="password">
                            Contraseña
                        </label>

                        <input
                            id="password"
                            type="password"
                            value={password}
                            onChange={(event) =>
                                setPassword(event.target.value)
                            }
                            autoComplete="current-password"
                            required
                        />
                    </div>


                    {error && (
                        <p className="login-error">
                            {error}
                        </p>
                    )}


                    <button
                        type="submit"
                        disabled={loading}
                    >
                        {loading
                            ? "Ingresando..."
                            : "Ingresar"}
                    </button>

                </form>

            </section>

        </main>
    );
}

export default Login;