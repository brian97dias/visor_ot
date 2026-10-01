import { useOutletContext } from "react-router-dom";


function Dashboard() {
    const { user } = useOutletContext();

    return (
        <section className="page">

            <header className="page-header">

                <div>
                    <span className="page-eyebrow">
                        VISUAL OT
                    </span>

                    <h1>
                        Dashboard
                    </h1>

                    <p>
                        Bienvenido, {user.username}.
                    </p>
                </div>

            </header>


            <div className="panel">

                <h2>
                    Estado del sistema
                </h2>

                <p>
                    Visual OT está conectado y tu
                    sesión se encuentra activa.
                </p>

                <div className="user-information">

                    <p>
                        <strong>Usuario:</strong>{" "}
                        {user.username}
                    </p>

                    <p>
                        <strong>Correo:</strong>{" "}
                        {user.email}
                    </p>

                    <p>
                        <strong>Rol:</strong>{" "}
                        {user.role}
                    </p>

                </div>

            </div>

        </section>
    );
}

export default Dashboard;