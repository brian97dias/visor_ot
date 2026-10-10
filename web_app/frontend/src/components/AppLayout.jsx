import { useEffect, useState } from "react";
import { NavLink, Outlet, useNavigate } from "react-router-dom";

import { getCurrentUser } from "../api/auth";

function AppLayout() {
  const navigate = useNavigate();

  const [user, setUser] = useState(null);
  const [error, setError] = useState("");

  useEffect(() => {
    async function loadUser() {
      try {
        const userData = await getCurrentUser();

        setUser(userData);
      } catch (error) {
        sessionStorage.clear();

        setError(error.message || "Tu sesión ha expirado.");
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
      <main className="session-error">
        <h1>Sesión finalizada</h1>

        <p>{error}</p>

        <button onClick={logout}>Volver al login</button>
      </main>
    );
  }

  if (!user) {
    return <main className="session-loading">Cargando sesión...</main>;
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="sidebar-brand">
          <span>VISOR OT</span>

          <small>Gestión de activos OT</small>
        </div>

        <nav className="sidebar-nav">
          <NavLink
            to="/dashboard"
            className={({ isActive }) =>
              isActive ? "nav-item active" : "nav-item"
            }
          >
            Dashboard
          </NavLink>

          <div className="nav-section">
            <span className="nav-section-title">RED</span>

            <NavLink
              to="/passive-analysis"
              className={({ isActive }) =>
                isActive
                  ? "nav-item nav-subitem active"
                  : "nav-item nav-subitem"
              }
            >
              Análisis pasivo
            </NavLink>
            <NavLink
              to="/communications"
              className={({ isActive }) =>
                isActive
                  ? "nav-item nav-subitem active"
                  : "nav-item nav-subitem"
              }
            >
              Comunicaciones
            </NavLink>
          </div>

          <div className="nav-section">
            <span className="nav-section-title">ACTIVOS</span>
            <NavLink
              end
              to="/assets"
              className={({ isActive }) =>
                isActive ? "nav-item nav-subitem active" : "nav-item nav-subitem"
              }
            >
              Inventario
            </NavLink>
            <NavLink
              to="/assets/hardware"
              className={({ isActive }) =>
                isActive ? "nav-item nav-subitem active" : "nav-item nav-subitem"
              }
            >
              Hardware
            </NavLink>
          </div>
        </nav>

        <div className="sidebar-user">
          <div>
            <strong>{user.username}</strong>

            <span>{user.role}</span>
          </div>

          <button onClick={logout}>Cerrar sesión</button>
        </div>
      </aside>

      <main className="app-content">
        <Outlet context={{ user }} />
      </main>
    </div>
  );
}

export default AppLayout;
