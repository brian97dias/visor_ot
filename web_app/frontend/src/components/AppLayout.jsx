import { useEffect, useState } from "react";
import { NavLink, Outlet, useLocation, useNavigate } from "react-router-dom";

import { getCurrentUser } from "../api/auth";
import SidebarIcon from "./SidebarIcon";

function AppLayout() {
  const navigate = useNavigate();
  const location = useLocation();
  const viewingAssetCpe = /^\/assets\/\d+\/cpe\/?$/.test(location.pathname);

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
          <div className="sidebar-brand-title">
            <SidebarIcon name="panel" />
            <span>VISOR OT</span>
          </div>
          <small>Gestión de activos OT</small>
        </div>

        <nav className="sidebar-nav" aria-label="Navegación principal">
          <NavLink to="/dashboard" className={({ isActive }) =>
            isActive ? "nav-item active" : "nav-item"
          }>
            <SidebarIcon name="dashboard" />
            <span>Dashboard</span>
          </NavLink>

          <div className="nav-section">
            <span className="nav-section-title">RED</span>
            <NavLink to="/passive-analysis" className={({ isActive }) =>
              isActive ? "nav-item nav-subitem active" : "nav-item nav-subitem"
            }>
              <SidebarIcon name="network" />
              <span>Análisis pasivo</span>
            </NavLink>
            <NavLink to="/communications" className={({ isActive }) =>
              isActive ? "nav-item nav-subitem active" : "nav-item nav-subitem"
            }>
              <SidebarIcon name="communications" />
              <span>Comunicaciones</span>
            </NavLink>
          </div>

          <div className="nav-section">
            <span className="nav-section-title">ACTIVOS</span>
            <NavLink end to="/assets" className={({ isActive }) =>
              isActive ? "nav-item nav-subitem active" : "nav-item nav-subitem"
            }>
              <SidebarIcon name="inventory" />
              <span>Inventario</span>
            </NavLink>
            <NavLink to="/assets/interfaces" className={({ isActive }) =>
              isActive ? "nav-item nav-subitem active" : "nav-item nav-subitem"
            }>
              <SidebarIcon name="interfaces" />
              <span>Interfaces</span>
            </NavLink>
            <NavLink to="/assets/systems" className={({ isActive }) =>
              isActive ? "nav-item nav-subitem active" : "nav-item nav-subitem"
            }>
              <SidebarIcon name="systems" />
              <span>Sistemas</span>
            </NavLink>
          </div>

          <div className="nav-section">
            <span className="nav-section-title">VULNERABILIDADES</span>
            <NavLink to="/vulnerabilities/cpe" className={({ isActive }) =>
              isActive || viewingAssetCpe ? "nav-item nav-subitem active" : "nav-item nav-subitem"
            }>
              <SidebarIcon name="fingerprint" />
              <span>Identificación CPE</span>
            </NavLink>
            <span className="nav-item nav-subitem nav-item-disabled"
              aria-disabled="true" title="Disponible en una fase futura">
              <SidebarIcon name="shield" />
              <span>Análisis CVE (futuro)</span>
            </span>
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
