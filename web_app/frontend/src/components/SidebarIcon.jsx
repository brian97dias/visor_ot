/** Small inline SVG symbols matching the sidebar reference, no icon dependency. */
export default function SidebarIcon({ name }) {
  const drawings = {
    panel: <><rect x="3" y="4" width="18" height="16" rx="2"/><path d="M9 4v16"/></>,
    dashboard: <><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></>,
    network: <><circle cx="12" cy="4" r="2"/><circle cx="5" cy="19" r="2"/><circle cx="19" cy="19" r="2"/><path d="M12 6v5M5 17v-3h14v3M19 14l-7-3-7 3"/></>,
    communications: <><path d="M4 7h16M4 7l5-5M4 7l5 5M20 17H4M20 17l-5-5M20 17l-5 5"/></>,
    inventory: <><rect x="3" y="3" width="18" height="8" rx="2"/><rect x="3" y="13" width="18" height="8" rx="2"/><path d="M7 7h.01M7 17h.01"/></>,
    interfaces: <><path d="M7 2v7M5 2h4M7 9c0 4 3 4 3 8s-3 4-3 4M18 2v7M16 2h4M18 9c0 4-3 4-3 8"/><rect x="14" y="17" width="7" height="5" rx="1"/></>,
    systems: <><rect x="3" y="3" width="8" height="8" rx="1"/><rect x="13" y="13" width="8" height="8" rx="1"/><path d="M15 3h6v6h-6zM3 15h6v6H3z"/></>,
    fingerprint: <><path d="M6 10a6 6 0 0 1 12 0M4 13v-2a8 8 0 0 1 16 0M8 11a4 4 0 0 1 8 0v3M12 11v6M6 14v2m12-2v2M9 18c0 1-.4 2-1 3M15 18c0 1 .4 2 1 3M12 20v2"/></>,
    shield: <><path d="M12 2 4 5v7c0 5 3 8 8 10 5-2 8-5 8-10V5l-8-3Z"/><path d="M12 7v6M12 17h.01"/></>,
  };
  return <svg className="sidebar-icon" viewBox="0 0 24 24" fill="none"
    stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"
    aria-hidden="true" focusable="false">{drawings[name] || drawings.dashboard}</svg>;
}
