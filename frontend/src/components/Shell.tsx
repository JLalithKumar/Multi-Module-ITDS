import { useEffect, useRef, useState } from "react";
import { Link, NavLink, Outlet, useLocation, useNavigate } from "react-router-dom";
import { useQueryClient } from "@tanstack/react-query";
import {
  Bell,
  Bug,
  ChartNoAxesCombined,
  CheckCheck,
  ChevronDown,
  Cpu,
  FileBarChart,
  Fingerprint,
  Gauge,
  Globe2,
  HardDriveUpload,
  Laptop,
  LogOut,
  Menu,
  Network,
  Radar,
  Search,
  Settings,
  Shield,
  Siren,
  Terminal,
  Users,
  X,
} from "lucide-react";
import { api, clearSession, currentUser, hasPermission } from "../lib/api";
import { NotificationProvider, useNotifications } from "../lib/notifications";
import { NotificationContent } from "./NotificationList";

const groups = [
  {
    label: "Overview",
    items: [
      { to: "/", label: "Dashboard", icon: Gauge, permission: "dashboard:read" },
      { to: "/agent", label: "Live Endpoint Agent", icon: Laptop, permission: "dashboard:read" },
      { to: "/system-monitor", label: "Host Telemetry", icon: Cpu, permission: "dashboard:read" },
    ],
  },
  {
    label: "Security operations",
    items: [
      { to: "/detection", label: "Alerts & detection", icon: Radar, permission: "alerts:read" },
      { to: "/incidents", label: "Incidents", icon: Siren, permission: "incidents:read" },
      { to: "/network", label: "Network events", icon: Network, permission: "dashboard:read" },
      { to: "/logs", label: "Security logs", icon: HardDriveUpload, permission: "logs:read" },
      { to: "/anomaly", label: "Anomaly detection", icon: ChartNoAxesCombined, permission: "alerts:read" },
    ],
  },
  {
    label: "Threat management",
    items: [
      { to: "/intel", label: "Threat intelligence", icon: Globe2, permission: "threat_intel:read" },
      { to: "/malware", label: "Malware analysis", icon: Bug, permission: "malware:analyze" },
      { to: "/vulnerabilities", label: "Vulnerabilities", icon: Terminal, permission: "vulnerability:scan" },
    ],
  },
  {
    label: "Reporting",
    items: [
      { to: "/reports", label: "Reports", icon: FileBarChart, permission: "reports:read" },
      { to: "/audit", label: "Audit logs", icon: Fingerprint, permission: "audit:read" },
    ],
  },
  {
    label: "Administration",
    items: [
      { to: "/employees", label: "Employee Management", icon: Users, permission: "users:read" },
      { to: "/notifications", label: "Notifications", icon: Bell, permission: "dashboard:read" },
      { to: "/settings", label: "Settings", icon: Settings, permission: "settings:read" },
    ],
  },
];

function Workspace() {
  const user = currentUser();
  const navigate = useNavigate();
  const location = useLocation();
  const queryClient = useQueryClient();
  const { unread, update, updating, connected } = useNotifications();
  const [collapsed, setCollapsed] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);
  const [panel, setPanel] = useState<"notifications" | "profile" | null>(null);
  const [search, setSearch] = useState("");
  const header = useRef<HTMLElement>(null);
  const sidebar = useRef<HTMLElement>(null);
  const toggle = useRef<HTMLButtonElement>(null);
  const bell = useRef<HTMLButtonElement>(null);
  const profile = useRef<HTMLButtonElement>(null);
  const visibleGroups = groups
    .map((group) => ({ ...group, items: group.items.filter((item) => hasPermission(item.permission)) }))
    .filter((group) => group.items.length);

  useEffect(() => {
    setMobileOpen(false);
    setPanel(null);
    setSearch("");
  }, [location.pathname]);

  useEffect(() => {
    const end = () => {
      queryClient.clear();
      navigate("/login", { replace: true });
    };
    window.addEventListener("cybershield:session-ended", end);
    return () => window.removeEventListener("cybershield:session-ended", end);
  }, [navigate, queryClient]);

  useEffect(() => {
    const outside = (event: PointerEvent) => {
      if (!header.current?.contains(event.target as Node)) {
        setPanel(null);
        setSearch("");
      }
    };
    const keyboard = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        if (mobileOpen) toggle.current?.focus();
        else if (panel === "notifications") bell.current?.focus();
        else if (panel) profile.current?.focus();
        setMobileOpen(false);
        setPanel(null);
        setSearch("");
      }
      if (event.key === "Tab" && mobileOpen) {
        const elements = sidebar.current?.querySelectorAll<HTMLElement>("a,button");
        if (!elements?.length) return;
        const first = elements[0],
          last = elements[elements.length - 1];
        if (event.shiftKey && document.activeElement === first) {
          event.preventDefault();
          last.focus();
        } else if (!event.shiftKey && document.activeElement === last) {
          event.preventDefault();
          first.focus();
        }
      }
    };
    document.addEventListener("pointerdown", outside);
    document.addEventListener("keydown", keyboard);
    if (mobileOpen) sidebar.current?.querySelector<HTMLElement>("button,a")?.focus();
    return () => {
      document.removeEventListener("pointerdown", outside);
      document.removeEventListener("keydown", keyboard);
    };
  }, [mobileOpen, panel]);

  async function logout() {
    try {
      await api.post("/auth/logout", {
        access_token: localStorage.getItem("cybershield_token"),
        refresh_token: localStorage.getItem("cybershield_refresh_token"),
      });
    } finally {
      clearSession();
    }
  }

  return (
    <div className={`workspace ${collapsed ? "sidebar-collapsed" : ""}`}>
      {mobileOpen && <button className="sidebar-backdrop" aria-label="Close navigation" onClick={() => setMobileOpen(false)} />}
      <aside ref={sidebar} className={`soc-sidebar ${mobileOpen ? "mobile-open" : ""}`} aria-label="Main navigation">
        <div className="sidebar-brand">
          <Shield size={24} />
          <span>
            CyberShield <b>XDR</b>
          </span>
          <button
            className="icon-button mobile-close"
            aria-label="Close navigation"
            onClick={() => {
              setMobileOpen(false);
              toggle.current?.focus();
            }}
          >
            <X size={18} />
          </button>
        </div>
        <nav>
          {visibleGroups.map((group) => (
            <div className="nav-group" key={group.label}>
              <div className="nav-label">{group.label}</div>
              {group.items.map((item) => (
                <NavLink end={item.to === "/"} title={item.label} aria-label={item.label} to={item.to} key={item.to}>
                  <item.icon size={18} />
                  <span>{item.label}</span>
                </NavLink>
              ))}
            </div>
          ))}
        </nav>
        <div className="sidebar-footer">
          <span className={`connection-dot ${connected ? "connected" : ""}`} />
          <span>{connected ? "Notifications connected" : "Reconnecting notifications"}</span>
        </div>
      </aside>
      <div className="workspace-main" inert={mobileOpen || undefined}>
        <header ref={header} className="soc-header">
          <button
            ref={toggle}
            className="icon-button"
            aria-label="Toggle navigation"
            aria-expanded={mobileOpen || !collapsed}
            onClick={() => (window.innerWidth < 1024 ? setMobileOpen(!mobileOpen) : setCollapsed(!collapsed))}
          >
            <Menu size={20} />
          </button>
          <Link to="/" className="header-brand">
            CyberShield <b>XDR</b>
          </Link>
          <div className="workspace-search">
            <Search size={16} />
            <input
              aria-label="Find a module"
              placeholder="Find a module..."
              value={search}
              onChange={(event) => setSearch(event.target.value)}
            />
            {search && (
              <div className="search-results">
                {visibleGroups
                  .flatMap((group) => group.items)
                  .filter((item) => item.label.toLowerCase().includes(search.toLowerCase()))
                  .map((item) => (
                    <Link key={item.to} to={item.to}>
                      {item.label}
                    </Link>
                  ))}
                {!visibleGroups.some((group) =>
                  group.items.some((item) => item.label.toLowerCase().includes(search.toLowerCase()))
                ) && <p>No matching modules</p>}
              </div>
            )}
          </div>
          <div className="header-actions">
            <button
              ref={bell}
              className="icon-button bell-button"
              aria-label={`Notifications, ${unread} unread`}
              aria-expanded={panel === "notifications"}
              aria-controls="notification-popover"
              onClick={() => setPanel(panel === "notifications" ? null : "notifications")}
            >
              <Bell size={19} />
              {unread > 0 && <span key={unread} className="unread-badge">{unread > 99 ? "99+" : unread}</span>}
            </button>
            <button
              ref={profile}
              className="profile-button"
              aria-label="Open profile menu"
              aria-expanded={panel === "profile"}
              onClick={() => setPanel(panel === "profile" ? null : "profile")}
            >
              <span className="avatar">
                {(user?.full_name ?? "U")
                  .split(" ")
                  .map((part: string) => part[0])
                  .slice(0, 2)
                  .join("")}
              </span>
              <span className="profile-copy">
                <strong>{user?.full_name}</strong>
                <small>{user?.role}</small>
              </span>
              <ChevronDown size={14} />
            </button>
          </div>
          {panel === "notifications" && (
            <section id="notification-popover" aria-label="Notifications" className="notification-popover">
              <div className="panel-heading">
                <h2>
                  Notifications <span>{unread}</span>
                </h2>
                <button
                  className="icon-button"
                  title="Mark all as read"
                  aria-label="Mark all as read"
                  disabled={!unread || updating}
                  onClick={() => update({ action: "read-all" })}
                >
                  <CheckCheck size={18} />
                </button>
                <button
                  className="icon-button"
                  aria-label="Close notifications"
                  onClick={() => {
                    setPanel(null);
                    bell.current?.focus();
                  }}
                >
                  <X size={18} />
                </button>
              </div>
              <NotificationContent compact />
              <Link className="popover-footer" to="/notifications">
                View all notifications
              </Link>
            </section>
          )}
          {panel === "profile" && (
            <div className="profile-popover">
              <strong>{user?.full_name}</strong>
              <small>{user?.role}</small>
              {hasPermission("users:read") && (
                <Link to="/employees">
                  <Users size={16} /> Employees
                </Link>
              )}
              {hasPermission("settings:read") && (
                <Link to="/settings">
                  <Settings size={16} /> Settings
                </Link>
              )}
              <button
                onClick={() => {
                  void logout().catch(() => undefined);
                }}
              >
                <LogOut size={16} /> Sign out
              </button>
            </div>
          )}
        </header>
        <main className="workspace-content">
          <Outlet />
        </main>
      </div>
    </div>
  );
}

export function Shell() {
  return (
    <NotificationProvider>
      <Workspace />
    </NotificationProvider>
  );
}
