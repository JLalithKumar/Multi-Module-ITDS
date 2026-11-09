import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { Activity, ArrowUpRight, Database, RefreshCw, ShieldAlert, Siren, ShieldCheck } from "lucide-react";
import { api, currentUser, hasPermission } from "../lib/api";
import type { DashboardMetrics } from "../lib/types";
import { relativeTime, useNotifications } from "../lib/notifications";
import { Badge } from "../components/ui";
import { NotificationContent } from "../components/NotificationList";

type Incident = { id: number; title: string; severity: string; status: string; assignee: string; created_at: string };

export function Dashboard() {
  const [range, setRange] = useState("7d");
  const user = currentUser();
  const notifications = useNotifications();
  const dashboard = useQuery({ queryKey: ["dashboard", user?.id], queryFn: async () => (await api.get<DashboardMetrics>("/dashboard")).data, refetchInterval: 60000, retry: 1 });
  const incidents = useQuery({ queryKey: ["incidents", user?.id], queryFn: async () => (await api.get<Incident[]>("/incidents")).data, enabled: !!hasPermission("incidents:read"), refetchInterval: 60000, retry: 1 });
  const data = dashboard.data;
  const severity = [{ name: "Critical", value: data?.critical_alerts ?? 0, color: "#f87171" }, { name: "High", value: data?.high_threats ?? 0, color: "#fbbf24" }, { name: "Medium", value: data?.medium_threats ?? 0, color: "#60a5fa" }, { name: "Low", value: data?.low_threats ?? 0, color: "#34d399" }];
  const total = severity.reduce((sum, row) => sum + row.value, 0);
  const active = incidents.data?.filter(row => !["closed", "resolved"].includes(row.status)) ?? [];
  const trend = range === "7d" ? data?.weekly_trend : data?.monthly_trend;
  const hour = new Date().getHours();
  const refresh = () => { void dashboard.refetch(); void notifications.refetch(); if (hasPermission("incidents:read")) void incidents.refetch(); };

  return <div className="soc-dashboard">
    <div className="page-heading">
      <div>
        <p className="eyebrow">Good {hour < 12 ? "morning" : hour < 18 ? "afternoon" : "evening"}, {user?.full_name?.split(" ")[0] ?? "Analyst"}</p>
        <h1>Security Operations</h1>
        <p>Real-time threat monitoring, insider analytics, and host telemetry across your organization.</p>
      </div>
      <button className="text-button" onClick={refresh} disabled={dashboard.isFetching}>
        <RefreshCw size={16} className={dashboard.isFetching ? "spin" : ""} /> Refresh
      </button>
    </div>

    {dashboard.isError ? <div className="section-error" role="alert">Unable to load the security overview. <button className="text-button" onClick={() => dashboard.refetch()}>Retry</button></div> : <>
      <div className="kpi-grid">{[
        { label: "Security logs", value: data?.total_logs, icon: Database, tone: "blue", detail: "Recorded across connected sources", permission: "logs:read" },
        { label: "Critical alerts", value: data?.critical_alerts, icon: ShieldAlert, tone: "red", detail: "Recorded critical detections", permission: "alerts:read" },
        { label: "Open incidents", value: data?.incidents, icon: Siren, tone: "amber", detail: "Excludes closed and resolved", permission: "incidents:read" },
        { label: "Alerts today", value: data?.todays_attacks, icon: Activity, tone: "green", detail: "Since 00:00 UTC", permission: "alerts:read" },
      ].filter(metric => hasPermission(metric.permission)).map(metric => <article key={metric.label} className={`kpi ${metric.tone}`}><div><span>{metric.label}</span><metric.icon size={19} /></div>{dashboard.isPending ? <div className="skeleton metric-skeleton" /> : <strong>{metric.value?.toLocaleString() ?? "0"}</strong>}<p>{metric.detail}</p></article>)}</div>
      <div className="overview-grid"><section className="soc-section"><div className="panel-heading"><h2><Activity size={17} /> Threat activity</h2><div className="segmented" aria-label="Activity period">{["7d", "30d"].map(value => <button key={value} aria-pressed={range === value} onClick={() => setRange(value)}>{value}</button>)}</div></div><p className="section-caption">Recorded alerts per day (UTC)</p>
        {dashboard.isPending ? <div className="skeleton chart-skeleton" /> : !hasPermission("alerts:read") ? <div className="empty-state">Alert telemetry is not available for your role.</div> : <div className="activity-chart" role="img" aria-label={`${range} alert activity, ${trend?.reduce((sum, row) => sum + Number(row.attacks ?? row.alerts ?? 0), 0) ?? 0} recorded alerts`}><ResponsiveContainer width="100%" height="100%"><AreaChart data={trend} margin={{ top: 20, right: 12, left: -28, bottom: 0 }}><CartesianGrid vertical={false} stroke="#303439" strokeDasharray="3 4" /><XAxis dataKey="name" tick={{ fill: "#a6adb7", fontSize: 11 }} tickLine={false} axisLine={false} minTickGap={28} /><YAxis allowDecimals={false} tick={{ fill: "#a6adb7", fontSize: 11 }} tickLine={false} axisLine={false} /><Tooltip contentStyle={{ background: "#202327", border: "1px solid #454b54", borderRadius: 6 }} /><Area name="Alerts" type="monotone" dataKey={range === "7d" ? "attacks" : "alerts"} stroke="#60a5fa" fill="#60a5fa" fillOpacity={0.12} strokeWidth={2} isAnimationActive={false} /></AreaChart></ResponsiveContainer></div>}
      </section><section className="soc-section"><div className="panel-heading"><h2><ShieldCheck size={17} /> Security posture</h2></div><div className="posture-summary"><span className="posture-symbol"><ShieldCheck size={30} /></span><div><strong>{total ? `${total} classified alerts` : "Clean security state"}</strong><p>{total ? "Investigation required" : "No active threats detected"}</p></div></div><h3 className="distribution-title">Threat distribution</h3>{severity.map(row => <div key={row.name} className="distribution-row"><span><i style={{ background: row.color }} />{row.name}</span><div className="distribution-track"><div style={{ width: `${total ? row.value / total * 100 : 0}%`, background: row.color }} /></div><b>{row.value}</b></div>)}</section></div>
    </>}
    <div className="overview-grid"><section className="soc-section"><div className="panel-heading"><h2><Siren size={17} /> Active incidents</h2>{hasPermission("incidents:read") && <Link to="/incidents">View all <ArrowUpRight size={14} /></Link>}</div>
      {!hasPermission("incidents:read") ? <div className="empty-state">Incident access is not included in your role.</div> : incidents.isPending ? <div className="skeleton-list">{[1, 2, 3].map(i => <div key={i} className="skeleton" />)}</div> : incidents.isError ? <div className="empty-state"><strong>Unable to load incidents</strong><button className="text-button" onClick={() => incidents.refetch()}>Retry</button></div> : !active.length ? <div className="empty-state"><ShieldCheck size={25} /><strong>No active incidents</strong><span>No open investigations in your organization.</span></div> : <div className="table-scroll"><table className="incident-table"><thead><tr><th>Incident</th><th>Severity</th><th>Status</th><th>Assignee</th><th>Created</th></tr></thead><tbody>{active.slice(0, 5).map(item => <tr key={item.id}><td><Link to={`/incidents?id=${item.id}`}><small>INC-{item.id}</small>{item.title}</Link></td><td><Badge severity={item.severity}>{item.severity}</Badge></td><td><span className="status-tag">{item.status}</span></td><td>{item.assignee}</td><td>{relativeTime(item.created_at)}</td></tr>)}</tbody></table></div>}
    </section><section className="soc-section"><div className="panel-heading"><h2>Recent notifications</h2><Link to="/notifications">View all <ArrowUpRight size={14} /></Link></div><NotificationContent compact /></section></div>
    <div className="overview-grid"><section className="soc-section"><div className="panel-heading"><h2>Recent security events</h2>{hasPermission("alerts:read") && <Link to="/detection">View alerts <ArrowUpRight size={14} /></Link>}</div>{dashboard.isPending ? <div className="skeleton-list"><div className="skeleton" /></div> : dashboard.isError ? <div className="empty-state"><strong>Unable to load events</strong><button className="text-button" onClick={() => dashboard.refetch()}>Retry</button></div> : !data?.live_feed.length ? <div className="empty-state"><Activity size={24} /><strong>No recent security events</strong><span>New authorized detections will appear here in real time.</span></div> : <ol className="event-timeline">{data.live_feed.slice(0, 5).map((item, index) => <li key={item.id ?? index}><span className={`severity-dot ${item.severity}`} /><div><Link to={`/detection?id=${item.id ?? ""}`}>{item.title}</Link><p>{item.source} <span>{item.created_at && relativeTime(item.created_at)}</span></p></div><Badge severity={item.severity}>{item.severity}</Badge></li>)}</ol>}</section>
    <section className="soc-section"><div className="panel-heading"><h2>Host resource usage</h2><Link to="/system-monitor">Optimizer <ArrowUpRight size={14} /></Link></div><div className="resource-meters">{[["CPU", data?.cpu], ["Memory", data?.memory], ["Disk", data?.disk]].map(([label, value]) => <div key={String(label)}><span>{label}</span><strong>{typeof value === "number" ? `${Math.round(value)}%` : "Unavailable"}</strong><meter aria-label={String(label)} min={0} max={100} value={Number(value ?? 0)} /></div>)}</div><div className="panel-heading"><h2>MITRE ATT&CK</h2></div>{data?.mitre_matrix.length ? <ul className="mitre-list">{data.mitre_matrix.map(row => <li key={`${row.tactic}-${row.technique}`}><span><strong>{row.tactic}</strong><small>{row.technique}</small></span><b>{row.count}</b></li>)}</ul> : <div className="empty-state">No recorded technique mappings.</div>}</section></div>
    {!!data?.recent_activity.length && <section className="soc-section"><div className="panel-heading"><h2>Recent log activity</h2></div><ul className="log-activity">{data.recent_activity.map((item, i) => <li key={i}><span>{item.action}</span><time>{relativeTime(item.time)}</time></li>)}</ul></section>}
  </div>;
}
