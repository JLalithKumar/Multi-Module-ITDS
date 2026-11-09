import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  Activity,
  AlertOctagon,
  CheckCircle2,
  Globe,
  Laptop,
  Radio,
  RefreshCw,
  Search,
  ShieldAlert,
  Terminal,
} from "lucide-react";
import { api } from "../lib/api";
import { Card, PageFrame, SectionTitle } from "../components/ui";

interface AgentStatusData {
  agent_id: string;
  hostname: string;
  os: string;
  ip: string;
  status: string;
  is_online: boolean;
  last_seen_iso: string | null;
  events_captured: number;
  threats_detected: number;
  recent_events: Array<{
    time: string;
    process: string;
    pid: number;
    destination: string;
    event_type: string;
    is_threat: boolean;
    threat_title: string;
  }>;
}

export function EndpointAgent() {
  const [filterType, setFilterType] = useState<"all" | "network" | "system" | "threats">("all");
  const [searchTerm, setSearchTerm] = useState("");

  const { data, isLoading, refetch, isFetching } = useQuery<AgentStatusData>({
    queryKey: ["agent-status"],
    queryFn: async () => {
      const res = await api.get("/agent/status");
      return res.data.data;
    },
    refetchInterval: 2000, // Poll every 2 seconds for live telemetry
  });

  // Filter events based on active tab and search
  const allEvents = data?.recent_events ?? [];
  const filteredEvents = allEvents.filter((ev) => {
    // Type filter
    if (filterType === "threats" && !ev.is_threat) return false;
    if (filterType === "network" && !ev.event_type?.toLowerCase().includes("network")) return false;
    if (
      filterType === "system" &&
      !ev.event_type?.toLowerCase().includes("system") &&
      !ev.event_type?.toLowerCase().includes("windows")
    ) {
      return false;
    }

    // Search filter
    if (searchTerm.trim()) {
      const q = searchTerm.toLowerCase();
      const match =
        ev.process?.toLowerCase().includes(q) ||
        ev.destination?.toLowerCase().includes(q) ||
        ev.event_type?.toLowerCase().includes(q) ||
        ev.threat_title?.toLowerCase().includes(q);
      if (!match) return false;
    }

    return true;
  });

  return (
    <PageFrame>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex flex-col justify-between gap-4 sm:flex-row sm:items-center">
          <div>
            <SectionTitle
              title="Endpoint Activity & System Logs"
              subtitle="Real-time collection feed streamed directly from CMD and PowerShell agents on your laptop."
            />
          </div>
          <div className="flex items-center gap-3">
            <span
              className={`inline-flex items-center gap-2 rounded-full px-3 py-1 text-xs font-semibold border ${
                data?.is_online
                  ? "border-emerald-500/30 bg-emerald-950/40 text-emerald-300"
                  : "border-amber-500/30 bg-amber-950/40 text-amber-300"
              }`}
            >
              <Radio size={14} className={data?.is_online ? "animate-pulse text-emerald-400" : ""} />
              {data?.is_online ? "AGENT CONNECTED & STREAMING" : "WAITING FOR AGENT LAUNCH"}
            </span>
            <button
              onClick={() => refetch()}
              disabled={isFetching}
              className="flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800/80 px-3 py-1.5 text-xs font-semibold text-slate-200 hover:bg-slate-700 transition"
            >
              <RefreshCw size={13} className={isFetching ? "animate-spin" : ""} />
              Sync
            </button>
          </div>
        </div>

        {/* Telemetry Overview KPI Cards */}
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <Card>
            <div className="flex items-center justify-between">
              <span className="text-xs font-medium text-slate-400">Monitored Laptop</span>
              <Laptop size={18} className="text-blue-400" />
            </div>
            <div className="mt-2 text-xl font-bold text-white truncate">{data?.hostname || "This Machine"}</div>
            <p className="mt-1 text-xs text-slate-400">{data?.os || "Windows Host"}</p>
          </Card>

          <Card>
            <div className="flex items-center justify-between">
              <span className="text-xs font-medium text-slate-400">Sensor IP Address</span>
              <Globe size={18} className="text-blue-400" />
            </div>
            <div className="mt-2 text-xl font-mono font-bold text-white">{data?.ip || "127.0.0.1"}</div>
            <p className="mt-1 text-xs text-slate-400">Endpoint Network Interface</p>
          </Card>

          <Card>
            <div className="flex items-center justify-between">
              <span className="text-xs font-medium text-slate-400">Live Events Captured</span>
              <Activity size={18} className="text-purple-400" />
            </div>
            <div className="mt-2 text-2xl font-bold text-purple-300">{data?.events_captured ?? 0}</div>
            <p className="mt-1 text-xs text-slate-400">Streamed from CMD / PowerShell</p>
          </Card>

          <Card>
            <div className="flex items-center justify-between">
              <span className="text-xs font-medium text-slate-400">Threats Intercepted</span>
              <ShieldAlert size={18} className="text-rose-400" />
            </div>
            <div className="mt-2 text-2xl font-bold text-rose-400">{data?.threats_detected ?? 0}</div>
            <p className="mt-1 text-xs text-slate-400">Hostile sockets, web, & events</p>
          </Card>
        </div>

        {/* Live Telemetry & System Logs Feed */}
        <Card className="p-0 overflow-hidden">
          {/* Feed Toolbar */}
          <div className="border-b border-line bg-slate-900/60 p-4">
            <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
              <div>
                <h3 className="text-sm font-bold text-white flex items-center gap-2">
                  <Activity size={16} className="text-blue-400" />
                  Live Host Activity & Event Logs
                </h3>
                <p className="text-xs text-slate-400">
                  Captures real-time outbound connections, executed processes, and Windows event logs.
                </p>
              </div>
              <span className="text-[11px] font-mono text-blue-400/80 animate-pulse">● Auto-syncing every 2s</span>
            </div>

            {/* Filters */}
            <div className="mt-3 flex flex-wrap items-center justify-between gap-3 pt-3 border-t border-slate-800/60">
              <div className="flex items-center gap-1.5">
                <button
                  onClick={() => setFilterType("all")}
                  className={`rounded-lg px-2.5 py-1 text-xs font-medium transition ${
                    filterType === "all"
                      ? "bg-blue-500/20 text-blue-300 border border-cyan-500/40"
                      : "text-slate-400 hover:text-white"
                  }`}
                >
                  All ({allEvents.length})
                </button>
                <button
                  onClick={() => setFilterType("network")}
                  className={`rounded-lg px-2.5 py-1 text-xs font-medium transition ${
                    filterType === "network"
                      ? "bg-blue-500/20 text-blue-300 border border-cyan-500/40"
                      : "text-slate-400 hover:text-white"
                  }`}
                >
                  Network Traffic
                </button>
                <button
                  onClick={() => setFilterType("system")}
                  className={`rounded-lg px-2.5 py-1 text-xs font-medium transition ${
                    filterType === "system"
                      ? "bg-indigo-500/20 text-indigo-300 border border-indigo-500/40"
                      : "text-slate-400 hover:text-white"
                  }`}
                >
                  System Logs
                </button>
                <button
                  onClick={() => setFilterType("threats")}
                  className={`rounded-lg px-2.5 py-1 text-xs font-medium transition ${
                    filterType === "threats"
                      ? "bg-rose-500/20 text-rose-300 border border-rose-500/40"
                      : "text-slate-400 hover:text-white"
                  }`}
                >
                  Threats Only ({allEvents.filter((e) => e.is_threat).length})
                </button>
              </div>

              <div className="relative">
                <Search size={13} className="absolute left-2.5 top-2.5 text-slate-500" />
                <input
                  type="text"
                  placeholder="Filter logs or process..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="rounded-lg border border-slate-800 bg-slate-950 py-1 pl-8 pr-3 text-xs text-white placeholder-slate-500 focus:border-cyan-500 focus:outline-none"
                />
              </div>
            </div>
          </div>

          {/* Table */}
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="border-b border-line bg-slate-900/40 text-slate-400 uppercase text-[10px] tracking-wider">
                <tr>
                  <th className="py-2.5 px-4">Time</th>
                  <th className="py-2.5 px-4">Process / Provider</th>
                  <th className="py-2.5 px-4">PID</th>
                  <th className="py-2.5 px-4">Destination / Event Details</th>
                  <th className="py-2.5 px-4">Log Category</th>
                  <th className="py-2.5 px-4 text-right">Detection Verdict</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line/30 font-mono">
                {isLoading ? (
                  <tr>
                    <td colSpan={6} className="py-8 text-center text-slate-400 font-sans">
                      Connecting to agent data stream...
                    </td>
                  </tr>
                ) : filteredEvents.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="py-10 text-center text-slate-400 font-sans">
                      <div className="flex flex-col items-center justify-center space-y-2">
                        <Terminal size={24} className="text-slate-600" />
                        <p className="text-sm text-slate-300 font-medium">No activity or logs captured yet</p>
                        <p className="text-xs text-slate-500 max-w-md">
                          Waiting for incoming telemetry stream from endpoint sensors.
                        </p>
                      </div>
                    </td>
                  </tr>
                ) : (
                  [...filteredEvents].reverse().map((ev, idx) => {
                    const isNet = ev.event_type?.toLowerCase().includes("network");
                    const isSys =
                      ev.event_type?.toLowerCase().includes("system") ||
                      ev.event_type?.toLowerCase().includes("windows");

                    return (
                      <tr
                        key={idx}
                        className={
                          ev.is_threat ? "bg-rose-950/20 border-l-2 border-l-rose-500" : "hover:bg-slate-800/30"
                        }
                      >
                        <td className="py-2.5 px-4 text-slate-400 whitespace-nowrap">{ev.time}</td>
                        <td className="py-2.5 px-4 font-sans font-medium text-white whitespace-nowrap">
                          {ev.process}
                        </td>
                        <td className="py-2.5 px-4 text-slate-400">{ev.pid || "-"}</td>
                        <td className="py-2.5 px-4 text-slate-300 max-w-md truncate" title={ev.destination}>
                          {ev.destination}
                        </td>
                        <td className="py-2.5 px-4 whitespace-nowrap">
                          <span
                            className={`rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase font-sans ${
                              isNet
                                ? "bg-blue-950 text-blue-300 border border-cyan-800/50"
                                : isSys
                                ? "bg-indigo-950 text-indigo-300 border border-indigo-800/50"
                                : "bg-slate-800 text-slate-400"
                            }`}
                          >
                            {ev.event_type}
                          </span>
                        </td>
                        <td className="py-2.5 px-4 text-right whitespace-nowrap">
                          {ev.is_threat ? (
                            <span className="inline-flex items-center gap-1 rounded-full bg-rose-500/20 px-2 py-0.5 text-[10px] font-semibold text-rose-300 font-sans">
                              <AlertOctagon size={12} /> {ev.threat_title || "THREAT DETECTED"}
                            </span>
                          ) : (
                            <span className="inline-flex items-center gap-1 text-[11px] text-emerald-400 font-sans">
                              <CheckCircle2 size={13} /> Clean / Recorded
                            </span>
                          )}
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        </Card>
      </div>
    </PageFrame>
  );
}
