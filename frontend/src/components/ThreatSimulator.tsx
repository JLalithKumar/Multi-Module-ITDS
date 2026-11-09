import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, Database, Play, RefreshCw, ShieldAlert, Terminal, Trash2, Zap } from "lucide-react";
import { api } from "../lib/api";
import { notify } from "../lib/feedback";

export function ThreatSimulator() {
  const queryClient = useQueryClient();
  const [activeTab, setActiveTab] = useState(false);

  const simulateMutation = useMutation({
    mutationFn: async (threat_type: string) => {
      const res = await api.post("/system/simulate-threat", { threat_type });
      return res.data;
    },
    onSuccess: (data) => {
      notify(`Threat detected! "${data.data?.title}" recorded with severity: ${data.data?.severity?.toUpperCase()}`);
      queryClient.invalidateQueries({ queryKey: ["dashboard"] });
      queryClient.invalidateQueries({ queryKey: ["detection"] });
      queryClient.invalidateQueries({ queryKey: ["logs"] });
      queryClient.invalidateQueries({ queryKey: ["network"] });
      queryClient.invalidateQueries({ queryKey: ["incidents"] });
      queryClient.invalidateQueries({ queryKey: ["notifications"] });
      queryClient.invalidateQueries({ queryKey: ["users"] });
    },
    onError: () => {
      notify("Failed to dispatch threat simulation.");
    },
  });

  const purgeMutation = useMutation({
    mutationFn: async () => {
      const res = await api.post("/system/purge-data");
      return res.data;
    },
    onSuccess: () => {
      notify("All telemetry and demo records successfully purged. Clean slate active.");
      queryClient.invalidateQueries({ queryKey: ["dashboard"] });
      queryClient.invalidateQueries({ queryKey: ["detection"] });
      queryClient.invalidateQueries({ queryKey: ["logs"] });
      queryClient.invalidateQueries({ queryKey: ["network"] });
      queryClient.invalidateQueries({ queryKey: ["incidents"] });
      queryClient.invalidateQueries({ queryKey: ["notifications"] });
    },
    onError: () => {
      notify("Failed to purge data. Make sure you have admin permissions.");
    },
  });

  return (
    <div className="mb-6 rounded-xl border border-cyan-500/20 bg-gradient-to-r from-cyan-950/40 via-slate-900/60 to-purple-950/40 p-4 shadow-xl backdrop-blur-md">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-cyan-500/20 text-cyan-400">
            <Zap size={22} className="animate-pulse" />
          </div>
          <div>
            <h2 className="text-base font-bold text-white flex items-center gap-2">
              Live Threat Demo & Attack Simulator
              <span className="rounded-full bg-cyan-500/20 px-2 py-0.5 text-xs font-semibold text-cyan-300">Laptop Demo Ready</span>
            </h2>
            <p className="text-xs text-slate-400">
              Trigger real threat vectors to prove detection across log analysis, network probes, and employee risk scores.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => setActiveTab(!activeTab)}
            className="flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800/80 px-3 py-1.5 text-xs font-medium text-slate-200 hover:bg-slate-700 transition"
          >
            {activeTab ? "Hide Controls" : "Launch Attack Vectors"}
          </button>
          <button
            onClick={() => {
              if (confirm("Are you sure you want to purge all existing alerts, logs, and incidents to start with a fresh clean state?")) {
                purgeMutation.mutate();
              }
            }}
            disabled={purgeMutation.isPending}
            className="flex items-center gap-1.5 rounded-lg border border-rose-500/30 bg-rose-500/10 px-3 py-1.5 text-xs font-medium text-rose-400 hover:bg-rose-500/20 transition disabled:opacity-50"
            title="Wipe mock/demo data and start with 0 records"
          >
            <Trash2 size={14} />
            {purgeMutation.isPending ? "Purging..." : "Clear All Telemetry"}
          </button>
        </div>
      </div>

      {activeTab && (
        <div className="mt-4 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-2.5 pt-3 border-t border-slate-800">
          <button
            onClick={() => simulateMutation.mutate("sql-injection")}
            disabled={simulateMutation.isPending}
            className="flex flex-col items-start p-3 rounded-lg border border-red-500/30 bg-red-950/20 hover:bg-red-900/30 text-left transition group"
          >
            <div className="flex items-center gap-2 text-xs font-semibold text-red-400">
              <ShieldAlert size={14} /> SQL Injection Probe
            </div>
            <p className="mt-1 text-[11px] text-slate-400 line-clamp-2">
              Injects UNION SELECT attack into web application logs.
            </p>
            <span className="mt-2 text-[10px] uppercase font-mono tracking-wider text-red-300/80 bg-red-500/10 px-1.5 py-0.5 rounded">Critical Detection</span>
          </button>

          <button
            onClick={() => simulateMutation.mutate("brute-force")}
            disabled={simulateMutation.isPending}
            className="flex flex-col items-start p-3 rounded-lg border border-amber-500/30 bg-amber-950/20 hover:bg-amber-900/30 text-left transition group"
          >
            <div className="flex items-center gap-2 text-xs font-semibold text-amber-400">
              <AlertTriangle size={14} /> Brute Force Attack
            </div>
            <p className="mt-1 text-[11px] text-slate-400 line-clamp-2">
              Simulates password spray against employee credentials.
            </p>
            <span className="mt-2 text-[10px] uppercase font-mono tracking-wider text-amber-300/80 bg-amber-500/10 px-1.5 py-0.5 rounded">High Severity</span>
          </button>

          <button
            onClick={() => simulateMutation.mutate("ransomware")}
            disabled={simulateMutation.isPending}
            className="flex flex-col items-start p-3 rounded-lg border border-purple-500/30 bg-purple-950/20 hover:bg-purple-900/30 text-left transition group"
          >
            <div className="flex items-center gap-2 text-xs font-semibold text-purple-400">
              <Terminal size={14} /> Ransomware Indicator
            </div>
            <p className="mt-1 text-[11px] text-slate-400 line-clamp-2">
              Executes vssadmin shadow copy deletion simulation.
            </p>
            <span className="mt-2 text-[10px] uppercase font-mono tracking-wider text-purple-300/80 bg-purple-500/10 px-1.5 py-0.5 rounded">Auto Incident</span>
          </button>

          <button
            onClick={() => simulateMutation.mutate("port-scan")}
            disabled={simulateMutation.isPending}
            className="flex flex-col items-start p-3 rounded-lg border border-blue-500/30 bg-blue-950/20 hover:bg-blue-900/30 text-left transition group"
          >
            <div className="flex items-center gap-2 text-xs font-semibold text-blue-400">
              <Play size={14} /> TCP Port Scan
            </div>
            <p className="mt-1 text-[11px] text-slate-400 line-clamp-2">
              Rapid multi-port reconnaissance probe from external IP.
            </p>
            <span className="mt-2 text-[10px] uppercase font-mono tracking-wider text-blue-300/80 bg-blue-500/10 px-1.5 py-0.5 rounded">Network Recon</span>
          </button>

          <button
            onClick={() => simulateMutation.mutate("dns-tunnel")}
            disabled={simulateMutation.isPending}
            className="flex flex-col items-start p-3 rounded-lg border border-emerald-500/30 bg-emerald-950/20 hover:bg-emerald-900/30 text-left transition group"
          >
            <div className="flex items-center gap-2 text-xs font-semibold text-emerald-400">
              <Database size={14} /> DNS Data Exfiltration
            </div>
            <p className="mt-1 text-[11px] text-slate-400 line-clamp-2">
              High-entropy base64 query beaconing to rogue C2 server.
            </p>
            <span className="mt-2 text-[10px] uppercase font-mono tracking-wider text-emerald-300/80 bg-emerald-500/10 px-1.5 py-0.5 rounded">Exfiltration</span>
          </button>
        </div>
      )}
    </div>
  );
}
