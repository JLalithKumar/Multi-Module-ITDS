import { useQuery } from "@tanstack/react-query";
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  Cpu,
  HardDrive,
  Network,
  RefreshCw,
  Server,
  Zap,
} from "lucide-react";
import { api } from "../lib/api";
import { Card, PageFrame, SectionTitle } from "../components/ui";

interface SystemResources {
  cpu_percent: number;
  cpu_count: number;
  memory: {
    total_gb: number;
    used_gb: number;
    percent: number;
  };
  disk: {
    total_gb: number;
    used_gb: number;
    percent: number;
  };
  network_io: {
    bytes_sent_mb: number;
    bytes_recv_mb: number;
  };
  top_processes: Array<{
    pid: number;
    name: string;
    cpu_percent: number;
    memory_percent: number;
    status: string;
  }>;
  recommendations: Array<{
    type: "optimal" | "warning" | "critical";
    message: string;
  }>;
}

export function SystemMonitor() {
  const { data, isLoading, refetch, isFetching } = useQuery<SystemResources>({
    queryKey: ["system-resources"],
    queryFn: async () => {
      const res = await api.get("/system/resources");
      return res.data.data;
    },
    refetchInterval: 5000, // Poll every 5s for live telemetry
  });

  return (
    <PageFrame>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex flex-col justify-between gap-4 sm:flex-row sm:items-center">
          <div>
            <SectionTitle
              title="Host Telemetry & Resource Optimization"
              subtitle="Live hardware performance telemetry, active process monitoring, and real-time system optimization."
            />
          </div>
          <button
            onClick={() => refetch()}
            disabled={isFetching}
            className="flex items-center gap-2 rounded-lg border border-slate-700 bg-slate-800/80 px-3.5 py-2 text-xs font-semibold text-slate-200 hover:bg-slate-700 transition"
          >
            <RefreshCw size={14} className={isFetching ? "animate-spin" : ""} />
            Poll Telemetry
          </button>
        </div>

        {/* Live Gauges */}
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {/* CPU Card */}
          <Card>
            <div className="flex items-center justify-between">
              <span className="text-xs font-medium text-slate-400">CPU Load</span>
              <Cpu size={18} className="text-cyan-400" />
            </div>
            <div className="mt-2 flex items-baseline gap-2">
              <span className="text-3xl font-extrabold text-white">{data?.cpu_percent ?? 0}%</span>
              <span className="text-xs text-slate-400">{data?.cpu_count ?? 1} Cores</span>
            </div>
            <div className="mt-3 h-2 w-full rounded-full bg-slate-800 overflow-hidden">
              <div
                className={`h-full transition-all duration-500 ${
                  (data?.cpu_percent || 0) > 80
                    ? "bg-rose-500"
                    : (data?.cpu_percent || 0) > 60
                    ? "bg-amber-500"
                    : "bg-cyan-500"
                }`}
                style={{ width: `${Math.min(100, data?.cpu_percent || 0)}%` }}
              />
            </div>
          </Card>

          {/* Memory Card */}
          <Card>
            <div className="flex items-center justify-between">
              <span className="text-xs font-medium text-slate-400">RAM Utilization</span>
              <Server size={18} className="text-purple-400" />
            </div>
            <div className="mt-2 flex items-baseline gap-2">
              <span className="text-3xl font-extrabold text-white">{data?.memory.percent ?? 0}%</span>
              <span className="text-xs text-slate-400">
                {data?.memory.used_gb} / {data?.memory.total_gb} GB
              </span>
            </div>
            <div className="mt-3 h-2 w-full rounded-full bg-slate-800 overflow-hidden">
              <div
                className={`h-full transition-all duration-500 ${
                  (data?.memory.percent || 0) > 85 ? "bg-rose-500" : "bg-purple-500"
                }`}
                style={{ width: `${data?.memory.percent || 0}%` }}
              />
            </div>
          </Card>

          {/* Disk Card */}
          <Card>
            <div className="flex items-center justify-between">
              <span className="text-xs font-medium text-slate-400">Disk Capacity</span>
              <HardDrive size={18} className="text-emerald-400" />
            </div>
            <div className="mt-2 flex items-baseline gap-2">
              <span className="text-3xl font-extrabold text-white">{data?.disk.percent ?? 0}%</span>
              <span className="text-xs text-slate-400">
                {data?.disk.used_gb} / {data?.disk.total_gb} GB
              </span>
            </div>
            <div className="mt-3 h-2 w-full rounded-full bg-slate-800 overflow-hidden">
              <div
                className="h-full bg-emerald-500 transition-all duration-500"
                style={{ width: `${data?.disk.percent || 0}%` }}
              />
            </div>
          </Card>

          {/* Network I/O */}
          <Card>
            <div className="flex items-center justify-between">
              <span className="text-xs font-medium text-slate-400">Network Telemetry</span>
              <Network size={18} className="text-blue-400" />
            </div>
            <div className="mt-2 space-y-1">
              <div className="flex justify-between text-xs text-slate-300">
                <span>Sent:</span>
                <span className="font-mono font-bold text-white">{data?.network_io.bytes_sent_mb} MB</span>
              </div>
              <div className="flex justify-between text-xs text-slate-300">
                <span>Received:</span>
                <span className="font-mono font-bold text-white">{data?.network_io.bytes_recv_mb} MB</span>
              </div>
            </div>
            <div className="mt-3 text-[10px] text-cyan-400/80 flex items-center gap-1 font-mono">
              <Activity size={12} className="animate-pulse" /> Live Host Socket Connected
            </div>
          </Card>
        </div>

        {/* Resource Optimization Advice */}
        <div className="rounded-xl border border-line bg-card p-5">
          <h3 className="text-sm font-bold text-white flex items-center gap-2 mb-3">
            <Zap size={16} className="text-cyan-400" />
            Resource Optimization Advisor
          </h3>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            {data?.recommendations?.map((rec, idx) => (
              <div
                key={idx}
                className={`flex items-start gap-3 rounded-lg border p-3 text-xs ${
                  rec.type === "critical"
                    ? "border-rose-500/30 bg-rose-950/20 text-rose-300"
                    : rec.type === "warning"
                    ? "border-amber-500/30 bg-amber-950/20 text-amber-300"
                    : "border-emerald-500/30 bg-emerald-950/20 text-emerald-300"
                }`}
              >
                {rec.type === "optimal" ? (
                  <CheckCircle2 size={16} className="shrink-0 mt-0.5 text-emerald-400" />
                ) : (
                  <AlertTriangle size={16} className="shrink-0 mt-0.5" />
                )}
                <span>{rec.message}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Top Active Processes */}
        <Card className="p-0 overflow-hidden">
          <div className="border-b border-line bg-slate-900/50 p-4">
            <h3 className="text-sm font-bold text-white">Top Active Host Processes (Laptop Telemetry)</h3>
            <p className="text-xs text-slate-400">Processes currently monitored for anomalous CPU and memory consumption.</p>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="border-b border-line bg-slate-900/40 text-slate-400 uppercase text-[10px] tracking-wider">
                <tr>
                  <th className="py-2.5 px-4">PID</th>
                  <th className="py-2.5 px-4">Process Name</th>
                  <th className="py-2.5 px-4">CPU %</th>
                  <th className="py-2.5 px-4">Memory %</th>
                  <th className="py-2.5 px-4">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line/30 font-mono">
                {isLoading ? (
                  <tr>
                    <td colSpan={5} className="py-6 text-center text-slate-400 font-sans">
                      Sampling host processes...
                    </td>
                  </tr>
                ) : (
                  data?.top_processes.map((proc) => (
                    <tr key={proc.pid} className="hover:bg-slate-800/30">
                      <td className="py-2.5 px-4 text-cyan-400">{proc.pid}</td>
                      <td className="py-2.5 px-4 font-sans font-medium text-white">{proc.name}</td>
                      <td className="py-2.5 px-4">
                        <span
                          className={`font-semibold ${
                            proc.cpu_percent > 30 ? "text-rose-400" : "text-slate-300"
                          }`}
                        >
                          {proc.cpu_percent}%
                        </span>
                      </td>
                      <td className="py-2.5 px-4 text-slate-300">{proc.memory_percent}%</td>
                      <td className="py-2.5 px-4">
                        <span className="rounded bg-slate-800 px-1.5 py-0.5 text-[10px] uppercase font-sans text-slate-400">
                          {proc.status}
                        </span>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </Card>
      </div>
    </PageFrame>
  );
}
