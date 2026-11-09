import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { motion } from "framer-motion";
import { Activity, Bell, LockKeyhole, Mail, Shield, ShieldCheck } from "lucide-react";
import { api } from "../lib/api";

export function Login() {
  const navigate = useNavigate();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setError("");
    setLoading(true);
    try {
      const response = await api.post("/auth/login", { email, password });
      localStorage.setItem("cybershield_token", response.data.access_token);
      localStorage.setItem("cybershield_refresh_token", response.data.refresh_token);
      localStorage.setItem("cybershield_user", JSON.stringify(response.data.user));
      navigate("/");
    } catch {
      setError("Invalid credentials or access denied. Check your email and password.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="grid min-h-screen place-items-center bg-[#080C14] px-4 py-8">
      <motion.div
        initial={{ opacity: 0, y: 16 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.35, ease: "easeOut" }}
        className="w-full max-w-4xl overflow-hidden rounded-2xl border border-slate-800/90 bg-slate-900/95 shadow-2xl backdrop-blur-2xl md:grid md:grid-cols-[1.15fr_0.85fr]"
      >
        {/* Left Side: CyberShield Brand & Platform Highlights */}
        <div className="relative flex flex-col justify-between p-8 sm:p-10 border-b border-slate-800/80 md:border-b-0 md:border-r bg-gradient-to-br from-slate-900 via-slate-900/95 to-[#0B0F17]">
          <div>
            {/* Logo & Platform Name */}
            <div className="flex items-center gap-3">
              <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-blue-600/15 border border-blue-500/30 text-blue-400 shadow-sm shadow-blue-500/10">
                <Shield className="h-6 w-6 text-blue-400" />
              </div>
              <div>
                <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
                  CyberShield <span className="text-xs px-2 py-0.5 rounded-full bg-blue-600/20 text-blue-400 font-semibold border border-blue-500/30">XDR</span>
                </h1>
                <p className="text-xs font-medium text-slate-400">Enterprise Threat Detection & Incident Response</p>
              </div>
            </div>

            <div className="mt-10">
              <h2 className="text-3xl font-bold tracking-tight text-white leading-tight">
                Unified Security Intelligence & Autonomous Threat Defense.
              </h2>
              <p className="mt-3 text-sm text-slate-400 leading-relaxed">
                Real-time endpoint telemetry, host network monitoring, automated log analysis, and instant critical alerts.
              </p>
            </div>
          </div>

          {/* Core Feature Badges */}
          <div className="mt-8 space-y-3">
            <div className="flex items-center gap-3 rounded-xl border border-slate-800/80 bg-slate-950/60 p-3 text-xs text-slate-300">
              <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-blue-500/10 text-blue-400">
                <Activity size={16} />
              </div>
              <div>
                <div className="font-semibold text-white">Live Endpoint Telemetry</div>
                <div className="text-[11px] text-slate-400">Continuous inspection of outbound sockets and processes</div>
              </div>
            </div>

            <div className="flex items-center gap-3 rounded-xl border border-slate-800/80 bg-slate-950/60 p-3 text-xs text-slate-300">
              <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-amber-500/10 text-amber-400">
                <Bell size={16} />
              </div>
              <div>
                <div className="font-semibold text-white">Instant Critical Threat Alerts</div>
                <div className="text-[11px] text-slate-400">Automated SMS and Email notifications on compromise</div>
              </div>
            </div>
          </div>

          <div className="mt-8 pt-4 border-t border-slate-800/80 flex items-center justify-between text-[11px] text-slate-500">
            <span>CyberShield Defense Platform v2.4</span>
            <span className="flex items-center gap-1.5 text-emerald-400 font-medium">
              <span className="h-2 w-2 rounded-full bg-emerald-400 animate-pulse" />
              Engine Online
            </span>
          </div>
        </div>

        {/* Right Side: Professional Enterprise Sign In Form */}
        <div className="flex flex-col justify-center p-8 sm:p-10 bg-slate-900/60">
          <div className="mb-6">
            <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-blue-400">
              <LockKeyhole size={14} />
              <span>Authentication</span>
            </div>
            <h3 className="mt-1.5 text-xl font-bold text-white">Sign in to SOC Console</h3>
            <p className="mt-1 text-xs text-slate-400">Enter your credentials to access security workspace</p>
          </div>

          <form onSubmit={submit} className="space-y-4">
            <div>
              <label className="block text-xs font-semibold text-slate-300 mb-1.5">Email Address</label>
              <div className="relative">
                <Mail size={16} className="absolute left-3.5 top-3.5 text-slate-500" />
                <input
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="name@company.com"
                  type="email"
                  required
                  autoComplete="email"
                  className="h-11 w-full rounded-lg border border-slate-700 bg-slate-950/80 pl-10 pr-3.5 text-sm text-white placeholder-slate-500 focus:border-blue-500 focus:ring-1 focus:ring-blue-500 focus:outline-none transition"
                />
              </div>
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-300 mb-1.5">Password</label>
              <div className="relative">
                <LockKeyhole size={16} className="absolute left-3.5 top-3.5 text-slate-500" />
                <input
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••••••"
                  type="password"
                  required
                  autoComplete="current-password"
                  className="h-11 w-full rounded-lg border border-slate-700 bg-slate-950/80 pl-10 pr-3.5 text-sm text-white placeholder-slate-500 focus:border-blue-500 focus:ring-1 focus:ring-blue-500 focus:outline-none transition"
                />
              </div>
            </div>

            {error ? (
              <div className="rounded-lg border border-rose-500/30 bg-rose-950/40 p-3 text-xs text-rose-300 font-medium">
                {error}
              </div>
            ) : null}

            <button
              type="submit"
              disabled={loading}
              className="mt-2 flex h-11 w-full items-center justify-center gap-2 rounded-lg bg-blue-600 text-sm font-semibold text-white shadow-md shadow-blue-600/20 hover:bg-blue-500 focus:outline-none focus:ring-2 focus:ring-blue-500/50 transition disabled:opacity-50"
            >
              {loading ? "Authenticating..." : "Open Security Workspace"}
            </button>

            <div className="pt-2 text-center">
              <p className="text-[11px] text-slate-500 leading-relaxed">
                Authorized SOC access only. All sessions, telemetry queries, and authentication attempts are audited.
              </p>
            </div>
          </form>
        </div>
      </motion.div>
    </div>
  );
}
