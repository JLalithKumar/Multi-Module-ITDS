import { motion } from "framer-motion";
import type { ReactNode } from "react";
import { cn, severityClass } from "../lib/utils";

export function Card({ className, children }: { className?: string; children: ReactNode }) {
  return (
    <div className={cn("rounded-xl border border-slate-800 bg-slate-900/80 p-5 shadow-sm transition hover:border-slate-700/80", className)}>
      {children}
    </div>
  );
}

export function Button(props: React.ButtonHTMLAttributes<HTMLButtonElement>) {
  return (
    <button
      {...props}
      className={cn(
        "inline-flex h-10 items-center justify-center gap-2 rounded-lg bg-blue-600 px-4 text-sm font-semibold text-white shadow-sm transition hover:bg-blue-500 focus:outline-none focus:ring-2 focus:ring-blue-500/50 disabled:cursor-not-allowed disabled:opacity-50",
        props.className,
      )}
    />
  );
}

export function Input(props: React.InputHTMLAttributes<HTMLInputElement>) {
  return (
    <input
      {...props}
      className={cn(
        "h-10 w-full rounded-lg border border-slate-700 bg-slate-950/80 px-3 text-sm text-slate-100 placeholder:text-slate-500 focus:border-blue-500 focus:ring-1 focus:ring-blue-500 focus:outline-none transition",
        props.className,
      )}
    />
  );
}

export function Textarea(props: React.TextareaHTMLAttributes<HTMLTextAreaElement>) {
  return (
    <textarea
      {...props}
      className={cn(
        "min-h-32 w-full rounded-lg border border-slate-700 bg-slate-950/80 p-3 text-sm text-slate-100 placeholder:text-slate-500 focus:border-blue-500 focus:ring-1 focus:ring-blue-500 focus:outline-none transition",
        props.className,
      )}
    />
  );
}

export function Badge({ severity, children }: { severity?: string; children: ReactNode }) {
  const sev = severity?.toLowerCase();
  let color = "bg-slate-800 text-slate-300 border-slate-700";
  if (sev === "critical") color = "bg-rose-950/50 text-rose-300 border-rose-800/60";
  else if (sev === "high") color = "bg-amber-950/50 text-amber-300 border-amber-800/60";
  else if (sev === "medium" || sev === "info") color = "bg-blue-950/50 text-blue-300 border-blue-800/60";
  else if (sev === "low") color = "bg-emerald-950/50 text-emerald-300 border-emerald-800/60";

  return (
    <span className={cn("inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-semibold capitalize tracking-wide", color)}>
      {children}
    </span>
  );
}

export function Metric({ label, value, accent = "cyan" }: { label: string; value: string | number; accent?: "cyan" | "mint" | "amber" | "red" }) {
  const color = { cyan: "text-blue-400", mint: "text-emerald-400", amber: "text-amber-400", red: "text-rose-400" }[accent];
  const barBg = { cyan: "bg-blue-500", mint: "bg-emerald-500", amber: "bg-amber-500", red: "bg-rose-500" }[accent];

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="rounded-xl border border-slate-800 bg-slate-900/80 p-5 shadow-sm">
      <div className="flex items-center justify-between gap-3">
        <div className="text-xs font-bold uppercase tracking-wider text-slate-400">{label}</div>
        <span className={cn("h-2 w-2 rounded-full", barBg)} />
      </div>
      <div className={cn("mt-3 text-3xl font-bold tabular-nums tracking-tight", color)}>{value}</div>
      <div className="mt-4 h-1 overflow-hidden rounded-full bg-slate-800">
        <motion.div
          initial={{ width: "12%" }}
          animate={{ width: `${Math.max(18, Math.min(100, Number(value) || 42))}%` }}
          transition={{ duration: 0.8, ease: "easeOut" }}
          className={cn("h-full rounded-full", barBg)}
        />
      </div>
    </motion.div>
  );
}

export function SectionTitle({ title, subtitle }: { title: string; subtitle?: string }) {
  return (
    <div>
      <h2 className="text-xl font-bold tracking-tight text-white">{title}</h2>
      {subtitle ? <p className="mt-1 text-sm text-slate-400">{subtitle}</p> : null}
    </div>
  );
}

export function PageFrame({ children }: { children: ReactNode }) {
  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -8 }} transition={{ duration: 0.25, ease: "easeOut" }}>
      {children}
    </motion.div>
  );
}

export function SkeletonCard() {
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5 space-y-4">
      <div className="skeleton h-5 w-28 rounded" />
      <div className="skeleton mt-4 h-8 w-44 rounded" />
      <div className="skeleton mt-4 h-16 rounded" />
    </div>
  );
}

export function StatusPill({ label }: { label: string }) {
  return (
    <div className="status-pill flex items-center gap-2 rounded-full border border-emerald-500/30 bg-emerald-950/40 px-3.5 py-1.5 text-xs font-semibold text-emerald-300">
      <span className="status-pulse h-2 w-2 rounded-full bg-emerald-400" />
      {label}
    </div>
  );
}
