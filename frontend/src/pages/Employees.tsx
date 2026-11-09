import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  AlertCircle,
  AlertTriangle,
  CheckCircle,
  KeyRound,
  Lock,
  LogOut,
  Plus,
  RefreshCw,
  Search,
  Shield,
  ShieldAlert,
  Unlock,
  UserCheck,
  UserPlus,
  Users,
  UserX,
  X,
} from "lucide-react";
import { api } from "../lib/api";
import { notify } from "../lib/feedback";
import { Badge, Card, PageFrame, SectionTitle } from "../components/ui";

interface Employee {
  id: number;
  email: string;
  full_name: string;
  role: string;
  is_active: boolean;
  is_verified: boolean;
  mfa_enabled: boolean;
  failed_login_count: number;
  is_locked: boolean;
  locked_until: string | null;
  alert_count: number;
  critical_alert_count: number;
  risk_level: "low" | "medium" | "high" | "critical";
  created_at: string;
}

export function Employees() {
  const queryClient = useQueryClient();
  const [search, setSearch] = useState("");
  const [roleFilter, setRoleFilter] = useState("all");
  const [showAddModal, setShowAddModal] = useState(false);
  const [selectedEmployeeId, setSelectedEmployeeId] = useState<number | null>(null);

  // Form states for Add Employee
  const [newName, setNewName] = useState("");
  const [newEmail, setNewEmail] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [newRole, setNewRole] = useState("SOC Analyst");

  // Fetch employees
  const { data: employees = [], isLoading, refetch, isFetching } = useQuery<Employee[]>({
    queryKey: ["users"],
    queryFn: async () => {
      const res = await api.get("/users");
      return res.data.data;
    },
  });

  // Fetch single employee activity
  const { data: activityData, isLoading: activityLoading } = useQuery({
    queryKey: ["user-activity", selectedEmployeeId],
    queryFn: async () => {
      if (!selectedEmployeeId) return null;
      const res = await api.get(`/users/${selectedEmployeeId}/activity`);
      return res.data.data;
    },
    enabled: !!selectedEmployeeId,
  });

  // Add Employee mutation
  const addMutation = useMutation({
    mutationFn: async () => {
      const res = await api.post("/users", {
        full_name: newName,
        email: newEmail,
        password: newPassword,
        role_name: newRole,
      });
      return res.data;
    },
    onSuccess: () => {
      notify("Employee created successfully!");
      setShowAddModal(false);
      setNewName("");
      setNewEmail("");
      setNewPassword("");
      queryClient.invalidateQueries({ queryKey: ["users"] });
    },
    onError: (err: any) => {
      notify(err.response?.data?.detail || "Failed to create employee.");
    },
  });

  // Lock / Unlock mutation
  const toggleLockMutation = useMutation({
    mutationFn: async (id: number) => {
      const res = await api.post(`/users/${id}/toggle-lock`);
      return res.data;
    },
    onSuccess: (data) => {
      notify(data.data?.is_locked ? "Account locked successfully." : "Account unlocked.");
      queryClient.invalidateQueries({ queryKey: ["users"] });
    },
    onError: () => notify("Failed to update lock state."),
  });

  // Revoke Sessions mutation
  const revokeSessionsMutation = useMutation({
    mutationFn: async (id: number) => {
      const res = await api.post(`/users/${id}/revoke-sessions`);
      return res.data;
    },
    onSuccess: (data) => {
      notify(`Revoked ${data.data?.revoked_sessions ?? 0} active user sessions.`);
      queryClient.invalidateQueries({ queryKey: ["users"] });
    },
    onError: () => notify("Failed to revoke user sessions."),
  });

  // Filter employees
  const filtered = employees.filter((emp) => {
    const matchesSearch =
      emp.full_name.toLowerCase().includes(search.toLowerCase()) ||
      emp.email.toLowerCase().includes(search.toLowerCase());
    const matchesRole = roleFilter === "all" || emp.role === roleFilter;
    return matchesSearch && matchesRole;
  });

  const totalEmployees = employees.length;
  const lockedCount = employees.filter((e) => e.is_locked).length;
  const highRiskCount = employees.filter((e) => e.risk_level === "high" || e.risk_level === "critical").length;
  const mfaCount = employees.filter((e) => e.mfa_enabled).length;

  return (
    <PageFrame>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex flex-col justify-between gap-4 sm:flex-row sm:items-center">
          <div>
            <SectionTitle
              title="Employee Security & User Management"
              subtitle="Monitor insider activities, manage security access levels, and enforce incident response actions across staff."
            />
          </div>
          <div className="flex items-center gap-3">
            <button
              onClick={() => refetch()}
              disabled={isFetching}
              className="flex items-center gap-2 rounded-lg border border-slate-700 bg-slate-800/80 px-3.5 py-2 text-xs font-semibold text-slate-200 hover:bg-slate-700 transition"
            >
              <RefreshCw size={14} className={isFetching ? "animate-spin" : ""} />
              Refresh
            </button>
            <button
              onClick={() => setShowAddModal(true)}
              className="flex items-center gap-2 rounded-lg bg-cyan-600 px-4 py-2 text-xs font-semibold text-white shadow-lg shadow-cyan-900/30 hover:bg-cyan-500 transition"
            >
              <UserPlus size={15} />
              Add Employee
            </button>
          </div>
        </div>

        {/* KPI Cards */}
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <Card>
            <div className="flex items-center justify-between">
              <span className="text-xs font-medium text-slate-400">Total Staff</span>
              <Users size={18} className="text-cyan-400" />
            </div>
            <div className="mt-2 text-2xl font-bold text-white">{totalEmployees}</div>
            <p className="mt-1 text-xs text-slate-400">Enrolled company accounts</p>
          </Card>

          <Card>
            <div className="flex items-center justify-between">
              <span className="text-xs font-medium text-slate-400">High Risk Employees</span>
              <ShieldAlert size={18} className="text-rose-400" />
            </div>
            <div className="mt-2 text-2xl font-bold text-rose-400">{highRiskCount}</div>
            <p className="mt-1 text-xs text-slate-400">Linked to critical alerts/brute force</p>
          </Card>

          <Card>
            <div className="flex items-center justify-between">
              <span className="text-xs font-medium text-slate-400">Locked Accounts</span>
              <Lock size={18} className="text-amber-400" />
            </div>
            <div className="mt-2 text-2xl font-bold text-amber-400">{lockedCount}</div>
            <p className="mt-1 text-xs text-slate-400">Suspended or brute-force locked</p>
          </Card>

          <Card>
            <div className="flex items-center justify-between">
              <span className="text-xs font-medium text-slate-400">MFA Protected</span>
              <Shield size={18} className="text-emerald-400" />
            </div>
            <div className="mt-2 text-2xl font-bold text-emerald-400">{mfaCount}</div>
            <p className="mt-1 text-xs text-slate-400">{totalEmployees ? Math.round((mfaCount / totalEmployees) * 100) : 0}% compliance</p>
          </Card>
        </div>

        {/* Filter and Search Bar */}
        <div className="flex flex-col sm:flex-row items-center justify-between gap-4 rounded-xl border border-line bg-card p-4">
          <div className="relative w-full sm:w-80">
            <Search className="absolute left-3 top-2.5 h-4 w-4 text-slate-400" />
            <input
              type="text"
              placeholder="Search by name or email..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full rounded-lg border border-slate-700 bg-slate-900/60 pl-9 pr-4 py-2 text-xs text-white placeholder-slate-500 focus:border-cyan-500 focus:outline-none"
            />
          </div>

          <div className="flex items-center gap-3 w-full sm:w-auto">
            <span className="text-xs text-slate-400 whitespace-nowrap">Role Filter:</span>
            <select
              value={roleFilter}
              onChange={(e) => setRoleFilter(e.target.value)}
              className="rounded-lg border border-slate-700 bg-slate-900/60 px-3 py-2 text-xs text-white focus:border-cyan-500 focus:outline-none"
            >
              <option value="all">All Roles</option>
              <option value="Admin">Admin</option>
              <option value="SOC Manager">SOC Manager</option>
              <option value="Senior Security Analyst">Senior Analyst</option>
              <option value="SOC Analyst">SOC Analyst</option>
              <option value="Malware Analyst">Malware Analyst</option>
              <option value="Vulnerability Analyst">Vulnerability Analyst</option>
              <option value="Viewer">Viewer</option>
            </select>
          </div>
        </div>

        {/* Employee Table */}
        <Card className="overflow-hidden p-0">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="border-b border-line bg-slate-900/50 text-slate-400 uppercase tracking-wider text-[11px]">
                <tr>
                  <th className="py-3 px-4">Employee</th>
                  <th className="py-3 px-4">Role</th>
                  <th className="py-3 px-4">Security Risk</th>
                  <th className="py-3 px-4">Status</th>
                  <th className="py-3 px-4">Failed Logins</th>
                  <th className="py-3 px-4">MFA</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line/40">
                {isLoading ? (
                  <tr>
                    <td colSpan={7} className="py-8 text-center text-slate-400">
                      Loading staff roster...
                    </td>
                  </tr>
                ) : filtered.length === 0 ? (
                  <tr>
                    <td colSpan={7} className="py-8 text-center text-slate-400">
                      No employees match your criteria.
                    </td>
                  </tr>
                ) : (
                  filtered.map((emp) => (
                    <tr key={emp.id} className="hover:bg-slate-800/40 transition">
                      <td className="py-3 px-4">
                        <div className="flex items-center gap-3">
                          <div className="flex h-8 w-8 items-center justify-center rounded-full bg-cyan-900/40 border border-cyan-500/30 text-xs font-semibold text-cyan-300">
                            {emp.full_name.charAt(0).toUpperCase()}
                          </div>
                          <div>
                            <div className="font-semibold text-white">{emp.full_name}</div>
                            <div className="text-[11px] text-slate-400">{emp.email}</div>
                          </div>
                        </div>
                      </td>

                      <td className="py-3 px-4">
                        <span className="inline-flex items-center rounded-md bg-slate-800 px-2 py-1 text-[11px] font-medium text-slate-300 border border-slate-700">
                          {emp.role}
                        </span>
                      </td>

                      <td className="py-3 px-4">
                        <Badge
                          severity={
                            emp.risk_level === "critical"
                              ? "critical"
                              : emp.risk_level === "high"
                              ? "high"
                              : emp.risk_level === "medium"
                              ? "medium"
                              : "low"
                          }
                        >
                          {emp.risk_level.toUpperCase()}
                        </Badge>
                      </td>

                      <td className="py-3 px-4">
                        {emp.is_locked ? (
                          <span className="inline-flex items-center gap-1.5 text-rose-400 font-medium">
                            <Lock size={12} /> Locked
                          </span>
                        ) : emp.is_active ? (
                          <span className="inline-flex items-center gap-1.5 text-emerald-400 font-medium">
                            <CheckCircle size={12} /> Active
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1.5 text-slate-500 font-medium">
                            <UserX size={12} /> Inactive
                          </span>
                        )}
                      </td>

                      <td className="py-3 px-4 font-mono">
                        {emp.failed_login_count > 0 ? (
                          <span className="text-amber-400 font-semibold">{emp.failed_login_count}</span>
                        ) : (
                          <span className="text-slate-500">0</span>
                        )}
                      </td>

                      <td className="py-3 px-4">
                        {emp.mfa_enabled ? (
                          <span className="text-emerald-400">Enabled</span>
                        ) : (
                          <span className="text-slate-500">Disabled</span>
                        )}
                      </td>

                      <td className="py-3 px-4 text-right">
                        <div className="flex items-center justify-end gap-1.5">
                          <button
                            onClick={() => setSelectedEmployeeId(emp.id)}
                            className="rounded p-1.5 text-slate-400 hover:bg-slate-700 hover:text-white transition"
                            title="View Employee Security Activity"
                          >
                            <AlertCircle size={15} />
                          </button>
                          <button
                            onClick={() => toggleLockMutation.mutate(emp.id)}
                            className={`rounded p-1.5 transition ${
                              emp.is_locked
                                ? "text-amber-400 hover:bg-amber-950/40"
                                : "text-slate-400 hover:bg-slate-700 hover:text-white"
                            }`}
                            title={emp.is_locked ? "Unlock Account" : "Lock Account"}
                          >
                            {emp.is_locked ? <Unlock size={15} /> : <Lock size={15} />}
                          </button>
                          <button
                            onClick={() => revokeSessionsMutation.mutate(emp.id)}
                            className="rounded p-1.5 text-slate-400 hover:bg-rose-950/40 hover:text-rose-300 transition"
                            title="Emergency: Revoke All Active Sessions"
                          >
                            <LogOut size={15} />
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </Card>

        {/* Add Employee Modal */}
        {showAddModal && (
          <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
            <div className="w-full max-w-md rounded-xl border border-line bg-slate-900 p-6 shadow-2xl">
              <div className="flex items-center justify-between pb-4 border-b border-line">
                <h3 className="text-lg font-bold text-white flex items-center gap-2">
                  <UserPlus size={18} className="text-cyan-400" /> Add New Employee
                </h3>
                <button
                  onClick={() => setShowAddModal(false)}
                  className="rounded-lg p-1 text-slate-400 hover:text-white"
                >
                  <X size={18} />
                </button>
              </div>

              <form
                onSubmit={(e) => {
                  e.preventDefault();
                  addMutation.mutate();
                }}
                className="mt-4 space-y-4 text-xs"
              >
                <div>
                  <label className="block font-medium text-slate-300 mb-1">Full Name</label>
                  <input
                    type="text"
                    required
                    placeholder="e.g. Alex Johnson"
                    value={newName}
                    onChange={(e) => setNewName(e.target.value)}
                    className="w-full rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-white placeholder-slate-500 focus:border-cyan-500 focus:outline-none"
                  />
                </div>

                <div>
                  <label className="block font-medium text-slate-300 mb-1">Email Address</label>
                  <input
                    type="email"
                    required
                    placeholder="alex@company.com"
                    value={newEmail}
                    onChange={(e) => setNewEmail(e.target.value)}
                    className="w-full rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-white placeholder-slate-500 focus:border-cyan-500 focus:outline-none"
                  />
                </div>

                <div>
                  <label className="block font-medium text-slate-300 mb-1">Temporary Password (min 12 chars)</label>
                  <input
                    type="password"
                    required
                    placeholder="e.g. SecurePass!2026"
                    value={newPassword}
                    onChange={(e) => setNewPassword(e.target.value)}
                    className="w-full rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-white placeholder-slate-500 focus:border-cyan-500 focus:outline-none"
                  />
                </div>

                <div>
                  <label className="block font-medium text-slate-300 mb-1">Role & Permission Level</label>
                  <select
                    value={newRole}
                    onChange={(e) => setNewRole(e.target.value)}
                    className="w-full rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-white focus:border-cyan-500 focus:outline-none"
                  >
                    <option value="Viewer">Viewer (Read-only)</option>
                    <option value="SOC Analyst">SOC Analyst (Triage alerts)</option>
                    <option value="Senior Security Analyst">Senior Security Analyst</option>
                    <option value="Malware Analyst">Malware Analyst</option>
                    <option value="Vulnerability Analyst">Vulnerability Analyst</option>
                    <option value="Threat Hunter">Threat Hunter</option>
                    <option value="SOC Manager">SOC Manager</option>
                    <option value="Admin">Administrator</option>
                  </select>
                </div>

                <div className="flex justify-end gap-3 pt-4 border-t border-line">
                  <button
                    type="button"
                    onClick={() => setShowAddModal(false)}
                    className="rounded-lg border border-slate-700 bg-slate-800 px-4 py-2 font-semibold text-slate-300 hover:bg-slate-700"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    disabled={addMutation.isPending}
                    className="rounded-lg bg-cyan-600 px-4 py-2 font-semibold text-white hover:bg-cyan-500 disabled:opacity-50"
                  >
                    {addMutation.isPending ? "Creating..." : "Save Employee"}
                  </button>
                </div>
              </form>
            </div>
          </div>
        )}

        {/* Employee Activity Drawer */}
        {selectedEmployeeId && (
          <div className="fixed inset-0 z-50 flex items-center justify-end bg-black/60 backdrop-blur-sm">
            <div className="h-full w-full max-w-xl border-l border-line bg-slate-900 p-6 shadow-2xl overflow-y-auto">
              <div className="flex items-center justify-between pb-4 border-b border-line">
                <div>
                  <h3 className="text-base font-bold text-white flex items-center gap-2">
                    <ShieldAlert size={18} className="text-cyan-400" />
                    Security Activity Log
                  </h3>
                  <p className="text-xs text-slate-400">
                    {activityData?.user?.full_name} ({activityData?.user?.email})
                  </p>
                </div>
                <button
                  onClick={() => setSelectedEmployeeId(null)}
                  className="rounded-lg p-1.5 text-slate-400 hover:text-white"
                >
                  <X size={18} />
                </button>
              </div>

              {activityLoading ? (
                <div className="py-12 text-center text-xs text-slate-400">Loading audit trail...</div>
              ) : (
                <div className="mt-6 space-y-6">
                  {/* Linked Alerts */}
                  <div>
                    <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400 mb-3">
                      Linked Security Alerts ({activityData?.alerts?.length || 0})
                    </h4>
                    {activityData?.alerts?.length === 0 ? (
                      <p className="text-xs text-slate-500 italic">No alerts mapped to this employee.</p>
                    ) : (
                      <div className="space-y-2">
                        {activityData?.alerts?.map((alert: any) => (
                          <div
                            key={alert.id}
                            className="rounded-lg border border-slate-800 bg-slate-800/40 p-3 text-xs"
                          >
                            <div className="flex items-center justify-between">
                              <span className="font-semibold text-white">{alert.title}</span>
                              <Badge severity={alert.severity}>{alert.severity}</Badge>
                            </div>
                            <p className="mt-1 text-[11px] text-slate-400">{alert.description}</p>
                            <div className="mt-2 text-[10px] text-slate-500 font-mono">
                              Source: {alert.source} · Status: {alert.status}
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>

                  {/* Audit Logs */}
                  <div>
                    <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400 mb-3">
                      Recent Actions & Login Activity
                    </h4>
                    {activityData?.audit_logs?.length === 0 ? (
                      <p className="text-xs text-slate-500 italic">No recent system actions recorded.</p>
                    ) : (
                      <div className="space-y-2">
                        {activityData?.audit_logs?.map((log: any) => (
                          <div
                            key={log.id}
                            className="rounded-lg border border-slate-800/60 bg-slate-950/40 p-2.5 text-xs font-mono"
                          >
                            <div className="flex items-center justify-between text-slate-300">
                              <span className="font-semibold text-cyan-400">{log.action}</span>
                              <span className="text-[10px] text-slate-500">{log.created_at?.slice(0, 19)}</span>
                            </div>
                            <div className="text-[11px] text-slate-400 mt-1">Target: {log.entity}</div>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </PageFrame>
  );
}
