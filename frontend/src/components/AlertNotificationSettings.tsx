import { useState, useEffect } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Bell, CheckCircle2, Key, Mail, MessageSquare, Phone, Send, ShieldAlert, Sparkles, XCircle } from "lucide-react";
import { api } from "../lib/api";
import { notify } from "../lib/feedback";
import { Card } from "./ui";

interface AlertConfig {
  email_enabled: boolean;
  sms_enabled: boolean;
  registered_email: string;
  registered_phone: string;
  sms_provider: string;
  sms_webhook_url: string;
  sms_api_key: string;
  twilio_account_sid: string;
  twilio_from_phone: string;
}

interface DispatchLog {
  timestamp: string;
  threat: string;
  severity: string;
  email?: { success: boolean; message: string; to: string } | null;
  sms?: { success: boolean; message: string; to: string } | null;
}

export function AlertNotificationSettings() {
  const queryClient = useQueryClient();
  const [email, setEmail] = useState("");
  const [phone, setPhone] = useState("");
  const [provider, setProvider] = useState("webhook");
  const [apiKey, setApiKey] = useState("");
  const [webhookUrl, setWebhookUrl] = useState("");
  const [twilioSid, setTwilioSid] = useState("");
  const [twilioFrom, setTwilioFrom] = useState("");
  const [emailEnabled, setEmailEnabled] = useState(true);
  const [smsEnabled, setSmsEnabled] = useState(true);
  const [loaded, setLoaded] = useState(false);

  // Fetch current alert config
  const { data, isLoading } = useQuery<{ success: boolean; config: AlertConfig; recent_dispatches: DispatchLog[] }>({
    queryKey: ["alerts-config"],
    queryFn: async () => {
      const res = await api.get("/agent/alerts-config");
      return res.data;
    },
    refetchInterval: 5000,
  });

  useEffect(() => {
    if (!loaded && data?.config) {
      setEmail(data.config.registered_email || "");
      setPhone(data.config.registered_phone || "");
      setProvider(data.config.sms_provider || "webhook");
      setApiKey(data.config.sms_api_key || "");
      setWebhookUrl(data.config.sms_webhook_url || "");
      setTwilioSid(data.config.twilio_account_sid || "");
      setTwilioFrom(data.config.twilio_from_phone || "");
      setEmailEnabled(data.config.email_enabled ?? true);
      setSmsEnabled(data.config.sms_enabled ?? true);
      setLoaded(true);
    }
  }, [data, loaded]);

  // Save config
  const saveMutation = useMutation({
    mutationFn: async () => {
      return (
        await api.post("/agent/alerts-config", {
          registered_email: email,
          registered_phone: phone,
          sms_provider: provider,
          sms_api_key: apiKey,
          sms_webhook_url: webhookUrl,
          twilio_account_sid: twilioSid,
          twilio_from_phone: twilioFrom,
          email_enabled: emailEnabled,
          sms_enabled: smsEnabled,
        })
      ).data;
    },
    onSuccess: () => {
      notify("Alert channels & registered contacts saved successfully!");
      queryClient.invalidateQueries({ queryKey: ["alerts-config"] });
    },
    onError: () => {
      notify("Failed to save alert settings.");
    },
  });

  // Test dispatch
  const testMutation = useMutation({
    mutationFn: async () => {
      return (await api.post("/agent/test-alert-dispatch")).data;
    },
    onSuccess: (res) => {
      const emailResult = res?.dispatch?.email?.success ? "Email Sent" : "Email Logged";
      const smsResult = res?.dispatch?.sms?.success ? "SMS Sent" : "SMS Logged";
      notify(`Emergency test dispatched: ${emailResult} | ${smsResult}`);
      queryClient.invalidateQueries({ queryKey: ["alerts-config"] });
    },
    onError: () => {
      notify("Error triggering test dispatch.");
    },
  });

  return (
    <Card className="space-y-5">
      {/* Header */}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between border-b border-slate-800 pb-4">
        <div>
          <h3 className="text-base font-bold text-white flex items-center gap-2">
            <Bell size={18} className="text-blue-500" />
            Critical Threat Notifications (SMS & Email API)
          </h3>
          <p className="text-xs text-slate-400 mt-0.5">
            Immediately alert your registered mobile number and email whenever a critical threat or rogue C2 socket is intercepted.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => saveMutation.mutate()}
            disabled={saveMutation.isPending}
            className="rounded-lg bg-blue-600 hover:bg-blue-500 px-3.5 py-2 text-xs font-semibold text-white shadow-sm transition disabled:opacity-50"
          >
            {saveMutation.isPending ? "Saving..." : "Save Settings"}
          </button>
          <button
            onClick={() => testMutation.mutate()}
            disabled={testMutation.isPending}
            className="inline-flex items-center gap-2 rounded-lg bg-rose-600 hover:bg-rose-500 px-3.5 py-2 text-xs font-semibold text-white shadow-sm transition disabled:opacity-50"
          >
            <Send size={13} className={testMutation.isPending ? "animate-spin" : ""} />
            {testMutation.isPending ? "Dispatching..." : "Send Test Alert"}
          </button>
        </div>
      </div>

      {/* Recipient Channels */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
        {/* Email Recipient */}
        <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-4 space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold text-white flex items-center gap-2">
              <Mail size={15} className="text-blue-400" /> Registered Alert Email
            </span>
            <label className="flex items-center gap-2 text-xs text-slate-300 cursor-pointer">
              <input
                type="checkbox"
                checked={emailEnabled}
                onChange={(e) => setEmailEnabled(e.target.checked)}
                className="rounded border-slate-700 bg-slate-900 text-blue-600 focus:ring-0"
              />
              Enable Email
            </label>
          </div>
          <input
            type="email"
            placeholder="admin@cybershield.dev"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            className="h-10 w-full rounded-lg border border-slate-700 bg-slate-900 px-3 text-xs text-white placeholder-slate-500 focus:border-blue-500 focus:outline-none transition"
          />
          <p className="text-[11px] text-slate-500">
            Receives full emergency incident briefs with target IP, host device, process name, and mitigation guidance.
          </p>
        </div>

        {/* SMS Recipient Phone */}
        <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-4 space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold text-white flex items-center gap-2">
              <Phone size={15} className="text-emerald-400" /> Registered Mobile Number (SMS)
            </span>
            <label className="flex items-center gap-2 text-xs text-slate-300 cursor-pointer">
              <input
                type="checkbox"
                checked={smsEnabled}
                onChange={(e) => setSmsEnabled(e.target.checked)}
                className="rounded border-slate-700 bg-slate-900 text-blue-600 focus:ring-0"
              />
              Enable SMS
            </label>
          </div>
          <input
            type="tel"
            placeholder="+1-555-0199 or 9876543210"
            value={phone}
            onChange={(e) => setPhone(e.target.value)}
            className="h-10 w-full rounded-lg border border-slate-700 bg-slate-900 px-3 text-xs text-white placeholder-slate-500 focus:border-blue-500 focus:outline-none transition"
          />
          <p className="text-[11px] text-slate-500">
            Receives instant flash SMS notification with threat title, host, and immediate action link.
          </p>
        </div>
      </div>

      {/* SMS Gateway & API Provider Configuration */}
      <div className="rounded-xl border border-slate-800 bg-slate-950/40 p-4 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 border-b border-slate-800/80 pb-3">
          <span className="text-xs font-bold text-slate-300 flex items-center gap-2">
            <Key size={15} className="text-purple-400" />
            SMS Gateway API Provider
          </span>
          <div className="flex items-center gap-2">
            <select
              value={provider}
              onChange={(e) => setProvider(e.target.value)}
              className="h-8 rounded-lg border border-slate-700 bg-slate-900 px-2.5 text-xs text-white focus:border-blue-500 focus:outline-none"
            >
              <option value="webhook">Custom Webhook / Gateway / Telegram</option>
              <option value="twilio">Twilio SMS API</option>
              <option value="fast2sms">Fast2SMS (India)</option>
              <option value="generic">Direct HTTP SMS API</option>
            </select>
          </div>
        </div>

        {provider === "twilio" ? (
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            <div>
              <label className="block text-[11px] font-medium text-slate-400 mb-1">Twilio Account SID</label>
              <input
                type="text"
                placeholder="ACXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
                value={twilioSid}
                onChange={(e) => setTwilioSid(e.target.value)}
                className="h-9 w-full rounded-lg border border-slate-800 bg-slate-900 px-3 text-xs text-white placeholder-slate-600 focus:border-blue-500 focus:outline-none"
              />
            </div>
            <div>
              <label className="block text-[11px] font-medium text-slate-400 mb-1">Twilio Auth Token (API Key)</label>
              <input
                type="password"
                placeholder="Auth Token"
                value={apiKey}
                onChange={(e) => setApiKey(e.target.value)}
                className="h-9 w-full rounded-lg border border-slate-800 bg-slate-900 px-3 text-xs text-white placeholder-slate-600 focus:border-blue-500 focus:outline-none"
              />
            </div>
            <div>
              <label className="block text-[11px] font-medium text-slate-400 mb-1">Twilio From Phone</label>
              <input
                type="tel"
                placeholder="+1234567890"
                value={twilioFrom}
                onChange={(e) => setTwilioFrom(e.target.value)}
                className="h-9 w-full rounded-lg border border-slate-800 bg-slate-900 px-3 text-xs text-white placeholder-slate-600 focus:border-blue-500 focus:outline-none"
              />
            </div>
          </div>
        ) : provider === "fast2sms" ? (
          <div>
            <label className="block text-[11px] font-medium text-slate-400 mb-1">Fast2SMS Authorization API Key</label>
            <input
              type="password"
              placeholder="Paste Fast2SMS API Key"
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
              className="h-9 w-full rounded-lg border border-slate-800 bg-slate-900 px-3 text-xs text-white placeholder-slate-600 focus:border-blue-500 focus:outline-none"
            />
          </div>
        ) : (
          <div>
            <label className="block text-[11px] font-medium text-slate-400 mb-1">
              SMS Gateway Webhook URL (or Discord, Slack, Telegram Bot Webhook)
            </label>
            <input
              type="url"
              placeholder="https://api.your-sms-gateway.com/send or webhook URL"
              value={webhookUrl}
              onChange={(e) => setWebhookUrl(e.target.value)}
              className="h-9 w-full rounded-lg border border-slate-800 bg-slate-900 px-3 text-xs text-white placeholder-slate-600 focus:border-blue-500 focus:outline-none"
            />
          </div>
        )}
      </div>

      {/* Recent Dispatches Log */}
      {data?.recent_dispatches && data.recent_dispatches.length > 0 && (
        <div className="space-y-2 pt-2 border-t border-slate-800">
          <span className="text-xs font-bold text-slate-400 uppercase tracking-wider block">
            Recent Emergency Dispatches
          </span>
          <div className="max-h-40 overflow-y-auto rounded-lg border border-slate-800 bg-slate-950/70 p-2 text-xs font-mono">
            {data.recent_dispatches.slice().reverse().map((item, idx) => (
              <div key={idx} className="flex items-center justify-between py-1.5 px-2 border-b border-slate-900 last:border-0">
                <div className="flex items-center gap-2 truncate">
                  <span className="text-slate-500 text-[11px]">{item.timestamp}</span>
                  <span className="text-rose-400 font-semibold">{item.threat}</span>
                </div>
                <div className="flex items-center gap-3 shrink-0 text-[11px]">
                  {item.email && (
                    <span className="inline-flex items-center gap-1 text-blue-400">
                      <Mail size={12} /> {item.email.success ? "Email OK" : "Failed"}
                    </span>
                  )}
                  {item.sms && (
                    <span className="inline-flex items-center gap-1 text-emerald-400">
                      <Phone size={12} /> {item.sms.success ? "SMS OK" : "Failed"}
                    </span>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </Card>
  );
}
