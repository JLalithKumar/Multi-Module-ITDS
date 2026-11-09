import { useState } from "react";
import { ScanSearch } from "lucide-react";
import { api } from "../lib/api";
import { Badge, Button, Card, SectionTitle, Textarea } from "../components/ui";

type DetectionResult = {
  matched: boolean;
  risk_score: number;
  alerts: Array<{ title: string; severity: string; source: string; description: string }>;
  recommendations: string[];
};

export function Detection() {
  const [text, setText] = useState("GET /search?q=' UNION SELECT password FROM users --");
  const [result, setResult] = useState<DetectionResult | null>(null);

  async function analyze() {
    const response = await api.post<DetectionResult>("/detection/analyze", { text, source: "analyst-console" });
    setResult(response.data);
  }

  return (
    <div className="space-y-6">
      <SectionTitle
        title="Threat Detection Engine"
        subtitle="Signature and behavior detection for SQLi, XSS, brute force, PowerShell abuse, ransomware, beaconing, and automated incident dispatch."
      />

      <div className="grid gap-5 xl:grid-cols-[0.9fr_1.1fr]">
        <Card className="space-y-3">
          <SectionTitle title="Telemetry Payload Inspector" subtitle="Input raw payloads, encoded commands, or HTTP requests to test detection engine." />
          <Textarea value={text} onChange={(event) => setText(event.target.value)} />
          <Button onClick={analyze}>
            <ScanSearch className="h-4 w-4" />
            Analyze Telemetry
          </Button>
        </Card>

        <Card>
          <SectionTitle title="Detection Verdict & Correlated Alerts" />
          {result ? (
            <div className="mt-4 space-y-4">
              <div className="rounded-xl border border-slate-800 bg-slate-950/70 p-4">
                <div className="text-xs uppercase font-bold text-slate-400">Risk Score</div>
                <div className="mt-1 text-4xl font-bold text-rose-500">{result.risk_score}</div>
              </div>
              {result.alerts.map((alert) => (
                <div key={alert.title} className="rounded-xl border border-slate-800 bg-slate-950/70 p-4">
                  <div className="flex items-center justify-between gap-3">
                    <div className="font-semibold text-white">{alert.title}</div>
                    <Badge severity={alert.severity}>{alert.severity}</Badge>
                  </div>
                  <p className="mt-2 text-xs text-slate-400">{alert.description}</p>
                </div>
              ))}
              <div className="text-xs text-slate-300 bg-slate-950/50 p-3 rounded-lg border border-slate-800">
                {result.recommendations.join(" ")}
              </div>
            </div>
          ) : (
            <div className="mt-4 rounded-xl border border-slate-800 bg-slate-950/40 p-8 text-center text-xs text-slate-400">
              Run analysis on raw telemetry above to test engine signatures and real-time alert correlation.
            </div>
          )}
        </Card>
      </div>
    </div>
  );
}
