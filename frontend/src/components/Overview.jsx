import { useCallback, useEffect, useState } from "react";
import {
  listDocuments,
  listRejectedUploads,
  listFindings,
  listAIRequests,
  listAuditLog,
  getFrameworkCoverage,
  getServiceHealth,
} from "../api.js";

const PENDING = new Set(["pending", "scanning", "in_progress"]);
const OPEN_STATUSES = new Set(["open", "acknowledged", "in_progress"]);
const SEVERITIES = ["critical", "high", "medium", "low"];

// Real detections only - see backend/app/services/guardrails.py. Anything
// this app doesn't actually detect (e.g. AML.T0048 Misuse) is left out
// rather than shown with a fabricated zero.
const ATLAS_BUCKETS = [
  { id: "AML.T0051", label: "Prompt Injection", match: (f) => f === "prompt_injection_suspected" },
  { id: "AML.T0054", label: "Jailbreak", match: (f) => f === "jailbreak_suspected" },
  { id: "AML.T0057", label: "Data Leakage", match: (f) => f.startsWith("redacted_") },
];

function formatTime(iso) {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "—";
  return d.toLocaleString(undefined, {
    month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit",
  });
}

function BarRow({ label, value, max, tone }) {
  const pct = max > 0 ? Math.round((value / max) * 100) : 0;
  return (
    <div className="bar-row">
      <span className="bar-row__label mono">{label}</span>
      <div className="bar-track">
        <div className={`bar-fill bar-fill--${tone}`} style={{ width: `${pct}%` }} />
      </div>
      <span className="bar-row__value mono">{value}</span>
    </div>
  );
}

export default function Overview() {
  const [state, setState] = useState("loading"); // loading | error | ready
  const [error, setError] = useState(null);
  const [docs, setDocs] = useState([]);
  const [rejected, setRejected] = useState([]);
  const [findings, setFindings] = useState(null);
  const [aiRequests, setAiRequests] = useState(null);
  const [auditEntries, setAuditEntries] = useState(null);
  const [coverage, setCoverage] = useState(null);
  const [health, setHealth] = useState(null);

  const load = useCallback(async () => {
    setState("loading");
    setError(null);
    try {
      const [
        docsResult,
        rejectedResult,
        findingsResult,
        aiRequestsResult,
        auditResult,
        coverageResult,
        healthResult,
      ] = await Promise.allSettled([
        listDocuments(),
        listRejectedUploads(),
        listFindings({ limit: 200 }),
        listAIRequests({ limit: 200 }),
        listAuditLog({ limit: 10 }),
        getFrameworkCoverage(),
        getServiceHealth(),
      ]);

      setDocs(docsResult.status === "fulfilled" ? docsResult.value : []);
      setRejected(rejectedResult.status === "fulfilled" ? rejectedResult.value : []);
      setFindings(findingsResult.status === "fulfilled" ? findingsResult.value : null);
      setAiRequests(aiRequestsResult.status === "fulfilled" ? aiRequestsResult.value : null);
      setAuditEntries(auditResult.status === "fulfilled" ? auditResult.value : null);
      setCoverage(coverageResult.status === "fulfilled" ? coverageResult.value : null);
      setHealth(healthResult.status === "fulfilled" ? healthResult.value : null);
      setState("ready");
    } catch (err) {
      setError(err.message);
      setState("error");
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  if (state === "loading") {
    return <p className="gov-loading">Loading overview…</p>;
  }
  if (state === "error") {
    return <p className="gov-error">Couldn't load the overview: {error}</p>;
  }

  const heldCount = docs.length + rejected.length;
  const clearedCount = docs.filter((d) => d.malware_scan_status === "clean").length;
  const inScanCount = docs.filter((d) => PENDING.has(d.malware_scan_status)).length;
  const flaggedCount = rejected.length;

  const openFindings = findings ? findings.filter((f) => OPEN_STATUSES.has(f.status)) : [];
  const severityCounts = SEVERITIES.map((sev) => ({
    severity: sev,
    count: openFindings.filter((f) => f.severity === sev).length,
  }));
  const maxSeverity = Math.max(1, ...severityCounts.map((s) => s.count));

  const totalAiRequests = aiRequests ? aiRequests.length : 0;
  const blockedAiRequests = aiRequests ? aiRequests.filter((r) => r.blocked).length : 0;

  const allFlags = aiRequests ? aiRequests.flatMap((r) => r.guardrail_flags) : [];
  const atlasCounts = ATLAS_BUCKETS.map((bucket) => ({
    ...bucket,
    count: allFlags.filter(bucket.match).length,
  }));
  const maxAtlas = Math.max(1, ...atlasCounts.map((b) => b.count));

  const frameworksCovered = coverage?.frameworks?.length ?? null;

  return (
    <div>
      <header className="gov-header">
        <div>
          <h1 className="gov-header__title">Overview</h1>
          <p className="gov-header__sub">
            A live snapshot of documents, findings, AI request telemetry, and service health — read directly
            from the real backend, not sample data.
          </p>
        </div>
      </header>

      <div className="stat-grid">
        <div className="stat-card">
          <div className="stat-card__label">Documents Held</div>
          <div className="stat-card__value">{String(heldCount).padStart(3, "0")}</div>
          <div className="stat-card__delta">
            {clearedCount} cleared · {inScanCount} in scan · {flaggedCount} flagged
          </div>
        </div>

        <div className="stat-card">
          <div className="stat-card__label">Open Findings</div>
          <div className="stat-card__value">
            {findings ? String(openFindings.length).padStart(3, "0") : "—"}
          </div>
          <div className="stat-card__delta">
            {findings
              ? severityCounts.map((s) => `${s.count} ${s.severity}`).join(" · ")
              : "Requires governance access"}
          </div>
        </div>

        <div className="stat-card">
          <div className="stat-card__label">AI Requests</div>
          <div className="stat-card__value">
            {aiRequests ? String(totalAiRequests).padStart(3, "0") : "—"}
          </div>
          <div className="stat-card__delta">
            {aiRequests ? `${blockedAiRequests} blocked by guardrails` : "Requires governance access"}
          </div>
        </div>

        <div className="stat-card">
          <div className="stat-card__label">Framework Coverage</div>
          <div className="stat-card__value">
            {frameworksCovered != null ? `${frameworksCovered}` : "—"}
          </div>
          <div className="stat-card__delta">
            {frameworksCovered != null ? "Frameworks mapped — see Governance" : "Requires governance access"}
          </div>
        </div>
      </div>

      <div className="overview-grid">
        <div className="overview-panel">
          <div className="overview-panel__title">Findings by Severity</div>
          {findings ? (
            severityCounts.map((s) => (
              <BarRow key={s.severity} label={s.severity} value={s.count} max={maxSeverity} tone={s.severity} />
            ))
          ) : (
            <p className="gov-empty">Requires governance access.</p>
          )}
        </div>

        <div className="overview-panel">
          <div className="overview-panel__title">MITRE ATLAS Techniques Observed</div>
          <p className="overview-panel__desc">
            Guardrail detections tagged by ATLAS technique — only categories this app actually detects are shown.
          </p>
          {aiRequests ? (
            atlasCounts.map((b) => (
              <BarRow key={b.id} label={`${b.id} ${b.label}`} value={b.count} max={maxAtlas} tone="stamp" />
            ))
          ) : (
            <p className="gov-empty">Requires governance access.</p>
          )}
        </div>
      </div>

      <div className="overview-panel">
        <div className="overview-panel__title">Service Health</div>
        {health ? (
          <div className="health-list">
            {health.components.map((c) => (
              <div className="health-row" key={c.name}>
                <span className="health-row__name mono">
                  <span className={`health-dot health-dot--${c.status}`} />
                  {c.name}
                </span>
                <span className={`health-row__status health-row__status--${c.status}`}>
                  {c.status}
                  {c.latency_ms != null ? ` · ${c.latency_ms}ms` : ""}
                </span>
              </div>
            ))}
          </div>
        ) : (
          <p className="gov-empty">Requires governance access.</p>
        )}
      </div>

      <div className="overview-panel">
        <div className="overview-panel__title">Recent Activity</div>
        {auditEntries ? (
          auditEntries.length === 0 ? (
            <p className="gov-empty">No recent activity.</p>
          ) : (
            <div className="audit-table-wrap">
              <table className="audit-table">
                <thead>
                  <tr>
                    <th>Time</th>
                    <th>Actor</th>
                    <th>Event</th>
                    <th>Outcome</th>
                  </tr>
                </thead>
                <tbody>
                  {auditEntries.map((e) => (
                    <tr key={e.id}>
                      <td className="mono">{formatTime(e.occurred_at)}</td>
                      <td>{e.actor_email ?? "system"}</td>
                      <td className="mono">{e.event_type}</td>
                      <td>
                        <span className={`outcome-pill outcome-pill--${e.outcome === "success" ? "clean" : "flagged"}`}>
                          {e.outcome}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )
        ) : (
          <p className="gov-empty">Requires governance access.</p>
        )}
      </div>
    </div>
  );
}
