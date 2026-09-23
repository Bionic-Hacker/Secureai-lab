import { useCallback, useEffect, useState } from "react";
import {
  getActiveSessions,
  getExternalHealth,
  getFrameworkCoverage,
  getServiceHealth,
  listAIRequests,
  listAuditLog,
  listDocuments,
  listFindings,
  listRejectedUploads,
} from "../api.js";

const PENDING = new Set(["pending", "scanning", "in_progress"]);
const OPEN_STATUSES = new Set(["open", "acknowledged", "in_progress"]);
const SEVERITIES = ["critical", "high", "medium", "low"];
const AI_REQUEST_FETCH_LIMIT = 200;
const DAY_MS = 24 * 60 * 60 * 1000;

// Real detections only - see backend/app/services/guardrails.py. Anything
// this app doesn't actually detect (e.g. AML.T0048 Misuse) is left out
// rather than shown with a fabricated zero. Tones follow the mockup:
// injection red, jailbreak orange, data leakage blue.
const ATLAS_BUCKETS = [
  { id: "AML.T0051", label: "Prompt Injection", tone: "critical", match: (f) => f === "prompt_injection_suspected" },
  { id: "AML.T0054", label: "Jailbreak", tone: "high", match: (f) => f === "jailbreak_suspected" },
  { id: "AML.T0057", label: "Data Leakage", tone: "low", match: (f) => f.startsWith("redacted_") },
];

const ROLE_ORDER = ["administrator", "security_engineer", "developer"];

const EXTERNAL_STATUS_LABELS = {
  healthy: "healthy",
  timeout: "cold start / timed out",
  unreachable: "unreachable",
  not_configured: "not configured",
};

function formatTime(iso) {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "—";
  return d.toLocaleString(undefined, {
    month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit",
  });
}

function fmt(n) {
  return Number(n).toLocaleString();
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

function StatCard({ label, value, delta }) {
  return (
    <div className="stat-card">
      <div className="stat-card__label">{label}</div>
      <div className="stat-card__value">{value}</div>
      <div className="stat-card__delta">{delta}</div>
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
  const [sessions, setSessions] = useState(null);
  const [external, setExternal] = useState({ status: "loading" });

  // Loaded separately from everything else: a sleeping free-tier dependency
  // can take several seconds to answer, and it shouldn't hold up the page.
  useEffect(() => {
    let cancelled = false;
    getExternalHealth()
      .then((data) => {
        if (!cancelled) setExternal({ status: "ready", data });
      })
      .catch((err) => {
        if (!cancelled) setExternal({ status: err.status === 403 ? "hidden" : "error", error: err });
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const load = useCallback(async () => {
    setState("loading");
    setError(null);
    try {
      const settled = await Promise.allSettled([
        listDocuments(),
        listRejectedUploads(),
        listFindings({ limit: 200 }),
        listAIRequests({ limit: AI_REQUEST_FETCH_LIMIT }),
        listAuditLog({ limit: 8 }),
        getFrameworkCoverage(),
        getServiceHealth(),
        getActiveSessions(),
      ]);
      const value = (i, fallback) => (settled[i].status === "fulfilled" ? settled[i].value : fallback);

      setDocs(value(0, []));
      setRejected(value(1, []));
      setFindings(value(2, null));
      setAiRequests(value(3, null));
      setAuditEntries(value(4, null));
      setCoverage(value(5, null));
      setHealth(value(6, null));
      setSessions(value(7, null));
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

  const GOV_ONLY = "Requires governance access";

  // --- documents
  const heldCount = docs.length + rejected.length;
  const clearedCount = docs.filter((d) => d.malware_scan_status === "clean").length;
  const inScanCount = docs.filter((d) => PENDING.has(d.malware_scan_status)).length;
  const flaggedCount = rejected.length;

  // --- findings
  const openFindings = findings ? findings.filter((f) => OPEN_STATUSES.has(f.status)) : [];
  const severityCounts = SEVERITIES.map((sev) => ({
    severity: sev,
    count: openFindings.filter((f) => f.severity === sev).length,
  }));
  const maxSeverity = Math.max(1, ...severityCounts.map((s) => s.count));

  // --- AI requests (last 24h) and guardrail activity. Computed from the most
  // recent AI_REQUEST_FETCH_LIMIT requests; if every one of them falls inside
  // the window, the true 24h count may be higher, so it's shown as "200+".
  const requests = aiRequests ?? [];
  const cutoff = Date.now() - DAY_MS;
  const last24h = requests.filter((r) => new Date(r.created_at).getTime() >= cutoff);
  const windowSaturated = requests.length >= AI_REQUEST_FETCH_LIMIT && last24h.length === requests.length;
  const passed24h = last24h.filter((r) => !r.blocked).length;
  const passRate = last24h.length ? Math.round((passed24h / last24h.length) * 1000) / 10 : null;

  const allFlags = requests.flatMap((r) => r.guardrail_flags ?? []);
  const injectionBlocks = allFlags.filter((f) => f === "prompt_injection_suspected").length;
  const jailbreakBlocks = allFlags.filter((f) => f === "jailbreak_suspected").length;
  const redactedResponses = requests.filter((r) => (r.guardrail_flags ?? []).some((f) => f.startsWith("redacted_"))).length;
  const guardrailEvents = injectionBlocks + jailbreakBlocks + redactedResponses;

  const atlasCounts = ATLAS_BUCKETS.map((bucket) => ({
    ...bucket,
    count: allFlags.filter(bucket.match).length,
  }));
  const maxAtlas = Math.max(1, ...atlasCounts.map((b) => b.count));

  // --- framework coverage: real counts from framework_coverage.json
  const frameworks = coverage?.frameworks ?? [];
  const controls = frameworks.flatMap((fw) => fw.controls ?? []);
  const applicable = controls.filter((c) => c.status !== "not_applicable");
  const implemented = applicable.filter((c) => c.status === "implemented").length;

  // --- active sessions
  const roleBreakdown = sessions
    ? [...ROLE_ORDER, ...Object.keys(sessions.by_role).filter((r) => !ROLE_ORDER.includes(r))]
        .filter((r) => sessions.by_role[r])
        .map((r) => `${sessions.by_role[r]} ${r.replace("_", " ")}`)
        .join(" · ")
    : "";

  return (
    <div>
      <header className="gov-header">
        <div>
          <h1 className="gov-header__title">Operations Overview</h1>
          <p className="gov-header__sub">
            A live snapshot of documents, findings, AI request telemetry, sessions, and service health, read
            directly from the real backend, not sample data.
          </p>
        </div>
      </header>

      <div className="stat-grid stat-grid--six">
        <StatCard
          label="AI Requests (24h)"
          value={aiRequests ? `${fmt(last24h.length)}${windowSaturated ? "+" : ""}` : "—"}
          delta={
            aiRequests
              ? passRate != null
                ? `Guardrail pass rate ${passRate}%`
                : "No requests in the last 24 hours"
              : GOV_ONLY
          }
        />
        <StatCard
          label="Guardrail Blocks"
          value={aiRequests ? fmt(guardrailEvents) : "—"}
          delta={
            aiRequests
              ? `${injectionBlocks} prompt injection · ${jailbreakBlocks} jailbreak · ${redactedResponses} output redactions`
              : GOV_ONLY
          }
        />
        <StatCard
          label="Open Findings"
          value={findings ? fmt(openFindings.length) : "—"}
          delta={findings ? severityCounts.map((s) => `${s.count} ${s.severity}`).join(" · ") : GOV_ONLY}
        />
        <StatCard
          label="Documents Held"
          value={fmt(heldCount)}
          delta={`${clearedCount} cleared · ${inScanCount} in scan · ${flaggedCount} flagged`}
        />
        <StatCard
          label="Active Sessions"
          value={sessions ? fmt(sessions.total) : "—"}
          delta={sessions ? roleBreakdown || "No active sessions" : GOV_ONLY}
        />
        <StatCard
          label="Framework Coverage"
          value={coverage ? fmt(frameworks.length) : "—"}
          delta={
            coverage
              ? `${implemented} of ${applicable.length} mapped controls implemented · see Governance`
              : GOV_ONLY
          }
        />
      </div>

      <div className="overview-grid overview-grid--activity">
        <div className="overview-panel">
          <div className="overview-panel__title">Recent Activity</div>
          <p className="overview-panel__desc">Live tail of the audit log. Full history is under Governance.</p>
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
                          <span
                            className={`outcome-pill outcome-pill--${e.outcome === "success" ? "clean" : "flagged"}`}
                          >
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
            <p className="gov-empty">{GOV_ONLY}.</p>
          )}
        </div>

        <div className="overview-panel">
          <div className="overview-panel__title">Service Health</div>
          <p className="overview-panel__desc">Every dependency is pinged live on each load.</p>
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
            <p className="gov-empty">{GOV_ONLY}.</p>
          )}
          {external.status !== "hidden" && (
            <div className="health-external">
              <div className="health-external__title">External Services</div>
              <p className="overview-panel__desc">Optional third-party dependencies, not counted in system status.</p>
              {external.status === "loading" && <p className="gov-loading">Checking…</p>}
              {external.status === "error" && (
                <p className="gov-error">Couldn&apos;t check external services: {external.error?.message}</p>
              )}
              {external.status === "ready" && (
                <div className="health-list">
                  {(external.data?.components ?? []).map((c) => (
                    <div className="health-row" key={c.name} title={c.detail || undefined}>
                      <span className="health-row__name mono">
                        <span className={`health-dot health-dot--${c.status}`} />
                        {c.name}
                      </span>
                      <span className={`health-row__status health-row__status--${c.status}`}>
                        {EXTERNAL_STATUS_LABELS[c.status] ?? c.status}
                        {c.latency_ms != null ? ` · ${c.latency_ms}ms` : ""}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      </div>

      <div className="overview-panel">
        <div className="overview-panel__title">Findings by Severity</div>
        {findings ? (
          severityCounts.map((s) => (
            <BarRow key={s.severity} label={s.severity} value={s.count} max={maxSeverity} tone={s.severity} />
          ))
        ) : (
          <p className="gov-empty">{GOV_ONLY}.</p>
        )}
      </div>

      <div className="overview-panel">
        <div className="overview-panel__title">MITRE ATLAS Techniques Observed</div>
        <p className="overview-panel__desc">
          Adversarial AI activity caught by the input and output guardrails, tagged by ATLAS technique. Only
          techniques this app actually detects are shown.
        </p>
        {aiRequests ? (
          atlasCounts.map((b) => (
            <BarRow key={b.id} label={`${b.id} ${b.label}`} value={b.count} max={maxAtlas} tone={b.tone} />
          ))
        ) : (
          <p className="gov-empty">{GOV_ONLY}.</p>
        )}
      </div>
    </div>
  );
}
