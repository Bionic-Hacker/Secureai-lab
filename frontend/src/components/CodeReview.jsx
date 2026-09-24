import { useCallback, useEffect, useMemo, useState } from "react";
import { getFindingExcerpt, listCodeFindings, updateFindingStatus } from "../api.js";

const SEVERITIES = ["critical", "high", "medium", "low"];
const OPEN_STATUSES = new Set(["open", "acknowledged", "in_progress"]);
const STATUSES = ["open", "acknowledged", "in_progress", "remediated", "accepted_risk", "closed"];
const GOVERNANCE_ROLES = new Set(["security_engineer", "administrator"]);
const TOOL_LABELS = { semgrep: "Semgrep", bandit: "Bandit" };

// Curated per-category reference, keyed by the categories the scanner
// actually assigns (backend/app/services/cvss_mapping.py). Guidance is
// general remediation for the category, not a generated fix for this code.
const CATEGORY_INFO = {
  sql_injection: {
    owasp: "A03:2021 Injection", cwe: "CWE-89",
    guidance: "Replace string-built SQL with bound parameters, so the database driver handles escaping instead of the application. This closes the injection path regardless of what characters appear in the input.",
  },
  command_injection: {
    owasp: "A03:2021 Injection", cwe: "CWE-78",
    guidance: "Avoid shell=True and string-built commands. Pass arguments as a list to subprocess (or execFile in Node) so user input can never be interpreted by a shell, and validate inputs against an allowlist.",
  },
  insecure_deserialization: {
    owasp: "A08:2021 Software and Data Integrity Failures", cwe: "CWE-502",
    guidance: "Never unpickle or yaml.load untrusted data. Use a data-only format such as JSON, or yaml.safe_load, and validate the structure after parsing.",
  },
  hardcoded_credentials: {
    owasp: "A07:2021 Identification and Authentication Failures", cwe: "CWE-798",
    guidance: "Move the secret into an environment variable or a secrets manager and rotate it: a credential that has been committed should be treated as exposed, even after it's removed from the code.",
  },
  ssrf: {
    owasp: "A10:2021 Server-Side Request Forgery", cwe: "CWE-918",
    guidance: "Don't fetch URLs taken directly from user input. Resolve them against an allowlist of hosts and schemes, and block private, loopback, and cloud-metadata address ranges.",
  },
  path_traversal: {
    owasp: "A01:2021 Broken Access Control", cwe: "CWE-22",
    guidance: "Never join user input straight into a file path. Resolve the final path and confirm it is still inside the intended base directory, or map user-facing IDs to server-side paths.",
  },
  xss: {
    owasp: "A03:2021 Injection", cwe: "CWE-79",
    guidance: "Render untrusted content as text, not HTML: avoid innerHTML and dangerouslySetInnerHTML, or sanitize with a vetted library such as DOMPurify when HTML is genuinely required.",
  },
  weak_crypto: {
    owasp: "A02:2021 Cryptographic Failures", cwe: "CWE-327",
    guidance: "Replace broken algorithms (MD5, SHA-1, DES) with current ones: SHA-256 or better for integrity, AES-GCM for encryption, and a dedicated password hash such as Argon2 or bcrypt for passwords.",
  },
  insecure_random: {
    owasp: "A02:2021 Cryptographic Failures", cwe: "CWE-330",
    guidance: "Use a cryptographically secure generator (Python's secrets module, Node's crypto.randomBytes) for tokens, IDs, and anything security-relevant; random and Math.random are predictable.",
  },
};

function tool(t) {
  return TOOL_LABELS[t] ?? t;
}

function label(s) {
  return String(s ?? "").replace(/_/g, " ");
}

function SeverityBadge({ severity }) {
  return <span className={`cr-badge cr-badge--${severity}`}>{severity}</span>;
}

function Excerpt({ finding }) {
  const [state, setState] = useState({ status: "loading" });

  useEffect(() => {
    let cancelled = false;
    setState({ status: "loading" });
    getFindingExcerpt(finding.id)
      .then((data) => !cancelled && setState({ status: "ready", data }))
      .catch((err) => !cancelled && setState({ status: "error", error: err }));
    return () => {
      cancelled = true;
    };
  }, [finding.id]);

  if (state.status === "loading") return <p className="gov-loading">Loading code…</p>;
  if (state.status === "error") return <p className="gov-error">Couldn&apos;t load the code: {state.error?.message}</p>;

  const { data } = state;
  if (!data.lines.length) return <p className="gov-empty">No line number was recorded for this finding.</p>;

  return (
    <>
      <div className="cr-code">
        <div className="cr-code__file mono">{data.document_filename}</div>
        {data.lines.map((line, i) => {
          const n = data.start_line + i;
          const flagged = n === data.highlight_line;
          return (
            <div key={n} className={`cr-code__line mono${flagged ? " cr-code__line--flagged" : ""}`}>
              <span className="cr-code__num">{n}</span>
              <span className="cr-code__text">{line || " "}</span>
            </div>
          );
        })}
      </div>
      {data.redactions.length > 0 && (
        <p className="kyora-note">
          Secrets in this excerpt were redacted by the output guardrail ({data.redactions.map(label).join(", ")}).
        </p>
      )}
    </>
  );
}

function FindingDetail({ finding, canEditStatus, onStatusChange }) {
  const info = CATEGORY_INFO[finding.category];
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState(null);

  async function changeStatus(next) {
    setSaving(true);
    setError(null);
    try {
      await onStatusChange(finding.id, next);
    } catch (err) {
      setError(err.message);
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="overview-panel">
      <div className="cr-detail__head">
        <div>
          <div className="overview-panel__title">{finding.title}</div>
          <p className="overview-panel__desc">
            <span className="mono">
              {finding.document_filename}
              {finding.line_number != null ? `:${finding.line_number}` : ""}
            </span>{" "}
            · detected by {tool(finding.tool)} <span className="mono cr-muted">({finding.rule_id})</span>
            {info ? ` · OWASP ${info.owasp}` : ""}
          </p>
        </div>
        <SeverityBadge severity={finding.severity} />
      </div>

      <div className="cr-cards">
        <div className="stat-card">
          <div className="stat-card__label">CVSS 3.1</div>
          <div className="stat-card__value">{Number(finding.cvss_score).toFixed(1)}</div>
          <div className="stat-card__delta mono">{finding.cvss_vector}</div>
          <div className="stat-card__hint">Category-level estimate, not scored for this deployment</div>
        </div>
        <div className="stat-card">
          <div className="stat-card__label">Weakness</div>
          <div className="stat-card__value">{info ? info.cwe : "—"}</div>
          <div className="stat-card__delta">{label(finding.category)}</div>
        </div>
      </div>

      <p className="kyora-text">{finding.description}</p>

      <Excerpt finding={finding} />

      {info && (
        <p className="cr-remediation">
          <strong>Remediation guidance:</strong> {info.guidance}
        </p>
      )}

      <div className="kyora-row">
        <span className="kyora-note" style={{ marginTop: 0 }}>Status</span>
        {canEditStatus ? (
          <select
            className="sort-select"
            value={finding.status}
            disabled={saving}
            onChange={(e) => changeStatus(e.target.value)}
          >
            {STATUSES.map((s) => (
              <option key={s} value={s}>
                {label(s)}
              </option>
            ))}
          </select>
        ) : (
          <span className="cr-status">{label(finding.status)}</span>
        )}
      </div>
      {error && <p className="gov-error">Couldn&apos;t update status: {error}</p>}
    </div>
  );
}

export default function CodeReview({ user }) {
  const [state, setState] = useState({ status: "loading" });
  const [selectedId, setSelectedId] = useState(null);
  const canEditStatus = GOVERNANCE_ROLES.has(user?.role);

  const load = useCallback(async () => {
    setState({ status: "loading" });
    try {
      setState({ status: "ready", findings: await listCodeFindings() });
    } catch (err) {
      setState({ status: "error", error: err });
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const findings = state.findings ?? [];
  const open = useMemo(() => findings.filter((f) => OPEN_STATUSES.has(f.status)), [findings]);
  const counts = SEVERITIES.map((s) => ({ s, n: open.filter((f) => f.severity === s).length }));
  const max = Math.max(1, ...counts.map((c) => c.n));
  const selected = findings.find((f) => f.id === selectedId) ?? open[0] ?? findings[0] ?? null;

  async function handleStatusChange(findingId, next) {
    const updated = await updateFindingStatus(findingId, next);
    setState((prev) => ({
      ...prev,
      findings: prev.findings.map((f) => (f.id === findingId ? { ...f, status: updated?.status ?? next } : f)),
    }));
  }

  return (
    <div>
      <header className="gov-header">
        <div>
          <h1 className="gov-header__title">Secure Code Review Engine</h1>
          <p className="gov-header__sub">
            Static analysis with Semgrep and Bandit, scored and mapped to OWASP and CWE. Findings cover every
            document you can access; run new scans from Document Vault.
          </p>
        </div>
      </header>

      {state.status === "loading" && <p className="gov-loading">Loading findings…</p>}
      {state.status === "error" && <p className="gov-error">Couldn&apos;t load findings: {state.error?.message}</p>}

      {state.status === "ready" && findings.length === 0 && (
        <div className="overview-panel">
          <p className="gov-empty" style={{ margin: 0 }}>
            No findings yet. Upload a .py, .js, .ts, .jsx or .tsx file in Document Vault and run a code scan.
          </p>
        </div>
      )}

      {state.status === "ready" && findings.length > 0 && (
        <>
          <div className="overview-panel">
            <div className="overview-panel__title">Open Findings by Severity</div>
            {counts.map(({ s, n }) => (
              <div className="bar-row" key={s}>
                <span className="bar-row__label mono">{s}</span>
                <div className="bar-track">
                  <div className={`bar-fill bar-fill--${s}`} style={{ width: `${Math.round((n / max) * 100)}%` }} />
                </div>
                <span className="bar-row__value mono">{n}</span>
              </div>
            ))}
          </div>

          {selected && (
            <FindingDetail
              key={selected.id}
              finding={selected}
              canEditStatus={canEditStatus}
              onStatusChange={handleStatusChange}
            />
          )}

          <div className="overview-panel overview-panel--flush">
            <div className="tm-table-wrap">
              <table className="tm-table cr-table">
                <thead>
                  <tr>
                    <th>Finding</th>
                    <th>Severity</th>
                    <th>File</th>
                    <th>Tool</th>
                    <th>Status</th>
                  </tr>
                </thead>
                <tbody>
                  {findings.map((f) => (
                    <tr
                      key={f.id}
                      className={selected?.id === f.id ? "cr-row--selected" : ""}
                      onClick={() => setSelectedId(f.id)}
                      tabIndex={0}
                      onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && setSelectedId(f.id)}
                      aria-selected={selected?.id === f.id}
                    >
                      <td>{f.title}</td>
                      <td>
                        <SeverityBadge severity={f.severity} />
                      </td>
                      <td className="mono">
                        {f.document_filename}
                        {f.line_number != null ? `:${f.line_number}` : ""}
                      </td>
                      <td>{tool(f.tool)}</td>
                      <td>
                        <span className="cr-status">{label(f.status)}</span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
