import { useCallback, useEffect, useState } from "react";
import { listFindings, updateFindingStatus } from "../../api.js";

const SEVERITY_TONE = { critical: "flagged", high: "pending", medium: "stamp", low: "slate" };
const STATUS_OPTIONS = ["open", "acknowledged", "in_progress", "remediated", "accepted_risk", "closed"];
const SEVERITIES = ["critical", "high", "medium", "low"];

function statusLabel(s) {
  return s.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

export default function Findings() {
  const [state, setState] = useState("loading"); // loading | denied | error | ready
  const [findings, setFindings] = useState([]);
  const [error, setError] = useState(null);
  const [severityFilter, setSeverityFilter] = useState("all");
  const [savingId, setSavingId] = useState(null);

  const load = useCallback(async () => {
    setState("loading");
    try {
      const params = severityFilter === "all" ? {} : { severity: severityFilter };
      const result = await listFindings({ limit: 100, ...params });
      setFindings(result);
      setState("ready");
    } catch (err) {
      if (err.status === 403) {
        setState("denied");
      } else {
        setError(err.message);
        setState("error");
      }
    }
  }, [severityFilter]);

  useEffect(() => {
    load();
  }, [load]);

  async function handleStatusChange(findingId, newStatus) {
    setSavingId(findingId);
    try {
      const updated = await updateFindingStatus(findingId, newStatus);
      setFindings((prev) => prev.map((f) => (f.id === findingId ? updated : f)));
    } catch (err) {
      setError(`Couldn't update status: ${err.message}`);
    } finally {
      setSavingId(null);
    }
  }

  if (state === "loading") {
    return <p className="gov-loading">Loading findings…</p>;
  }

  if (state === "denied") {
    return (
      <div className="gov-denied">
        <h2 className="gov-denied__title">Governance access required</h2>
        <p className="gov-denied__detail">
          This section requires the <code>security_engineer</code> or <code>administrator</code> role.
        </p>
      </div>
    );
  }

  if (state === "error" && findings.length === 0) {
    return <p className="gov-error">Couldn't load findings: {error}</p>;
  }

  return (
    <div>
      {error && <p className="gov-error">{error}</p>}

      <div className="toolbar" style={{ marginTop: 0 }}>
        <div className="toolbar__filters" role="group" aria-label="Filter by severity">
          <button
            type="button"
            className={`filter-btn ${severityFilter === "all" ? "filter-btn--active" : ""}`}
            onClick={() => setSeverityFilter("all")}
          >
            All
          </button>
          {SEVERITIES.map((sev) => (
            <button
              key={sev}
              type="button"
              className={`filter-btn ${severityFilter === sev ? `filter-btn--active filter-btn--${SEVERITY_TONE[sev]}` : ""}`}
              onClick={() => setSeverityFilter(sev)}
            >
              {sev}
            </button>
          ))}
        </div>
      </div>

      {findings.length === 0 ? (
        <p className="gov-empty">No findings match this filter.</p>
      ) : (
        <div className="finding-list">
          {findings.map((f) => (
            <article className="finding-card" key={f.id}>
              <div className="finding-card__head">
                <span className={`sev-pill sev-pill--${SEVERITY_TONE[f.severity] ?? "slate"}`}>{f.severity}</span>
                <h3 className="finding-card__title">{f.title}</h3>
              </div>
              <p className="finding-card__meta">
                <span className="mono">{f.document_filename ?? f.document_id}</span> · {f.tool} · {f.rule_id}
                {f.line_number != null && <> · line {f.line_number}</>}
              </p>
              <p className="finding-card__desc">{f.description}</p>
              <div className="finding-card__foot">
                <span className="mono finding-card__cvss">
                  CVSS {f.cvss_score.toFixed(1)} — {f.cvss_vector}
                </span>
                <label className="finding-card__status">
                  <span className="finding-card__status-label">Status</span>
                  <select
                    className="sort-select"
                    value={f.status}
                    disabled={savingId === f.id}
                    onChange={(e) => handleStatusChange(f.id, e.target.value)}
                  >
                    {STATUS_OPTIONS.map((s) => (
                      <option key={s} value={s}>
                        {statusLabel(s)}
                      </option>
                    ))}
                  </select>
                </label>
              </div>
            </article>
          ))}
        </div>
      )}
    </div>
  );
}
