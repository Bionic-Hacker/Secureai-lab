import { useCallback, useEffect, useState } from "react";
import { listAuditLog } from "../../api.js";

const CATEGORIES = ["auth", "upload", "governance"];
const OUTCOMES = ["success", "failure", "denied"];

function formatTime(iso) {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "—";
  return d.toLocaleString(undefined, {
    month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit",
  });
}

export default function AuditLog() {
  const [state, setState] = useState("loading"); // loading | denied | error | ready
  const [entries, setEntries] = useState([]);
  const [error, setError] = useState(null);
  const [categoryFilter, setCategoryFilter] = useState("all");
  const [outcomeFilter, setOutcomeFilter] = useState("all");

  const load = useCallback(async () => {
    setState("loading");
    try {
      const params = {};
      if (categoryFilter !== "all") params.eventCategory = categoryFilter;
      if (outcomeFilter !== "all") params.outcome = outcomeFilter;
      const result = await listAuditLog({ limit: 100, ...params });
      setEntries(result);
      setState("ready");
    } catch (err) {
      if (err.status === 403) {
        setState("denied");
      } else {
        setError(err.message);
        setState("error");
      }
    }
  }, [categoryFilter, outcomeFilter]);

  useEffect(() => {
    load();
  }, [load]);

  if (state === "loading") {
    return <p className="gov-loading">Loading audit log…</p>;
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

  if (state === "error") {
    return <p className="gov-error">Couldn't load the audit log: {error}</p>;
  }

  return (
    <div>
      <div className="toolbar" style={{ marginTop: 0 }}>
        <div className="toolbar__filters" role="group" aria-label="Filter by category">
          <button
            type="button"
            className={`filter-btn ${categoryFilter === "all" ? "filter-btn--active" : ""}`}
            onClick={() => setCategoryFilter("all")}
          >
            All categories
          </button>
          {CATEGORIES.map((c) => (
            <button
              key={c}
              type="button"
              className={`filter-btn ${categoryFilter === c ? "filter-btn--active" : ""}`}
              onClick={() => setCategoryFilter(c)}
            >
              {c}
            </button>
          ))}
        </div>
        <div className="toolbar__filters" role="group" aria-label="Filter by outcome">
          <button
            type="button"
            className={`filter-btn ${outcomeFilter === "all" ? "filter-btn--active" : ""}`}
            onClick={() => setOutcomeFilter("all")}
          >
            All outcomes
          </button>
          {OUTCOMES.map((o) => (
            <button
              key={o}
              type="button"
              className={`filter-btn ${outcomeFilter === o ? "filter-btn--active" : ""} ${
                outcomeFilter === o && o !== "success" ? "filter-btn--flagged" : ""
              } ${outcomeFilter === o && o === "success" ? "filter-btn--clean" : ""}`}
              onClick={() => setOutcomeFilter(o)}
            >
              {o}
            </button>
          ))}
        </div>
      </div>

      {entries.length === 0 ? (
        <p className="gov-empty">No audit events match this filter.</p>
      ) : (
        <div className="audit-table-wrap">
          <table className="audit-table">
            <thead>
              <tr>
                <th>Time</th>
                <th>Actor</th>
                <th>Event</th>
                <th>Category</th>
                <th>Resource</th>
                <th>Outcome</th>
              </tr>
            </thead>
            <tbody>
              {entries.map((e) => (
                <tr key={e.id}>
                  <td className="mono">{formatTime(e.occurred_at)}</td>
                  <td>{e.actor_email ?? "system"}</td>
                  <td className="mono">{e.event_type}</td>
                  <td>{e.event_category}</td>
                  <td className="mono">{e.resource_type ? `${e.resource_type}:${e.resource_id}` : "—"}</td>
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
      )}
    </div>
  );
}
