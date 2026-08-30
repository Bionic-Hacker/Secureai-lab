import { useCallback, useEffect, useState } from "react";
import { listAIRequests } from "../../api.js";

function truncate(text, max = 220) {
  if (!text) return "";
  return text.length > max ? `${text.slice(0, max)}…` : text;
}

function formatTime(iso) {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "—";
  return d.toLocaleString(undefined, {
    month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit",
  });
}

export default function AIRequests() {
  const [state, setState] = useState("loading"); // loading | denied | error | ready
  const [requests, setRequests] = useState([]);
  const [error, setError] = useState(null);
  const [blockedFilter, setBlockedFilter] = useState("all"); // all | true | false

  const load = useCallback(async () => {
    setState("loading");
    try {
      const params = blockedFilter === "all" ? {} : { blocked: blockedFilter };
      const result = await listAIRequests({ limit: 100, ...params });
      setRequests(result);
      setState("ready");
    } catch (err) {
      if (err.status === 403) {
        setState("denied");
      } else {
        setError(err.message);
        setState("error");
      }
    }
  }, [blockedFilter]);

  useEffect(() => {
    load();
  }, [load]);

  if (state === "loading") {
    return <p className="gov-loading">Loading AI request telemetry…</p>;
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
    return <p className="gov-error">Couldn't load AI request telemetry: {error}</p>;
  }

  return (
    <div>
      <div className="toolbar" style={{ marginTop: 0 }}>
        <div className="toolbar__filters" role="group" aria-label="Filter by guardrail outcome">
          <button
            type="button"
            className={`filter-btn ${blockedFilter === "all" ? "filter-btn--active" : ""}`}
            onClick={() => setBlockedFilter("all")}
          >
            All
          </button>
          <button
            type="button"
            className={`filter-btn ${blockedFilter === "true" ? "filter-btn--active filter-btn--flagged" : ""}`}
            onClick={() => setBlockedFilter("true")}
          >
            Blocked
          </button>
          <button
            type="button"
            className={`filter-btn ${blockedFilter === "false" ? "filter-btn--active filter-btn--clean" : ""}`}
            onClick={() => setBlockedFilter("false")}
          >
            Allowed
          </button>
        </div>
      </div>

      {requests.length === 0 ? (
        <p className="gov-empty">No AI requests match this filter.</p>
      ) : (
        <div className="finding-list">
          {requests.map((r) => (
            <article className="ai-req-card" key={r.id}>
              <div className="ai-req-card__head">
                <span className={`outcome-pill outcome-pill--${r.blocked ? "flagged" : "clean"}`}>
                  {r.blocked ? "Blocked" : "Allowed"}
                </span>
                <span className="ai-req-card__feature mono">{r.feature}</span>
                <span className="ai-req-card__meta">
                  {r.provider !== "n/a" ? `${r.provider} · ${r.model}` : "not called"}
                </span>
                <span className="ai-req-card__time mono">{formatTime(r.created_at)}</span>
              </div>

              <p className="ai-req-card__prompt">
                <span className="ai-req-card__label">Prompt</span> {truncate(r.prompt_redacted)}
              </p>
              {r.response_redacted && (
                <p className="ai-req-card__prompt">
                  <span className="ai-req-card__label">Response</span> {truncate(r.response_redacted)}
                </p>
              )}

              {r.guardrail_flags.length > 0 && (
                <div className="ai-req-card__flags">
                  {r.guardrail_flags.map((flag) => (
                    <span key={flag} className="flag-pill">
                      {flag.replace(/_/g, " ")}
                    </span>
                  ))}
                </div>
              )}

              <div className="ai-req-card__foot">
                <span className="mono">
                  {r.input_tokens != null ? `${r.input_tokens} in / ${r.output_tokens} out tokens` : "no token data"}
                </span>
                <span className="mono">{r.latency_ms}ms</span>
                <span className="ai-req-card__user">{r.user_email}</span>
              </div>
            </article>
          ))}
        </div>
      )}
    </div>
  );
}
