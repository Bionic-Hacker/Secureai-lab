import { useEffect, useState } from "react";
import { getKyoraFrameworks } from "../../api.js";

export default function KyoraReference() {
  const [state, setState] = useState("loading"); // loading | denied | error | ready
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const result = await getKyoraFrameworks();
        if (!cancelled) {
          setData(result);
          setState("ready");
        }
      } catch (err) {
        if (cancelled) return;
        if (err.status === 403) {
          setState("denied");
        } else {
          setError(err.message);
          setState("error");
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  if (state === "loading") {
    return <p className="gov-loading">Loading Kyora IQ reference data…</p>;
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
    return <p className="gov-error">Couldn't reach Kyora IQ: {error}</p>;
  }

  const frameworks = data?.frameworks ?? [];

  return (
    <div>
      <div className="overview-panel" style={{ marginTop: 0 }}>
        <p className="overview-panel__desc" style={{ margin: 0 }}>
          Live reference data from Kyora IQ's external compliance MCP server — a separate,
          general-purpose catalog of frameworks and controls, not a claim about what SecureAI Lab
          itself implements. See Framework Coverage for that.
        </p>
      </div>

      {data?.counts && (
        <div className="stat-grid">
          <div className="stat-card">
            <div className="stat-card__label">Frameworks</div>
            <div className="stat-card__value">{data.counts.frameworks}</div>
          </div>
          <div className="stat-card">
            <div className="stat-card__label">Risk Domains</div>
            <div className="stat-card__value">{data.counts.risks}</div>
          </div>
          <div className="stat-card">
            <div className="stat-card__label">Cross-Mappings</div>
            <div className="stat-card__value">{data.counts.mappings}</div>
          </div>
          <div className="stat-card">
            <div className="stat-card__label">Total Controls</div>
            <div className="stat-card__value">{data.counts.total_controls}</div>
          </div>
        </div>
      )}

      <div className="tm-list" style={{ marginTop: "1.5rem" }}>
        {frameworks.map((fw) => (
          <div className="tm-list-item" key={fw.id} style={{ cursor: "default" }}>
            <span className="tm-list-item__title">{fw.name}</span>
            <span className="mono">{fw.version}</span>
            <span className="mono">{fw.controls} {fw.unit}</span>
            <span className="mono">{fw.publisher}</span>
          </div>
        ))}
      </div>

      {data?.attribution && (
        <p className="gov-empty" style={{ marginTop: "1.25rem", fontSize: "0.7rem" }}>
          {data.attribution}
        </p>
      )}
    </div>
  );
}
