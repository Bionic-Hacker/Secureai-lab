import { useEffect, useState } from "react";
import { getFrameworkCoverage } from "../../api.js";

const STATUS_LABEL = {
  implemented: "Implemented",
  partial: "Partial",
  not_applicable: "N/A",
};

export default function FrameworkCoverage() {
  const [state, setState] = useState("loading"); // loading | denied | error | ready
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const result = await getFrameworkCoverage();
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
    return <p className="gov-loading">Loading framework coverage…</p>;
  }

  if (state === "denied") {
    return (
      <div className="gov-denied">
        <h2 className="gov-denied__title">Governance access required</h2>
        <p className="gov-denied__detail">
          This section requires the <code>security_engineer</code> or <code>administrator</code> role. The
          signed-in account doesn't currently have it — this is the real, working access control from Phase 8,
          not a bug in this view.
        </p>
      </div>
    );
  }

  if (state === "error") {
    return <p className="gov-error">Couldn't load framework coverage: {error}</p>;
  }

  const totalControls = data.frameworks.reduce((sum, f) => sum + f.controls.length, 0);
  const implementedCount = data.frameworks.reduce(
    (sum, f) => sum + f.controls.filter((c) => c.status === "implemented").length,
    0
  );
  const partialCount = data.frameworks.reduce(
    (sum, f) => sum + f.controls.filter((c) => c.status === "partial").length,
    0
  );

  return (
    <div>
      <p className="fw-methodology">{data.methodology}</p>

      <dl className="fw-summary">
        <div className="fw-summary__cell">
          <dt>Frameworks</dt>
          <dd>{data.frameworks.length}</dd>
        </div>
        <div className="fw-summary__cell">
          <dt>Controls tracked</dt>
          <dd>{totalControls}</dd>
        </div>
        <div className="fw-summary__cell">
          <dt>Implemented</dt>
          <dd>{implementedCount}</dd>
        </div>
        <div className="fw-summary__cell">
          <dt>Partial</dt>
          <dd>{partialCount}</dd>
        </div>
      </dl>

      {data.frameworks.map((framework) => (
        <div className="fw-group" key={framework.id}>
          <h3 className="fw-group__title">{framework.name}</h3>
          {framework.controls.map((control) => (
            <div className="fw-control" key={control.control_id}>
              <div className="fw-control__head">
                <span>
                  <span className="fw-control__id">{control.control_id}</span>
                  <span className="fw-control__name">{control.name}</span>
                </span>
                <span className={`status-pill status-pill--${control.status}`}>
                  {STATUS_LABEL[control.status] ?? control.status}
                </span>
              </div>
              <p className="fw-control__evidence">{control.evidence}</p>
              <span className="fw-control__phase">Phase {control.phase}</span>
            </div>
          ))}
        </div>
      ))}
    </div>
  );
}
