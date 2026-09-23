import { useEffect, useState } from "react";
import {
  analyzeKyoraGap,
  getKyoraControl,
  getKyoraFrameworks,
  getKyoraRisk,
  listKyoraRisks,
  searchKyoraControls,
} from "../../api.js";

// Kyora IQ is a third-party source: every field goes through txt() so an
// unexpected shape (an object where a string was expected) renders as
// nothing instead of crashing the tab, and React escapes everything - no
// HTML from the server is ever interpreted.
function txt(value) {
  return typeof value === "string" || typeof value === "number" ? String(value) : "";
}

function useLoad(loader, deps) {
  const [state, setState] = useState({ status: "loading", data: null, error: null });
  useEffect(() => {
    let cancelled = false;
    setState({ status: "loading", data: null, error: null });
    loader()
      .then((data) => {
        if (!cancelled) setState({ status: "ready", data, error: null });
      })
      .catch((err) => {
        if (!cancelled) setState({ status: err.status === 403 ? "denied" : "error", data: null, error: err });
      });
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);
  return state;
}

function LoadState({ state, what }) {
  if (state.status === "loading") return <p className="gov-loading">Loading {what}…</p>;
  if (state.status === "error" || state.status === "denied") {
    return <p className="gov-error">Couldn't load {what}: {state.error?.message}</p>;
  }
  return null;
}

function ControlList({ items, framework, open, empty }) {
  if (!Array.isArray(items) || items.length === 0) return <p className="gov-empty">{empty}</p>;
  return (
    <div className="tm-list">
      {items.map((c, i) => {
        const fw = txt(c.framework) || framework;
        const id = txt(c.id);
        return (
          <button
            type="button"
            key={`${fw}:${id}:${i}`}
            className="tm-list-item"
            disabled={!fw || !id}
            onClick={() => open({ type: "control", framework: fw, controlId: id })}
          >
            <span className="tm-list-item__title">{txt(c.title) || id}</span>
            <span className="mono kyora-id">{txt(c.display_id) || id}</span>
            {txt(c.framework_name) && <span className="mono">{txt(c.framework_name)}</span>}
          </button>
        );
      })}
    </div>
  );
}

function SearchPanel({ framework, frameworks, open }) {
  const [q, setQ] = useState("");
  const [fw, setFw] = useState("");
  const [state, setState] = useState({ status: "idle" });

  async function run(e) {
    e.preventDefault();
    const query = q.trim();
    if (query.length < 2) return;
    setState({ status: "loading" });
    try {
      const data = await searchKyoraControls({ q: query, framework: framework ? framework.id : fw, limit: 50 });
      setState({ status: "ready", data });
    } catch (err) {
      setState({ status: "error", error: err });
    }
  }

  const results = state.data?.results ?? [];
  const total = state.data?.match_count ?? results.length;

  return (
    <div className="overview-panel">
      <div className="overview-panel__title">
        {framework ? `Search ${txt(framework.name)}` : "Search controls across all frameworks"}
      </div>
      <form className="kyora-row" onSubmit={run}>
        <input
          type="text"
          className="chat-input kyora-grow"
          placeholder="e.g. encryption, logging, access control"
          value={q}
          maxLength={200}
          onChange={(e) => setQ(e.target.value)}
        />
        {!framework && (
          <select className="sort-select" value={fw} onChange={(e) => setFw(e.target.value)}>
            <option value="">All frameworks</option>
            {frameworks.map((f) => (
              <option key={f.id} value={f.id}>
                {txt(f.name)}
              </option>
            ))}
          </select>
        )}
        <button type="submit" className="btn btn--accent" disabled={q.trim().length < 2 || state.status === "loading"}>
          Search
        </button>
      </form>
      {state.status === "loading" && <p className="gov-loading">Searching…</p>}
      {state.status === "error" && <p className="gov-error">Search failed: {state.error?.message}</p>}
      {state.status === "ready" && (
        <>
          <p className="kyora-note">
            {total} match{total === 1 ? "" : "es"}
            {results.length < total ? ` · showing the first ${results.length}` : ""}
          </p>
          <ControlList items={results} framework={framework?.id} open={open} empty="No controls matched." />
        </>
      )}
    </div>
  );
}

function GapPanel({ framework, frameworks, open }) {
  const others = frameworks.filter((f) => f.id !== framework.id);
  const [have, setHave] = useState(others[0]?.id ?? "");
  const [state, setState] = useState({ status: "idle" });

  async function run() {
    if (!have) return;
    setState({ status: "loading" });
    try {
      setState({ status: "ready", data: await analyzeKyoraGap(have, framework.id) });
    } catch (err) {
      setState({ status: "error", error: err });
    }
  }

  const d = state.data;
  return (
    <div className="overview-panel">
      <div className="overview-panel__title">Coverage gap analysis</div>
      <p className="kyora-text">
        Which {txt(framework.name)} {txt(framework.unit) || "controls"} are covered by an existing mapping from
        another framework, and which are gaps. Together, the two lists show every top-level item in this framework.
      </p>
      <div className="kyora-row">
        <span className="kyora-note" style={{ marginTop: 0 }}>Starting from</span>
        <select className="sort-select" value={have} onChange={(e) => setHave(e.target.value)}>
          {others.map((f) => (
            <option key={f.id} value={f.id}>
              {txt(f.name)}
            </option>
          ))}
        </select>
        <button type="button" className="btn btn--accent" onClick={run} disabled={!have || state.status === "loading"}>
          Analyze
        </button>
      </div>
      {state.status === "loading" && <p className="gov-loading">Analyzing…</p>}
      {state.status === "error" && <p className="gov-error">Gap analysis failed: {state.error?.message}</p>}
      {state.status === "ready" && d && (
        <>
          <p className="kyora-text">{txt(d.summary)}</p>
          <div className="kyora-gap-cols">
            <div>
              <div className="overview-panel__title">Covered ({(d.covered ?? []).length})</div>
              <ControlList items={d.covered} framework={framework.id} open={open} empty="Nothing covered." />
            </div>
            <div>
              <div className="overview-panel__title">Gaps ({(d.gaps ?? []).length})</div>
              <ControlList items={d.gaps} framework={framework.id} open={open} empty="No gaps." />
            </div>
          </div>
          {txt(d.caveat) && <p className="kyora-note">{txt(d.caveat)}</p>}
        </>
      )}
    </div>
  );
}

function FrameworkView({ framework, frameworks, open }) {
  const meta = [
    txt(framework.version),
    txt(framework.publisher),
    framework.controls != null ? `${txt(framework.controls)} ${txt(framework.unit)}` : "",
  ].filter(Boolean);
  return (
    <div>
      <header className="gov-header">
        <div>
          <h1 className="gov-header__title">{txt(framework.name)}</h1>
          <p className="gov-header__sub">{meta.join(" · ")}</p>
          {txt(framework.source_handling) && (
            <p className="kyora-note">
              Source handling: {txt(framework.source_handling)}
              {txt(framework.license) ? ` · license: ${txt(framework.license)}` : ""}
            </p>
          )}
        </div>
      </header>
      <GapPanel framework={framework} frameworks={frameworks} open={open} />
      <SearchPanel framework={framework} frameworks={frameworks} open={open} />
    </div>
  );
}

function ControlChildren({ items, depth = 0 }) {
  return (
    <ul className="kyora-children">
      {items.map((ch, i) => (
        <li key={txt(ch.id) || i}>
          <span className="mono kyora-id">{txt(ch.display_id) || txt(ch.id)}</span> <strong>{txt(ch.title)}</strong>
          {txt(ch.statement) && <p className="kyora-text">{txt(ch.statement)}</p>}
          {Array.isArray(ch.children) && ch.children.length > 0 && depth < 4 && (
            <ControlChildren items={ch.children} depth={depth + 1} />
          )}
        </li>
      ))}
    </ul>
  );
}

function MappingList({ items }) {
  return (
    <div>
      {items.map((m, i) =>
        typeof m === "string" ? (
          <div key={i} className="kyora-mapping mono">
            {m}
          </div>
        ) : (
          <div key={i} className="kyora-mapping">
            <div className="kyora-mapping__head">
              <span className="mono kyora-id">
                {txt(m.control) || txt(m.display_id) || txt(m.control_id) || txt(m.id) || "—"}
              </span>
              <span>{txt(m.title)}</span>
              <span className="mono kyora-mapping__fw">{txt(m.framework_name) || txt(m.framework)}</span>
            </div>
            {(txt(m.relation) || txt(m.strength) || txt(m.source)) && (
              <div className="mono kyora-mapping__meta">
                {[txt(m.relation), txt(m.strength) && `${txt(m.strength)} match`, txt(m.source) && `source: ${txt(m.source)}`]
                  .filter(Boolean)
                  .join(" · ")}
              </div>
            )}
            {txt(m.rationale) && <p className="kyora-text">{txt(m.rationale)}</p>}
          </div>
        )
      )}
      <p className="kyora-note">
        Mappings with source kyora-iq are Kyora IQ&apos;s own interpretation, not official crosswalks.
      </p>
    </div>
  );
}

function ControlView({ framework, controlId }) {
  const state = useLoad(() => getKyoraControl(framework, controlId), [framework, controlId]);
  if (state.status !== "ready") return <LoadState state={state} what="control" />;

  const d = state.data ?? {};
  const c = d.control ?? {};
  const mappings = Array.isArray(d.mappings) ? d.mappings : [];
  const children = Array.isArray(c.children) ? c.children : [];
  const sub = [txt(d.framework_name) || framework, txt(c.kind), txt(c.layer) && `${txt(c.layer)} layer`].filter(Boolean);

  return (
    <div>
      <header className="gov-header">
        <div>
          <h1 className="gov-header__title">
            <span className="kyora-id">{txt(c.display_id) || controlId}</span> · {txt(c.title)}
          </h1>
          <p className="gov-header__sub">{sub.join(" · ")}</p>
        </div>
      </header>

      <div className="overview-panel">
        <div className="overview-panel__title">Statement</div>
        <p className="kyora-text">{txt(c.statement) || "—"}</p>
        {txt(c.guidance) && (
          <>
            <div className="overview-panel__title" style={{ marginTop: "1rem" }}>Guidance</div>
            <p className="kyora-text">{txt(c.guidance)}</p>
          </>
        )}
        {txt(d.source_handling) && <p className="kyora-note">Source handling: {txt(d.source_handling)}</p>}
      </div>

      {children.length > 0 && (
        <div className="overview-panel">
          <div className="overview-panel__title">Sub-requirements ({children.length})</div>
          <ControlChildren items={children} />
        </div>
      )}

      <div className="overview-panel">
        <div className="overview-panel__title">Cross-framework mappings ({mappings.length})</div>
        {mappings.length === 0 ? (
          <p className="gov-empty">No mappings recorded for this control.</p>
        ) : (
          <MappingList items={mappings} />
        )}
      </div>

      {txt(d.attribution) && <p className="kyora-note">{txt(d.attribution)}</p>}
    </div>
  );
}

function RisksView({ open }) {
  const [layer, setLayer] = useState("");
  const state = useLoad(() => listKyoraRisks(), []);
  if (state.status !== "ready") return <LoadState state={state} what="risk domains" />;

  const risks = Array.isArray(state.data?.risks) ? state.data.risks : [];
  const layers = [...new Set(risks.map((r) => txt(r.layer)).filter(Boolean))];
  const shown = layer ? risks.filter((r) => txt(r.layer) === layer) : risks;

  return (
    <div>
      <header className="gov-header">
        <div>
          <h1 className="gov-header__title">Risk Domains</h1>
          <p className="gov-header__sub">
            {risks.length} cross-framework risk domains, each linking related controls from several frameworks.
          </p>
        </div>
      </header>
      {layers.length > 1 && (
        <div className="kyora-row">
          <button type="button" className={`btn ${layer ? "btn--ghost" : "btn--accent"}`} onClick={() => setLayer("")}>
            All
          </button>
          {layers.map((l) => (
            <button
              type="button"
              key={l}
              className={`btn ${layer === l ? "btn--accent" : "btn--ghost"}`}
              onClick={() => setLayer(l)}
            >
              {l}
            </button>
          ))}
        </div>
      )}
      <div className="tm-list" style={{ marginTop: "1.25rem" }}>
        {shown.map((r) => (
          <button
            type="button"
            key={txt(r.id)}
            className="tm-list-item"
            onClick={() => open({ type: "risk", riskId: txt(r.id) })}
          >
            <span className="tm-list-item__title">{txt(r.title)}</span>
            <span className="mono">{txt(r.layer)}</span>
            <span className="mono">{txt(r.control_count)} controls</span>
          </button>
        ))}
      </div>
    </div>
  );
}

function RiskView({ riskId, open }) {
  const state = useLoad(() => getKyoraRisk(riskId), [riskId]);
  if (state.status !== "ready") return <LoadState state={state} what="risk domain" />;

  const r = state.data?.risk ?? {};
  const resolved = Array.isArray(r.controls_resolved) ? r.controls_resolved : [];
  const items = resolved.map((c) => {
    const ref = txt(c.ref);
    const cut = ref.indexOf(":");
    return {
      framework: cut > 0 ? ref.slice(0, cut) : "",
      id: cut > 0 ? ref.slice(cut + 1) : ref,
      title: c.title,
      display_id: c.display_id,
      framework_name: cut > 0 ? ref.slice(0, cut) : "",
    };
  });

  return (
    <div>
      <header className="gov-header">
        <div>
          <h1 className="gov-header__title">{txt(r.title) || riskId}</h1>
          <p className="gov-header__sub">{txt(r.layer) && `${txt(r.layer)} layer`}</p>
        </div>
      </header>
      <div className="overview-panel">
        <div className="overview-panel__title">Summary</div>
        <p className="kyora-text">{txt(r.summary) || "—"}</p>
      </div>
      <div className="overview-panel">
        <div className="overview-panel__title">Linked controls ({items.length})</div>
        <ControlList items={items} open={open} empty="No controls linked." />
      </div>
      {txt(state.data?.attribution) && <p className="kyora-note">{txt(state.data.attribution)}</p>}
    </div>
  );
}

function Home({ data, open }) {
  const frameworks = Array.isArray(data?.frameworks) ? data.frameworks : [];
  const counts = data?.counts;
  return (
    <div>
      <div className="overview-panel" style={{ marginTop: 0 }}>
        <p className="overview-panel__desc" style={{ margin: 0 }}>
          Live reference data from Kyora IQ&apos;s external compliance MCP server: a separate, general-purpose catalog
          of frameworks and controls, not a claim about what SecureAI Lab itself implements. See Framework Coverage for
          that.
        </p>
      </div>

      {counts && (
        <div className="stat-grid">
          <div className="stat-card">
            <div className="stat-card__label">Frameworks</div>
            <div className="stat-card__value">{txt(counts.frameworks)}</div>
            <div className="stat-card__hint">Select one below</div>
          </div>
          <button type="button" className="stat-card kyora-card--link" onClick={() => open({ type: "risks" })}>
            <div className="stat-card__label">Risk Domains</div>
            <div className="stat-card__value">{txt(counts.risks)}</div>
            <div className="stat-card__hint">Browse →</div>
          </button>
          <div className="stat-card">
            <div className="stat-card__label">Cross-Mappings</div>
            <div className="stat-card__value">{txt(counts.mappings)}</div>
            <div className="stat-card__hint">Shown on each control</div>
          </div>
          <button type="button" className="stat-card kyora-card--link" onClick={() => open({ type: "search" })}>
            <div className="stat-card__label">Total Controls</div>
            <div className="stat-card__value">{txt(counts.total_controls)}</div>
            <div className="stat-card__hint">Search →</div>
          </button>
        </div>
      )}

      <div className="tm-list" style={{ marginTop: "1.5rem" }}>
        {frameworks.map((fw) => (
          <button
            type="button"
            className="tm-list-item"
            key={txt(fw.id)}
            onClick={() => open({ type: "framework", framework: fw })}
          >
            <span className="tm-list-item__title">{txt(fw.name)}</span>
            <span className="mono">{txt(fw.version)}</span>
            <span className="mono">
              {txt(fw.controls)} {txt(fw.unit)}
            </span>
            <span className="mono">{txt(fw.publisher)}</span>
          </button>
        ))}
      </div>

      {txt(data?.attribution) && (
        <p className="gov-empty" style={{ marginTop: "1.25rem", fontSize: "0.7rem" }}>
          {txt(data.attribution)}
        </p>
      )}
    </div>
  );
}

export default function KyoraReference() {
  const home = useLoad(() => getKyoraFrameworks(), []);
  const [stack, setStack] = useState([]);

  function open(view) {
    setStack((s) => [...s, view]);
    window.scrollTo({ top: 0, behavior: "smooth" });
  }

  if (home.status === "loading") return <p className="gov-loading">Loading Kyora IQ reference data…</p>;
  if (home.status === "denied") {
    return (
      <div className="gov-denied">
        <h2 className="gov-denied__title">Governance access required</h2>
        <p className="gov-denied__detail">
          This section requires the <code>security_engineer</code> or <code>administrator</code> role.
        </p>
      </div>
    );
  }
  if (home.status === "error") return <p className="gov-error">Couldn&apos;t reach Kyora IQ: {home.error?.message}</p>;

  const frameworks = Array.isArray(home.data?.frameworks) ? home.data.frameworks : [];
  const view = stack[stack.length - 1];
  if (!view) return <Home data={home.data} open={open} />;

  return (
    <div>
      <div className="kyora-nav">
        <button type="button" className="btn btn--ghost" onClick={() => setStack((s) => s.slice(0, -1))}>
          ← Back
        </button>
        {stack.length > 1 && (
          <button type="button" className="btn btn--ghost" onClick={() => setStack([])}>
            Kyora IQ home
          </button>
        )}
      </div>
      <div key={stack.length}>
        {view.type === "framework" && <FrameworkView framework={view.framework} frameworks={frameworks} open={open} />}
        {view.type === "control" && <ControlView framework={view.framework} controlId={view.controlId} />}
        {view.type === "risks" && <RisksView open={open} />}
        {view.type === "risk" && <RiskView riskId={view.riskId} open={open} />}
        {view.type === "search" && (
          <div>
            <header className="gov-header">
              <div>
                <h1 className="gov-header__title">Search Controls</h1>
                <p className="gov-header__sub">Full-text search across every framework in Kyora IQ&apos;s catalog.</p>
              </div>
            </header>
            <SearchPanel frameworks={frameworks} open={open} />
          </div>
        )}
      </div>
    </div>
  );
}
