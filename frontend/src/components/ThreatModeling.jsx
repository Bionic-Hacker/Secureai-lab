import { useCallback, useEffect, useRef, useState } from "react";
import {
  listThreatModels,
  createThreatModel,
  getThreatModel,
  addThreatEntry,
  updateThreatEntry,
  deleteThreatEntry,
  reviewThreatModel,
} from "../api.js";

const STRIDE_CATEGORIES = [
  { key: "spoofing", label: "Spoofing" },
  { key: "tampering", label: "Tampering" },
  { key: "repudiation", label: "Repudiation" },
  { key: "info_disclosure", label: "Info Disclosure" },
  { key: "dos", label: "DoS" },
  { key: "elevation", label: "Elevation of Privilege" },
];

const MITIGATION_STATUSES = ["mitigated", "planned", "accepted_risk"];

function formatDate(iso) {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "—";
  return d.toLocaleDateString(undefined, { month: "short", day: "2-digit", year: "numeric" });
}

function EntryForm({ threatModelId, onAdded }) {
  const [strideCategory, setStrideCategory] = useState(STRIDE_CATEGORIES[0].key);
  const [threatDescription, setThreatDescription] = useState("");
  const [affectedAsset, setAffectedAsset] = useState("");
  const [mitigation, setMitigation] = useState("");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState(null);

  async function handleSubmit(e) {
    e.preventDefault();
    if (!threatDescription.trim() || !affectedAsset.trim() || !mitigation.trim()) return;
    setSaving(true);
    setError(null);
    try {
      const entry = await addThreatEntry(threatModelId, {
        stride_category: strideCategory,
        threat_description: threatDescription.trim(),
        affected_asset: affectedAsset.trim(),
        mitigation: mitigation.trim(),
        mitigation_status: "planned",
      });
      onAdded(entry);
      setThreatDescription("");
      setAffectedAsset("");
      setMitigation("");
    } catch (err) {
      setError(err.message);
    } finally {
      setSaving(false);
    }
  }

  return (
    <form className="tm-entry-form" onSubmit={handleSubmit}>
      <div className="tm-entry-form__row">
        <select
          className="sort-select"
          value={strideCategory}
          onChange={(e) => setStrideCategory(e.target.value)}
        >
          {STRIDE_CATEGORIES.map((c) => (
            <option key={c.key} value={c.key}>{c.label}</option>
          ))}
        </select>
        <input
          type="text"
          className="chat-input"
          placeholder="Affected asset"
          value={affectedAsset}
          onChange={(e) => setAffectedAsset(e.target.value)}
        />
      </div>
      <textarea
        className="chat-input tm-entry-form__textarea"
        placeholder="Threat description"
        value={threatDescription}
        onChange={(e) => setThreatDescription(e.target.value)}
        rows={2}
      />
      <textarea
        className="chat-input tm-entry-form__textarea"
        placeholder="Mitigation"
        value={mitigation}
        onChange={(e) => setMitigation(e.target.value)}
        rows={2}
      />
      <button type="submit" className="btn btn--accent" disabled={saving}>
        {saving ? "Adding…" : "Add Entry"}
      </button>
      {error && <p className="gov-error">{error}</p>}
    </form>
  );
}

function ThreatModelDetail({ modelId, onBack, justCreated }) {
  const [model, setModel] = useState(null);
  const [state, setState] = useState("loading");
  const [error, setError] = useState(null);
  const addEntryRef = useRef(null);

  const load = useCallback(async () => {
    setState("loading");
    try {
      const result = await getThreatModel(modelId);
      setModel(result);
      setState("ready");
    } catch (err) {
      setError(err.message);
      setState("error");
    }
  }, [modelId]);

  useEffect(() => {
    load();
  }, [load]);

  // Right after creating a model, skip past six empty STRIDE categories
  // and drop the person straight into the form that actually adds
  // something - the empty-category view was a dead end otherwise.
  useEffect(() => {
    if (justCreated && state === "ready" && addEntryRef.current) {
      addEntryRef.current.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  }, [justCreated, state]);

  async function handleDeleteEntry(entryId) {
    await deleteThreatEntry(modelId, entryId);
    setModel((prev) => ({
      ...prev,
      entries: prev.entries.filter((e) => e.id !== entryId),
    }));
  }

  async function handleStatusChange(entryId, mitigation_status) {
    const updated = await updateThreatEntry(modelId, entryId, { mitigation_status });
    setModel((prev) => ({
      ...prev,
      entries: prev.entries.map((e) => (e.id === entryId ? updated : e)),
    }));
  }

  async function handleReview() {
    const updated = await reviewThreatModel(modelId);
    setModel(updated);
  }

  if (state === "loading") return <p className="gov-loading">Loading threat model…</p>;
  if (state === "error") return <p className="gov-error">Couldn't load: {error}</p>;

  return (
    <div>
      <button type="button" className="btn btn--ghost" onClick={onBack} style={{ marginBottom: "1rem" }}>
        ← Back to threat models
      </button>

      <header className="gov-header">
        <div>
          <h1 className="gov-header__title">{model.title}</h1>
          <p className="gov-header__sub">{model.system_description}</p>
        </div>
      </header>

      <div className="overview-panel" style={{ marginTop: "1rem" }}>
        <div className="tm-status-row">
          <span className={`stamp stamp--${model.status === "reviewed" ? "clean" : "pending"}`}>
            {model.status === "reviewed" ? "Reviewed" : "Draft"}
          </span>
          {model.status !== "reviewed" && (
            <button type="button" className="btn btn--accent" onClick={handleReview}>
              Mark Reviewed
            </button>
          )}
        </div>
      </div>

      {model.entries.length === 0 && (
        <div className="overview-panel">
          <p className="gov-empty">No entries yet — add the first one below.</p>
        </div>
      )}

      {STRIDE_CATEGORIES.map((cat) => {
        const catEntries = model.entries.filter((e) => e.stride_category === cat.key);
        // Only render a category once it actually has something in it -
        // showing all six as empty panels on every model, forever, was
        // pure clutter rather than useful structure.
        if (catEntries.length === 0) return null;
        return (
          <div className="overview-panel" key={cat.key}>
            <div className="overview-panel__title">{cat.label}</div>
            {(
              <div className="tm-entries">
                {catEntries.map((entry) => (
                  <div className="tm-entry" key={entry.id}>
                    <div className="tm-entry__head">
                      <span className="tm-entry__asset mono">{entry.affected_asset}</span>
                      {entry.ai_generated && !entry.human_edited && (
                        <span className="flag-pill">AI-generated</span>
                      )}
                      <button
                        type="button"
                        className="tm-entry__delete"
                        aria-label="Delete entry"
                        title="Delete entry"
                        onClick={() => handleDeleteEntry(entry.id)}
                      >
                        <svg viewBox="0 0 24 24" width="26" height="26" fill="none" stroke="currentColor" strokeWidth="2.75" strokeLinecap="round" strokeLinejoin="round">
                          <polyline points="3 6 5 6 21 6" />
                          <path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6" />
                          <path d="M10 11v6" />
                          <path d="M14 11v6" />
                          <path d="M9 6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2" />
                        </svg>
                      </button>
                    </div>
                    <p className="tm-entry__desc">{entry.threat_description}</p>
                    <p className="tm-entry__mitigation">
                      <span className="tm-entry__label">Mitigation:</span> {entry.mitigation}
                    </p>
                    <select
                      className="sort-select"
                      value={entry.mitigation_status}
                      onChange={(e) => handleStatusChange(entry.id, e.target.value)}
                    >
                      {MITIGATION_STATUSES.map((s) => (
                        <option key={s} value={s}>{s.replace("_", " ")}</option>
                      ))}
                    </select>
                  </div>
                ))}
              </div>
            )}
          </div>
        );
      })}

      <div className="overview-panel" ref={addEntryRef}>
        <div className="overview-panel__title">Add Entry</div>
        <EntryForm
          threatModelId={modelId}
          onAdded={(entry) => setModel((prev) => ({ ...prev, entries: [...prev.entries, entry] }))}
        />
      </div>
    </div>
  );
}

function CreateForm({ onCreated, onCancel }) {
  const [title, setTitle] = useState("");
  const [systemDescription, setSystemDescription] = useState("");
  const [generateWithAi, setGenerateWithAi] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState(null);

  async function handleSubmit(e) {
    e.preventDefault();
    if (!title.trim() || systemDescription.trim().length < 10) return;
    setSaving(true);
    setError(null);
    try {
      const model = await createThreatModel({
        title: title.trim(),
        systemDescription: systemDescription.trim(),
        generateWithAi,
      });
      onCreated(model.id);
    } catch (err) {
      setError(err.message);
      setSaving(false);
    }
  }

  return (
    <div className="overview-panel">
      <div className="overview-panel__title">New Threat Model</div>
      <form onSubmit={handleSubmit} style={{ marginTop: "1rem" }}>
        <input
          type="text"
          className="chat-input"
          placeholder="Title"
          value={title}
          onChange={(e) => setTitle(e.target.value)}
          style={{ marginBottom: "0.75rem", width: "100%" }}
        />
        <textarea
          className="chat-input tm-entry-form__textarea"
          placeholder="Describe the system, its components, trust boundaries, and data flows (min 10 characters)…"
          value={systemDescription}
          onChange={(e) => setSystemDescription(e.target.value)}
          rows={5}
          style={{ width: "100%", marginBottom: "0.75rem" }}
        />
        <label className="tm-checkbox-label">
          <input
            type="checkbox"
            checked={generateWithAi}
            onChange={(e) => setGenerateWithAi(e.target.checked)}
          />
          Generate initial entries with AI
        </label>
        <div style={{ display: "flex", gap: "0.6rem", marginTop: "1rem" }}>
          <button type="submit" className="btn btn--accent" disabled={saving}>
            {saving ? "Creating…" : "Create"}
          </button>
          <button type="button" className="btn btn--ghost" onClick={onCancel} disabled={saving}>
            Cancel
          </button>
        </div>
        {error && <p className="gov-error">{error}</p>}
      </form>
    </div>
  );
}

export default function ThreatModeling() {
  const [view, setView] = useState("list"); // list | create
  const [models, setModels] = useState([]);
  const [state, setState] = useState("loading");
  const [error, setError] = useState(null);
  const [selectedId, setSelectedId] = useState(null);
  const [justCreatedId, setJustCreatedId] = useState(null);

  const load = useCallback(async () => {
    setState("loading");
    try {
      const result = await listThreatModels();
      setModels(result);
      setState("ready");
    } catch (err) {
      setError(err.message);
      setState("error");
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  if (selectedId) {
    return (
      <ThreatModelDetail
        modelId={selectedId}
        justCreated={selectedId === justCreatedId}
        onBack={() => { setSelectedId(null); setJustCreatedId(null); load(); }}
      />
    );
  }

  return (
    <div>
      <header className="gov-header">
        <div>
          <h1 className="gov-header__title">Threat Modeling</h1>
          <p className="gov-header__sub">STRIDE-based threat models for the systems and features you build.</p>
        </div>
      </header>

      {view === "list" && (
        <>
          <button
            type="button"
            className="btn btn--accent"
            style={{ marginTop: "1.5rem" }}
            onClick={() => setView("create")}
          >
            + New Threat Model
          </button>

          {state === "loading" && <p className="gov-loading">Loading threat models…</p>}
          {state === "error" && <p className="gov-error">Couldn't load: {error}</p>}
          {state === "ready" && (
            models.length === 0 ? (
              <p className="gov-empty" style={{ marginTop: "1.5rem" }}>No threat models yet.</p>
            ) : (
              <div className="tm-list">
                {models.map((m) => (
                  <button
                    type="button"
                    key={m.id}
                    className="tm-list-item"
                    onClick={() => setSelectedId(m.id)}
                  >
                    <span className="tm-list-item__title">{m.title}</span>
                    <span className={`stamp stamp--${m.status === "reviewed" ? "clean" : "pending"}`}>
                      {m.status === "reviewed" ? "Reviewed" : "Draft"}
                    </span>
                    <span className="mono">{m.entry_count} entries</span>
                    <span className="mono">{formatDate(m.created_at)}</span>
                  </button>
                ))}
              </div>
            )
          )}
        </>
      )}

      {view === "create" && (
        <div style={{ marginTop: "1.5rem" }}>
          <CreateForm
            onCreated={(id) => { setView("list"); setSelectedId(id); setJustCreatedId(id); }}
            onCancel={() => setView("list")}
          />
        </div>
      )}
    </div>
  );
}
