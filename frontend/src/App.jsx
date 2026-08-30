import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { signIn, whoAmI, listDocuments, deleteDocument, uploadDocument } from "./api.js";
import IntakeSlot from "./components/IntakeSlot.jsx";
import CustodyTag from "./components/CustodyTag.jsx";

const PENDING = new Set(["pending", "scanning", "in_progress"]);

const FILTERS = [
  { key: "all", label: "All" },
  { key: "clean", label: "Cleared", tone: "clean" },
  { key: "pending", label: "In scan", tone: "pending" },
  { key: "flagged", label: "Flagged", tone: "flagged" },
];

function statusTone(status) {
  if (status === "clean") return "clean";
  if (PENDING.has(status)) return "pending";
  if (status === "infected" || status === "error") return "flagged";
  return "pending";
}

export default function App() {
  const [phase, setPhase] = useState("connecting");
  const [user, setUser] = useState(null);
  const [docs, setDocs] = useState([]);
  const [fault, setFault] = useState(null);
  const [busy, setBusy] = useState(false);
  const [filter, setFilter] = useState("all");
  const [sortBy, setSortBy] = useState("date_desc");
  const pollRef = useRef(null);

  const refresh = useCallback(async () => {
    const items = await listDocuments();
    setDocs(items);
    return items;
  }, []);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        await signIn();
        const me = await whoAmI();
        if (cancelled) return;
        setUser(me);
        await refresh();
        if (!cancelled) setPhase("ready");
      } catch (err) {
        if (!cancelled) {
          setFault(err.message);
          setPhase("faulted");
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [refresh]);

  // Scanning happens out of band, so poll while anything is still pending.
  useEffect(() => {
    const waiting = docs.some((d) => PENDING.has(d.malware_scan_status));
    clearInterval(pollRef.current);
    if (phase === "ready" && waiting) {
      pollRef.current = setInterval(() => refresh().catch(() => {}), 4000);
    }
    return () => clearInterval(pollRef.current);
  }, [docs, phase, refresh]);

  async function handleFiles(files) {
    setBusy(true);
    setFault(null);
    try {
      for (const file of files) await uploadDocument(file);
      await refresh();
    } catch (err) {
      setFault(err.message);
    } finally {
      setBusy(false);
    }
  }

  async function handleDelete(id) {
    setFault(null);
    try {
      await deleteDocument(id);
      setDocs((prev) => prev.filter((d) => d.id !== id));
    } catch (err) {
      setFault(err.message);
    }
  }

  // Filtering and sorting happen client-side over whatever the API already
  // returned - no extra request, and it stays instant as the shelf grows.
  const visibleDocs = useMemo(() => {
    let items = docs;
    if (filter !== "all") {
      items = items.filter((d) => statusTone(d.malware_scan_status) === filter);
    }
    const sorted = [...items];
    switch (sortBy) {
      case "date_asc":
        sorted.sort((a, b) => new Date(a.created_at) - new Date(b.created_at));
        break;
      case "name_asc":
        sorted.sort((a, b) =>
          (a.original_filename ?? "").localeCompare(b.original_filename ?? "")
        );
        break;
      case "status":
        sorted.sort((a, b) =>
          statusTone(a.malware_scan_status).localeCompare(statusTone(b.malware_scan_status))
        );
        break;
      case "date_desc":
      default:
        sorted.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
    }
    return sorted;
  }, [docs, filter, sortBy]);

  if (phase === "connecting") {
    return (
      <main className="bench bench--centered">
        <p className="waiting">Opening the bench…</p>
      </main>
    );
  }

  if (phase === "faulted") {
    return (
      <main className="bench bench--centered">
        <div className="fault">
          <h1 className="fault__title">The bench is closed</h1>
          <p className="fault__detail">{fault}</p>
          <ul className="fault__checks">
            <li>Is the stack up? <code>docker compose ps</code></li>
            <li>Does the account in <code>frontend/.env.local</code> exist?</li>
            <li>Is nginx answering? <code>curl http://localhost:8080/healthz</code></li>
          </ul>
        </div>
      </main>
    );
  }

  const clean = docs.filter((d) => d.malware_scan_status === "clean").length;
  const waiting = docs.filter((d) => PENDING.has(d.malware_scan_status)).length;

  return (
    <main className="bench">
      <header className="masthead">
        <div className="masthead__mark">
          <span className="masthead__rule" aria-hidden="true" />
          <h1 className="masthead__title">Intake</h1>
        </div>
        <dl className="ledger">
          <div className="ledger__cell">
            <dt>Held</dt>
            <dd>{String(docs.length).padStart(3, "0")}</dd>
          </div>
          <div className="ledger__cell">
            <dt>Cleared</dt>
            <dd>{String(clean).padStart(3, "0")}</dd>
          </div>
          <div className="ledger__cell">
            <dt>In scan</dt>
            <dd>{String(waiting).padStart(3, "0")}</dd>
          </div>
          <div className="ledger__cell ledger__cell--wide">
            <dt>Custodian</dt>
            <dd className="ledger__who">
              {user?.display_name}
              <span className="ledger__role">{user?.role?.replace("_", " ")}</span>
            </dd>
          </div>
        </dl>
      </header>

      <IntakeSlot onFiles={handleFiles} busy={busy} />

      {fault && (
        <p className="notice" role="alert">
          {fault}
        </p>
      )}

      {docs.length > 0 && (
        <div className="toolbar">
          <div className="toolbar__filters" role="group" aria-label="Filter by status">
            {FILTERS.map((f) => (
              <button
                key={f.key}
                type="button"
                className={`filter-btn ${filter === f.key ? "filter-btn--active" : ""} ${
                  filter === f.key && f.tone ? `filter-btn--${f.tone}` : ""
                }`}
                onClick={() => setFilter(f.key)}
                aria-pressed={filter === f.key}
              >
                {f.label}
              </button>
            ))}
          </div>
          <div className="toolbar__sort">
            <label htmlFor="sort-select">Sort</label>
            <select
              id="sort-select"
              className="sort-select"
              value={sortBy}
              onChange={(e) => setSortBy(e.target.value)}
            >
              <option value="date_desc">Newest logged</option>
              <option value="date_asc">Oldest logged</option>
              <option value="name_asc">Name (A–Z)</option>
              <option value="status">Status</option>
            </select>
          </div>
        </div>
      )}

      <section className="shelf">
        {docs.length === 0 ? (
          <p className="shelf__empty">
            Nothing logged yet. Drop a .pdf, .docx or .txt above and it gets a tag.
          </p>
        ) : visibleDocs.length === 0 ? (
          <p className="shelf__empty">No documents match this filter.</p>
        ) : (
          visibleDocs.map((doc) => (
            <CustodyTag key={doc.id} doc={doc} onDelete={() => handleDelete(doc.id)} />
          ))
        )}
      </section>
    </main>
  );
}
