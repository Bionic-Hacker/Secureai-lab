import { useCallback, useEffect, useRef, useState } from "react";
import { signIn, whoAmI, listDocuments, deleteDocument, uploadDocument } from "./api.js";
import IntakeSlot from "./components/IntakeSlot.jsx";
import CustodyTag from "./components/CustodyTag.jsx";

const PENDING = new Set(["pending", "scanning", "in_progress"]);

export default function App() {
  const [phase, setPhase] = useState("connecting");
  const [user, setUser] = useState(null);
  const [docs, setDocs] = useState([]);
  const [fault, setFault] = useState(null);
  const [busy, setBusy] = useState(false);
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

  if (phase === "connecting") {
    return (
      <main className="bench bench--centered">
        <p className="waiting">Opening the benchâ€¦</p>
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

      <section className="shelf">
        {docs.length === 0 ? (
          <p className="shelf__empty">
            Nothing logged yet. Drop a .pdf, .docx or .txt above and it gets a tag.
          </p>
        ) : (
          docs.map((doc) => (
            <CustodyTag key={doc.id} doc={doc} onDelete={() => handleDelete(doc.id)} />
          ))
        )}
      </section>
    </main>
  );
}
