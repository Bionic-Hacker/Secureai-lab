import { useCallback, useEffect, useRef, useState } from "react";
import { triggerCodeScan, getCodeScanFindings } from "../api.js";

const SCANNABLE_EXTENSIONS = new Set([".py", ".js", ".ts", ".jsx", ".tsx"]);

function extensionOf(name) {
  if (!name || !name.includes(".")) return "";
  return "." + name.split(".").pop().toLowerCase();
}

export default function CodeScanPanel({ doc }) {
  const ext = extensionOf(doc.original_filename ?? doc.sanitized_filename);
  const scannable = SCANNABLE_EXTENSIONS.has(ext);

  const [status, setStatus] = useState(doc.code_scan_status ?? "not_scanned");
  const [summary, setSummary] = useState(null);
  const [findings, setFindings] = useState([]);
  const [error, setError] = useState(null);
  const pollRef = useRef(null);

  const poll = useCallback(async () => {
    try {
      const result = await getCodeScanFindings(doc.id);
      setStatus(result.code_scan_status);
      setSummary(result.summary);
      setFindings(result.findings);
      if (result.code_scan_status !== "scanning") {
        clearInterval(pollRef.current);
      }
    } catch (err) {
      setError(err.message);
      clearInterval(pollRef.current);
    }
  }, [doc.id]);

  useEffect(() => {
    if (status === "scanning") {
      pollRef.current = setInterval(poll, 3000);
      return () => clearInterval(pollRef.current);
    }
  }, [status, poll]);

  // Documents scanned in a previous session land here already "completed" -
  // fetch the existing findings once rather than waiting for a click.
  useEffect(() => {
    if (doc.code_scan_status === "completed" || doc.code_scan_status === "failed") {
      poll();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  if (!scannable) return null;

  async function handleScan() {
    setError(null);
    try {
      await triggerCodeScan(doc.id);
      setStatus("scanning");
    } catch (err) {
      setError(err.message);
    }
  }

  return (
    <div className="code-scan">
      {status === "not_scanned" && (
        <button type="button" className="btn btn--ghost" onClick={handleScan}>
          Scan for vulnerabilities
        </button>
      )}

      {status === "scanning" && <p className="code-scan__status mono">Scanning…</p>}

      {status === "failed" && (
        <div>
          <p className="code-scan__status code-scan__status--failed mono">Scan failed.</p>
          <button type="button" className="btn btn--ghost" onClick={handleScan}>
            Retry scan
          </button>
        </div>
      )}

      {status === "completed" && summary && (
        <div>
          <p className="code-scan__summary mono">
            {summary.critical} critical · {summary.high} high · {summary.medium} medium · {summary.low} low
          </p>
          {findings.length > 0 && (
            <ul className="code-scan__findings">
              {findings.map((f) => (
                <li key={f.id} className={`code-scan__finding code-scan__finding--${f.severity}`}>
                  <span className="sev-pill sev-pill--flagged">{f.severity}</span>
                  <span className="code-scan__finding-title">{f.title}</span>
                  {f.line_number != null && <span className="mono">line {f.line_number}</span>}
                </li>
              ))}
            </ul>
          )}
        </div>
      )}

      {error && <p className="code-scan__status code-scan__status--failed mono">{error}</p>}
    </div>
  );
}
