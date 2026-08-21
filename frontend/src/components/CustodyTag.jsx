const STATUS_COPY = {
  clean: { label: "Cleared", tone: "clean" },
  pending: { label: "In scan", tone: "pending" },
  scanning: { label: "In scan", tone: "pending" },
  in_progress: { label: "In scan", tone: "pending" },
  infected: { label: "Flagged", tone: "flagged" },
  error: { label: "Scan failed", tone: "flagged" },
};

function bytes(n) {
  if (n == null) return "â€”";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

function logged(iso) {
  if (!iso) return "â€”";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "â€”";
  return d.toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export default function CustodyTag({ doc, onDelete }) {
  const status = STATUS_COPY[doc.malware_scan_status] ?? {
    label: doc.malware_scan_status ?? "Unknown",
    tone: "pending",
  };
  const digest = doc.sha256_hash ?? "";

  return (
    <article className={`tag tag--${status.tone}`}>
      <span className="tag__perf" aria-hidden="true" />

      <div className="tag__head">
        <h2 className="tag__name" title={doc.original_filename}>
          {doc.original_filename ?? doc.sanitized_filename ?? "Untitled"}
        </h2>
        <span className={`stamp stamp--${status.tone}`}>{status.label}</span>
      </div>

      <dl className="tag__facts">
        <div>
          <dt>Type</dt>
          <dd>{doc.content_type ?? "â€”"}</dd>
        </div>
        <div>
          <dt>Size</dt>
          <dd>{bytes(doc.size_bytes)}</dd>
        </div>
        <div>
          <dt>Logged</dt>
          <dd>{logged(doc.created_at)}</dd>
        </div>
        <div>
          <dt>Indexed</dt>
          <dd>{doc.ingestion_status ?? "â€”"}</dd>
        </div>
      </dl>

      {digest && (
        <div className="digest">
          <span className="digest__label">SHA-256</span>
          <code className="digest__value">
            {digest.match(/.{1,8}/g)?.map((chunk, i) => (
              <span key={i}>{chunk}</span>
            ))}
          </code>
        </div>
      )}

      <button type="button" className="tag__remove" onClick={onDelete}>
        Remove from shelf
      </button>
    </article>
  );
}
