import { useRef, useState } from "react";

export default function IntakeSlot({ onFiles, busy }) {
  const inputRef = useRef(null);
  const [over, setOver] = useState(false);

  function drop(e) {
    e.preventDefault();
    setOver(false);
    const files = Array.from(e.dataTransfer.files || []);
    if (files.length) onFiles(files);
  }

  return (
    <div
      className={`slot ${over ? "slot--over" : ""} ${busy ? "slot--busy" : ""}`}
      onDragOver={(e) => {
        e.preventDefault();
        setOver(true);
      }}
      onDragLeave={() => setOver(false)}
      onDrop={drop}
    >
      <div className="slot__mouth" aria-hidden="true">
        <span />
        <span />
        <span />
      </div>
      <div className="slot__copy">
        <p className="slot__lead">
          {busy ? "Logging and scanning???" : "Drop a file to log it"}
        </p>
        <p className="slot__fine">
          .pdf, .docx, .txt, up to 25 MB. Every file is hashed and scanned before it is
          is shelved.
        </p>
      </div>
      <button
        type="button"
        className="slot__browse"
        onClick={() => inputRef.current?.click()}
        disabled={busy}
      >
        Choose a file
      </button>
      <input
        ref={inputRef}
        type="file"
        multiple
        accept=".pdf,.docx,.txt"
        hidden
        onChange={(e) => {
          const files = Array.from(e.target.files || []);
          if (files.length) onFiles(files);
          e.target.value = "";
        }}
      />
    </div>
  );
}

