import { useEffect, useState } from "react";
import { getServiceHealth } from "../api.js";

const SECTION_TITLES = {
  overview: "Operations Overview",
  assistant: "AI Security Assistant",
  intake: "Document Vault",
  codereview: "Code Review Engine",
  threatmodel: "Threat Modeling",
  governance: "Governance",
};

const HEALTH_REFRESH_MS = 60_000;

// The status pill is driven by the real Service Health checks - it never
// claims "Operational" unless every dependency actually answered. Service
// Health is governance-only, so for other roles the pill is simply hidden
// rather than guessed.
function useSystemStatus() {
  const [status, setStatus] = useState({ kind: "loading" });

  useEffect(() => {
    let cancelled = false;

    async function check() {
      try {
        const health = await getServiceHealth();
        if (cancelled) return;
        const components = health?.components ?? [];
        const down = components.filter((c) => c.status !== "healthy");
        setStatus(down.length === 0 ? { kind: "ok" } : { kind: "degraded", down: down.map((c) => c.name) });
      } catch (err) {
        if (cancelled) return;
        setStatus(err.status === 403 ? { kind: "hidden" } : { kind: "unknown" });
      }
    }

    check();
    const timer = setInterval(check, HEALTH_REFRESH_MS);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, []);

  return status;
}

function StatusPill({ status }) {
  if (status.kind === "hidden" || status.kind === "loading") return null;
  if (status.kind === "ok") {
    return (
      <span className="status-pill status-pill--ok" title="Every service health check passed">
        <span className="status-pill__dot" />
        Operational
      </span>
    );
  }
  if (status.kind === "degraded") {
    return (
      <span className="status-pill status-pill--degraded" title={`Unhealthy: ${status.down.join(", ")}`}>
        <span className="status-pill__dot" />
        Degraded
      </span>
    );
  }
  return (
    <span className="status-pill" title="Service health could not be checked">
      <span className="status-pill__dot" />
      Status unknown
    </span>
  );
}

export default function TopBar({ section, user }) {
  const status = useSystemStatus();
  return (
    <header className="topbar">
      <div className="topbar__title">{SECTION_TITLES[section] ?? "SecureAI Lab"}</div>
      <div className="topbar__right">
        <StatusPill status={status} />
        {user && (
          <span className="session-chip">
            <svg
              viewBox="0 0 24 24"
              width="14"
              height="14"
              fill="none"
              stroke="currentColor"
              strokeWidth="1.8"
              strokeLinecap="round"
              strokeLinejoin="round"
              aria-hidden="true"
            >
              <rect x="5" y="10.5" width="14" height="9.5" rx="2" />
              <path d="M8 10.5V7.3a4 4 0 0 1 8 0v3.2" />
            </svg>
            <strong>{user.email}</strong>
            <span className="session-chip__detail">
              · {user.role?.replace("_", " ")} ·{" "}
              <span className={user.mfa_enabled ? "session-chip__mfa--on" : "session-chip__mfa--off"}>
                {user.mfa_enabled ? "MFA enabled" : "MFA off"}
              </span>
            </span>
          </span>
        )}
      </div>
    </header>
  );
}
