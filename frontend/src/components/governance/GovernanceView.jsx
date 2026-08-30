import { useState } from "react";
import FrameworkCoverage from "./FrameworkCoverage.jsx";
import Findings from "./Findings.jsx";
import AuditLog from "./AuditLog.jsx";
import AIRequests from "./AIRequests.jsx";

const TABS = [
  { key: "framework-coverage", label: "Framework Coverage" },
  { key: "findings", label: "Findings" },
  { key: "audit-log", label: "Audit Log" },
  { key: "ai-requests", label: "AI Requests" },
];

export default function GovernanceView() {
  const [activeTab, setActiveTab] = useState(TABS[0].key);

  return (
    <div>
      <header className="gov-header">
        <div>
          <h1 className="gov-header__title">Governance</h1>
          <p className="gov-header__sub">
            Audit trail, findings, AI request telemetry, and framework coverage — read directly from the real
            Phase 8 backend, not sample data.
          </p>
        </div>
      </header>

      <nav className="gov-tabs" role="tablist" aria-label="Governance sections">
        {TABS.map((tab) => (
          <button
            key={tab.key}
            type="button"
            role="tab"
            aria-selected={activeTab === tab.key}
            className={`gov-tab ${activeTab === tab.key ? "gov-tab--active" : ""}`}
            onClick={() => setActiveTab(tab.key)}
          >
            {tab.label}
          </button>
        ))}
      </nav>

      <div className="gov-panel">
        {activeTab === "framework-coverage" && <FrameworkCoverage />}
        {activeTab === "findings" && <Findings />}
        {activeTab === "audit-log" && <AuditLog />}
        {activeTab === "ai-requests" && <AIRequests />}
      </div>
    </div>
  );
}
