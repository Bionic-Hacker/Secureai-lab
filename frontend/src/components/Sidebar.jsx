// Icons are inline SVG (no icon library dependency), drawn on a 24px grid
// with currentColor so they follow each item's hover/active colour.
const ICON_PROPS = {
  viewBox: "0 0 24 24",
  width: 18,
  height: 18,
  fill: "none",
  stroke: "currentColor",
  strokeWidth: 1.6,
  strokeLinecap: "round",
  strokeLinejoin: "round",
  className: "sidebar__icon",
  "aria-hidden": true,
};

const ICONS = {
  overview: (
    <svg {...ICON_PROPS}>
      <rect x="3.5" y="3.5" width="7" height="7" rx="1.3" />
      <rect x="13.5" y="3.5" width="7" height="7" rx="1.3" />
      <rect x="3.5" y="13.5" width="7" height="7" rx="1.3" />
      <rect x="13.5" y="13.5" width="7" height="7" rx="1.3" />
    </svg>
  ),
  assistant: (
    <svg {...ICON_PROPS}>
      <path d="M4 5.5h16v11H9l-4 4v-4H4v-11z" />
    </svg>
  ),
  intake: (
    <svg {...ICON_PROPS}>
      <path d="M6 3.5h8l5 5v12a1 1 0 0 1-1 1H6a1 1 0 0 1-1-1v-16a1 1 0 0 1 1-1z" />
      <path d="M14 3.5v5h5" />
    </svg>
  ),
  threatmodel: (
    <svg {...ICON_PROPS}>
      <path d="M12 4l9 15.5H3L12 4z" />
      <path d="M12 10.2v4.2" />
      <circle cx="12" cy="17.4" r=".9" fill="currentColor" stroke="none" />
    </svg>
  ),
  governance: (
    <svg {...ICON_PROPS}>
      <path d="M12 3.5v17" />
      <path d="M5.5 7h13" />
      <path d="M5.5 7l-3 6.2a3.1 3.1 0 0 0 6 0L5.5 7z" />
      <path d="M18.5 7l-3 6.2a3.1 3.1 0 0 0 6 0L18.5 7z" />
    </svg>
  ),
};

const NAV_ITEMS = [
  { key: "overview", label: "Overview" },
  { key: "assistant", label: "AI Security Assistant" },
  { key: "intake", label: "Document Vault" },
  { key: "threatmodel", label: "Threat Modeling" },
  { key: "governance", label: "Governance" },
];

export default function Sidebar({ activeSection, onSelect, user, onLogout }) {
  return (
    <aside className="sidebar">
      <div className="sidebar__brand">
        <span className="sidebar__logo" aria-hidden="true">
          S
        </span>
        <span>
          <span className="sidebar__brand-text">SecureAI Lab</span>
          <span className="sidebar__brand-sub">AppSec Demo Platform</span>
        </span>
      </div>

      <div className="sidebar__section-label">Workspace</div>
      {NAV_ITEMS.map((item) => (
        <button
          key={item.key}
          type="button"
          className={`sidebar__item ${activeSection === item.key ? "sidebar__item--active" : ""}`}
          onClick={() => onSelect(item.key)}
          aria-current={activeSection === item.key ? "page" : undefined}
        >
          {ICONS[item.key]}
          <span>{item.label}</span>
        </button>
      ))}

      <div className="sidebar__build">
        <div className="sidebar__build-label">Build Status</div>
        <div className="sidebar__build-value">Phases 1–8 · Complete</div>
        <div className="sidebar__build-bar" aria-hidden="true">
          <span />
        </div>
      </div>

      {user && (
        <div className="sidebar__account">
          <div className="sidebar__account-name">{user.display_name}</div>
          <div className="sidebar__account-role">{user.role?.replace("_", " ")}</div>
          <button type="button" className="logout-btn" onClick={onLogout}>
            Sign out
          </button>
        </div>
      )}
    </aside>
  );
}
