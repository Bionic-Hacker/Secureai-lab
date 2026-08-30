const NAV_ITEMS = [
  { key: "intake", label: "Document Vault" },
  { key: "governance", label: "Governance" },
];

export default function Sidebar({ activeSection, onSelect, user, onLogout }) {
  return (
    <aside className="sidebar">
      <div className="sidebar__brand">
        <span className="sidebar__brand-mark" aria-hidden="true" />
        <span className="sidebar__brand-text">SecureAI Lab</span>
      </div>
      {NAV_ITEMS.map((item) => (
        <button
          key={item.key}
          type="button"
          className={`sidebar__item ${activeSection === item.key ? "sidebar__item--active" : ""}`}
          onClick={() => onSelect(item.key)}
          aria-current={activeSection === item.key ? "page" : undefined}
        >
          {item.label}
        </button>
      ))}

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
