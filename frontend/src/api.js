// Thin client for the SecureAI Lab API.
//
// Auth: a real login form collects credentials and calls /auth/login.
// The access token lives in memory only (never in browser storage - it's
// the bearer credential itself, and keeping it out of anything durable
// limits what a successful XSS could actually steal). The refresh token
// is opaque and single-use-with-rotation on the backend, so persisting
// it in sessionStorage (cleared when the tab closes, unlike
// localStorage) is what allows a page reload to restore the session
// without a full re-login, while still bounding exposure to the current
// browser session.
const UPLOAD_FIELD = "file";
export { UPLOAD_FIELD };

const REFRESH_STORAGE_KEY = "secureai_refresh_token";

let accessToken = null;
let sessionExpiredCallback = null;

// App.jsx registers this once on mount, so api.js can signal "the
// session is genuinely gone, show the login form again" without needing
// a full state-management library wired through every call site.
export function onSessionExpired(callback) {
  sessionExpiredCallback = callback;
}

async function readError(res) {
  try {
    const body = await res.json();
    if (typeof body.detail === "string") return body.detail;
    if (Array.isArray(body.detail)) {
      return body.detail.map((d) => `${d.loc?.join(".")}: ${d.msg}`).join("; ");
    }
    return JSON.stringify(body);
  } catch {
    return res.statusText;
  }
}

export async function login(email, password) {
  const res = await fetch("/api/v1/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password }),
  });
  if (!res.ok) {
    const detail = await readError(res);
    throw new Error(`Sign-in failed (${res.status}). ${detail}`);
  }
  const data = await res.json();

  // Handled honestly rather than silently mishandled: this project's
  // MFA capability is real, but this login form doesn't implement the
  // verification step yet - a clear, specific error beats a token pair
  // that never actually arrives.
  if (data.mfa_required) {
    throw new Error(
      "This account has MFA enabled. This login form doesn't support MFA verification yet - use an account without MFA, or sign in via the API directly."
    );
  }

  accessToken = data.access_token;
  if (data.refresh_token) {
    sessionStorage.setItem(REFRESH_STORAGE_KEY, data.refresh_token);
  }
  return data;
}

export async function logout() {
  const refreshToken = sessionStorage.getItem(REFRESH_STORAGE_KEY);
  sessionStorage.removeItem(REFRESH_STORAGE_KEY);
  accessToken = null;
  if (refreshToken) {
    try {
      await fetch("/api/v1/auth/logout", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ refresh_token: refreshToken }),
      });
    } catch {
      // Best-effort - the local session is already cleared either way,
      // which is what actually matters for the user in front of this
      // browser right now.
    }
  }
}

async function tryRefresh() {
  const refreshToken = sessionStorage.getItem(REFRESH_STORAGE_KEY);
  if (!refreshToken) return false;
  try {
    const res = await fetch("/api/v1/auth/refresh", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ refresh_token: refreshToken }),
    });
    if (!res.ok) {
      sessionStorage.removeItem(REFRESH_STORAGE_KEY);
      return false;
    }
    const data = await res.json();
    accessToken = data.access_token;
    // Rotated on every use server-side - the old refresh token is no
    // longer valid, so the new one must replace it in storage too.
    if (data.refresh_token) {
      sessionStorage.setItem(REFRESH_STORAGE_KEY, data.refresh_token);
    }
    return true;
  } catch {
    return false;
  }
}

// Called once on app mount - if a refresh token survived a page reload,
// this restores the session silently, without showing the login form
// to someone who was already signed in.
export async function restoreSession() {
  return tryRefresh();
}

async function request(path, options = {}, allowRetry = true) {
  const headers = { ...(options.headers || {}) };
  if (accessToken) headers.Authorization = `Bearer ${accessToken}`;
  const res = await fetch(path, { ...options, headers });
  if (res.status === 401 && allowRetry) {
    const refreshed = await tryRefresh();
    if (refreshed) {
      return request(path, options, false);
    }
    // Refresh itself failed - the session is genuinely gone (expired,
    // revoked, or never existed), not just this one request.
    if (sessionExpiredCallback) sessionExpiredCallback();
    const err = new Error("Session expired. Please sign in again.");
    err.status = 401;
    throw err;
  }
  if (!res.ok) {
    const err = new Error(`${res.status} — ${await readError(res)}`);
    err.status = res.status;
    throw err;
  }
  if (res.status === 204) return null;
  return res.json();
}

export function whoAmI() {
  return request("/api/v1/auth/me");
}
export async function listDocuments() {
  const data = await request("/api/v1/documents");
  // Tolerate either a bare array or a paginated envelope.
  if (Array.isArray(data)) return data;
  return data?.items ?? data?.documents ?? data?.results ?? [];
}
export function uploadDocument(file) {
  const form = new FormData();
  form.append(UPLOAD_FIELD, file);
  return request("/api/v1/documents", { method: "POST", body: form });
}
export function deleteDocument(id) {
  return request(`/api/v1/documents/${id}`, { method: "DELETE" });
}

// ---------------------------------------------------------------- governance ---
// Every function below hits a role-gated endpoint (security_engineer or
// administrator only, see Phase 8) - a 403 here means the signed-in
// account genuinely lacks that role, not a bug. Callers should surface
// err.status === 403 distinctly rather than as a generic failure.

export function getFrameworkCoverage() {
  return request("/api/v1/governance/framework-coverage");
}

export function listFindings({ limit = 50, offset = 0, severity, status, category } = {}) {
  const params = new URLSearchParams({ limit, offset });
  if (severity) params.set("severity", severity);
  if (status) params.set("status_filter", status);
  if (category) params.set("category", category);
  return request(`/api/v1/governance/findings?${params}`);
}

export function updateFindingStatus(findingId, status) {
  return request(`/api/v1/governance/findings/${findingId}/status`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ status }),
  });
}

export function listAuditLog({ limit = 50, offset = 0, eventCategory, outcome } = {}) {
  const params = new URLSearchParams({ limit, offset });
  if (eventCategory) params.set("event_category", eventCategory);
  if (outcome) params.set("outcome", outcome);
  return request(`/api/v1/governance/audit-log?${params}`);
}

export function listAIRequests({ limit = 50, offset = 0, feature, provider, blocked } = {}) {
  const params = new URLSearchParams({ limit, offset });
  if (feature) params.set("feature", feature);
  if (provider) params.set("provider", provider);
  if (blocked !== undefined) params.set("blocked", blocked);
  return request(`/api/v1/governance/ai-requests?${params}`);
}
