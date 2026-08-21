// Thin client for the SecureAI Lab API.
//
// Auth: the /documents routes go through get_current_user, so a token is
// required. Rather than showing a login screen we sign in on load with the
// dev credentials from .env.local and keep the token in memory. Access tokens
// last 15 minutes, so any 401 triggers one silent re-login and a retry.

const EMAIL = import.meta.env.VITE_DEV_EMAIL;
const PASSWORD = import.meta.env.VITE_DEV_PASSWORD;

// The multipart field name the upload endpoint expects. If uploads fail with
// a 422, open http://localhost:8000/docs, expand POST /api/v1/documents, and
// check the request body field name â€” then change it here.
export const UPLOAD_FIELD = "file";

let accessToken = null;

export async function signIn() {
  const res = await fetch("/api/v1/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email: EMAIL, password: PASSWORD }),
  });
  if (!res.ok) {
    const detail = await readError(res);
    throw new Error(`Sign-in failed (${res.status}). ${detail}`);
  }
  const data = await res.json();
  accessToken = data.access_token;
  return data;
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

async function request(path, options = {}, allowRetry = true) {
  const headers = { ...(options.headers || {}) };
  if (accessToken) headers.Authorization = `Bearer ${accessToken}`;

  const res = await fetch(path, { ...options, headers });

  if (res.status === 401 && allowRetry) {
    await signIn();
    return request(path, options, false);
  }
  if (!res.ok) {
    throw new Error(`${res.status} â€” ${await readError(res)}`);
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
