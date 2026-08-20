# Phase 1 — System Architecture & Security Rationale

## 1. Scope of this phase

Phase 1 delivers the foundation everything else builds on: repository structure,
system architecture, the identity/auth database schema, a fully working
authentication service, and a hardened Docker environment. No AI features yet —
those depend on having real users, roles, and audit logging in place first,
which is itself a security decision (see §4).

## 2. Component architecture

```
                          ┌─────────────────────┐
                          │        nginx         │  TLS termination, edge rate limiting,
                          │  (reverse proxy)      │  security headers, hides backend topology
                          └──────────┬───────────┘
                                     │  (frontend_net — only this hop is internet-facing)
                          ┌──────────▼───────────┐
                          │   FastAPI backend     │  non-root, read-only root fs, cap_drop: ALL
                          │  (Uvicorn, async)     │
                          └───┬────────┬─────┬────┘
                 (backend_net internal only)
           ┌─────────────┘    │        │      └──────────────┐
   ┌───────▼──────┐  ┌────────▼───┐ ┌──▼─────────┐  ┌────────▼────────┐
   │ PostgreSQL 16 │  │   Redis     │ │  ClamAV     │  │   ChromaDB       │
   │ (identity,    │  │ (rate limit,│ │ (malware    │  │ (vector store,   │
   │  audit, docs) │  │  sessions)  │ │  scanning)  │  │  token-auth'd)   │
   └───────────────┘  └─────────────┘ └─────────────┘  └──────────────────┘
```

Key network decision: `backend_net` is a Docker **internal** network — Postgres,
Redis, ClamAV, and ChromaDB have no route to the internet and are not published
on host ports (Postgres binds `127.0.0.1:5432` for local dev debugging only).
The only internet-facing container is `nginx`. This bounds the blast radius of
a backend compromise: even full RCE in the API process can't be used to pull
attacker tools from the internet through those services' egress.

## 3. Why this identity/auth design

**Argon2id over bcrypt.** Argon2id is OWASP's current recommendation — it's
memory-hard, which meaningfully raises the cost of GPU/ASIC cracking compared
to bcrypt at equivalent wall-clock hashing time. Parameters (64MB memory, 3
iterations, 4-way parallelism) follow OWASP's password storage cheat sheet
baseline and are isolated in `core/security.py` so they can be tuned in one
place as hardware improves.

**JWT access tokens are short-lived (15 min) and stateless; refresh tokens are
opaque, server-side, and rotated on every use.** Pure long-lived JWTs can't be
revoked before expiry — if one leaks, it's valid until it expires no matter
what the server does. By keeping access tokens short and backing sessions with
a revocable server-side refresh token, a compromised access token has a small
window, and a compromised refresh token can be invalidated immediately.
Rotation-with-reuse-detection (`auth_service.rotate_refresh_token`) means that
if a stolen refresh token is used after the legitimate client has already
rotated it, the whole token family is revoked — a strong, standard signal of
token theft (this mirrors the OAuth2 refresh token rotation best practice).

**Account lockout is separate from edge rate limiting.** The Redis-backed
`RateLimitMiddleware` throttles by IP; `auth_service`'s lockout logic throttles
by account. An attacker rotating IPs (common in credential stuffing) still
hits the per-account lockout; a shared-IP scenario (e.g. NAT'd office network)
still lets legitimate users elsewhere in on that IP make login attempts against
their own accounts, because the account-level counter is what actually blocks.

**No user enumeration.** Registration, login, and password-reset-request all
return generic responses regardless of whether the email exists. Login also
performs a dummy Argon2 verification when the user isn't found, so response
timing doesn't leak account existence either.

**RBAC is enforced against the database row, not just the JWT claim.** The
`role` claim in the JWT is a convenience/logging hint. `require_roles()` in
`core/deps.py` loads the user fresh from Postgres on every protected request
and checks `user.role` there. Combined with the 15-minute access token TTL,
this bounds how long a demoted or deactivated user can act on stale privileges.

**MFA (TOTP) is checked after password verification, never before.** Revealing
"this account has MFA enabled" before a correct password is supplied would
leak account configuration to an attacker who doesn't yet have valid
credentials.

## 4. Why auth comes before AI features

Every later feature (RAG document isolation, AI request governance logging,
code-review access control) depends on having a real `user_id` to key
permissions and audit records against. Building the AI pipeline first would
mean either bolting authorization on afterward (usually where the gaps are)
or building it single-tenant and re-architecting later. Phase 1 exists so
every subsequent phase inherits `get_current_user` / `require_roles` for free.

## 5. Container hardening summary

- Multi-stage Dockerfile: build tools (`build-essential`, `libpq-dev`) never
  reach the runtime image.
- Runtime container runs as a named non-root user (`secureai`, uid 10001).
- `read_only: true` + `tmpfs: /tmp` on the backend service — the app has no
  business writing to its own filesystem outside `/data/uploads`, which is a
  dedicated named volume.
- `cap_drop: ALL` and `no-new-privileges:true` on every service.
- Healthcheck baked into the image so orchestrators can detect a wedged
  process, not just a crashed one.

## 6. What's deliberately deferred

- `/metrics` Prometheus endpoint (wired into `docker-compose.yml` already,
  implemented in the governance/monitoring phase).
- TLS termination config exists in `Docker/nginx/nginx.conf` but is commented
  out pending real certs — documented rather than faked with a self-signed
  cert checked into the repo.
- Email delivery for password reset (the token issuance/validation logic is
  complete and tested; wiring an actual mail provider is an infra decision
  left for deployment-specific configuration, not a security gap).
