-- =============================================================================
-- SecureAI Lab — PostgreSQL Schema Reference (target end-state, all phases)
--
-- ** THIS FILE IS DOCUMENTATION, NOT EXECUTED AUTOMATICALLY. **
-- As of Phase 2, docker-compose.yml no longer mounts this into Postgres's
-- docker-entrypoint-initdb.d. Alembic (backend/alembic/versions/) is the
-- single source of truth for actual schema changes — this file exists so
-- the full target schema can be read in one place without piecing it
-- together from migration diffs. If you're setting up a fresh environment,
-- run `alembic upgrade head` instead of loading this file.
--
-- Design notes are inline. See documentation/architecture/ for the full
-- rationale behind each phase's additions.
-- =============================================================================

CREATE EXTENSION IF NOT EXISTS "pgcrypto";  -- gen_random_uuid()
CREATE EXTENSION IF NOT EXISTS "citext";    -- case-insensitive email comparisons without LOWER() everywhere

-- -----------------------------------------------------------------------------
-- Roles are a fixed enum, not a free-text column: RBAC decisions must be made
-- against a closed set of values, never against arbitrary strings from a client.
-- -----------------------------------------------------------------------------
CREATE TYPE user_role AS ENUM ('administrator', 'security_engineer', 'developer', 'viewer');

CREATE TABLE users (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email                   CITEXT UNIQUE NOT NULL,
    display_name            VARCHAR(100) NOT NULL,
    password_hash           TEXT NOT NULL,               -- Argon2id, never plaintext/reversible
    role                    user_role NOT NULL DEFAULT 'viewer',
    is_active               BOOLEAN NOT NULL DEFAULT TRUE,
    email_verified           BOOLEAN NOT NULL DEFAULT FALSE,

    -- MFA
    mfa_enabled             BOOLEAN NOT NULL DEFAULT FALSE,
    mfa_secret_encrypted    TEXT,                         -- Fernet(AES-128-CBC+HMAC) at rest, never plaintext
    mfa_recovery_codes_hash TEXT[],                        -- each code hashed individually, single-use

    -- Account lockout / brute-force defense
    failed_login_attempts   INT NOT NULL DEFAULT 0,
    failed_login_window_start TIMESTAMPTZ,
    locked_until            TIMESTAMPTZ,

    -- Password lifecycle
    password_changed_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    must_change_password    BOOLEAN NOT NULL DEFAULT FALSE,

    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_users_email ON users (email);
CREATE INDEX idx_users_role ON users (role);

-- -----------------------------------------------------------------------------
-- Refresh tokens are stored server-side (hashed) so they can be revoked —
-- pure stateless JWT refresh tokens can't be invalidated before expiry.
-- -----------------------------------------------------------------------------
CREATE TABLE refresh_tokens (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash      TEXT NOT NULL UNIQUE,     -- SHA-256 of the token; raw token never stored
    issued_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at      TIMESTAMPTZ NOT NULL,
    revoked_at      TIMESTAMPTZ,
    replaced_by     UUID REFERENCES refresh_tokens(id),
    user_agent      TEXT,
    ip_address      INET
);

CREATE INDEX idx_refresh_tokens_user ON refresh_tokens (user_id);
CREATE INDEX idx_refresh_tokens_hash ON refresh_tokens (token_hash);

-- -----------------------------------------------------------------------------
-- Password reset tokens: single-use, short-lived, hashed at rest.
-- -----------------------------------------------------------------------------
CREATE TABLE password_reset_tokens (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash  TEXT NOT NULL UNIQUE,
    expires_at  TIMESTAMPTZ NOT NULL,
    used_at     TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- -----------------------------------------------------------------------------
-- Audit log: append-only by convention (enforced via REVOKE UPDATE/DELETE for
-- the application role — see database/roles.sql). Every security-relevant
-- action in the system writes here.
-- -----------------------------------------------------------------------------
CREATE TABLE audit_log (
    id              BIGSERIAL PRIMARY KEY,
    occurred_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor_user_id   UUID REFERENCES users(id) ON DELETE SET NULL,
    actor_email     CITEXT,                    -- denormalized so history survives account deletion
    event_type      VARCHAR(64) NOT NULL,       -- e.g. 'login_success', 'login_failed', 'role_changed'
    event_category  VARCHAR(32) NOT NULL,       -- 'auth' | 'upload' | 'ai_request' | 'admin' | 'scan'
    resource_type   VARCHAR(64),
    resource_id     TEXT,
    ip_address      INET,
    user_agent      TEXT,
    metadata        JSONB NOT NULL DEFAULT '{}'::jsonb,
    outcome         VARCHAR(16) NOT NULL DEFAULT 'success'  -- success | failure | denied
);

CREATE INDEX idx_audit_log_actor ON audit_log (actor_user_id);
CREATE INDEX idx_audit_log_event_type ON audit_log (event_type);
CREATE INDEX idx_audit_log_occurred_at ON audit_log (occurred_at DESC);
CREATE INDEX idx_audit_log_category ON audit_log (event_category);

-- -----------------------------------------------------------------------------
-- Documents (Phase 2 preview — table defined now so FKs are stable).
-- Ownership is explicit for RAG tenant isolation: a query can NEVER retrieve
-- vector chunks belonging to a document the requesting user doesn't own or
-- have been explicitly granted access to.
-- -----------------------------------------------------------------------------
CREATE TABLE documents (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_id            UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    original_filename   TEXT NOT NULL,
    sanitized_filename  TEXT NOT NULL,          -- stored name, never the raw client-supplied name
    content_type        VARCHAR(128) NOT NULL,
    size_bytes          BIGINT NOT NULL,
    sha256_hash         CHAR(64) NOT NULL,
    storage_path        TEXT NOT NULL,
    malware_scan_status VARCHAR(16) NOT NULL DEFAULT 'pending',  -- pending|clean|infected|error
    ingestion_status    VARCHAR(16) NOT NULL DEFAULT 'pending',  -- pending|processing|indexed|failed
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_documents_owner ON documents (owner_id);

CREATE TABLE document_permissions (
    document_id UUID NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    permission  VARCHAR(16) NOT NULL DEFAULT 'read', -- read|write
    granted_by  UUID REFERENCES users(id),
    granted_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (document_id, user_id)
);

-- -----------------------------------------------------------------------------
-- AI request log — feeds the governance dashboard (Phase 7). Prompts/responses
-- are stored so admins can review for policy violations; sensitive fields are
-- redacted by the output-guardrail service before insert, not after.
-- -----------------------------------------------------------------------------
CREATE TABLE ai_requests (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id             UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    feature             VARCHAR(32) NOT NULL,   -- 'security_assistant'|'code_review'|'threat_model'
    provider            VARCHAR(16) NOT NULL,   -- 'openai'|'local'
    model               VARCHAR(64) NOT NULL,
    prompt_redacted     TEXT NOT NULL,
    response_redacted   TEXT NOT NULL,
    input_tokens        INT,
    output_tokens        INT,
    guardrail_flags     JSONB NOT NULL DEFAULT '[]'::jsonb,  -- e.g. ["prompt_injection_suspected"]
    blocked             BOOLEAN NOT NULL DEFAULT FALSE,
    latency_ms          INT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_ai_requests_user ON ai_requests (user_id);
CREATE INDEX idx_ai_requests_feature ON ai_requests (feature);
CREATE INDEX idx_ai_requests_created_at ON ai_requests (created_at DESC);

-- updated_at trigger
CREATE OR REPLACE FUNCTION set_updated_at() RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
