-- =============================================================================
-- Least-privilege DB roles.
-- The application NEVER connects as the migration/owner role in production.
-- This limits blast radius if the app tier is compromised (e.g. via a
-- SQLi that survives parameterization mistakes, or a leaked DATABASE_URL):
-- the attacker inherits app_role's grants, not superuser/owner.
-- =============================================================================

-- Owner role: runs migrations only (CI/CD deploy step), never used by the API.
CREATE ROLE secureai_owner WITH LOGIN PASSWORD 'set_via_secrets_manager' NOSUPERUSER NOCREATEDB NOCREATEROLE;
GRANT ALL PRIVILEGES ON DATABASE secureai_lab TO secureai_owner;

-- Application role: what the FastAPI backend actually connects as.
CREATE ROLE secureai_app WITH LOGIN PASSWORD 'set_via_secrets_manager' NOSUPERUSER NOCREATEDB NOCREATEROLE;

GRANT CONNECT ON DATABASE secureai_lab TO secureai_app;
GRANT USAGE ON SCHEMA public TO secureai_app;

GRANT SELECT, INSERT, UPDATE, DELETE ON
    users, refresh_tokens, password_reset_tokens,
    documents, document_permissions, ai_requests
TO secureai_app;

-- Audit log is INSERT + SELECT only for the app: even a full RCE in the API
-- process cannot rewrite or erase its own audit trail. Deletion of audit
-- rows is only possible via the owner role, gated by retention-policy jobs.
GRANT SELECT, INSERT ON audit_log TO secureai_app;
REVOKE UPDATE, DELETE ON audit_log FROM secureai_app;

GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO secureai_app;

-- Read-only role for BI / Grafana Postgres datasource — never sees password
-- hashes or MFA secrets, enforced via column-level revoke.
CREATE ROLE secureai_readonly WITH LOGIN PASSWORD 'set_via_secrets_manager' NOSUPERUSER NOCREATEDB NOCREATEROLE;
GRANT CONNECT ON DATABASE secureai_lab TO secureai_readonly;
GRANT USAGE ON SCHEMA public TO secureai_readonly;
GRANT SELECT ON audit_log, ai_requests TO secureai_readonly;
REVOKE SELECT ON users FROM secureai_readonly;  -- explicit: readonly never gets user PII/secrets
