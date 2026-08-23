# Semgrep Rules — Actual Location

The custom Semgrep ruleset lives at `backend/semgrep-rules/security-rules.yaml`,
not here, despite `security-tests/` being the documented top-level location
for security tooling in this project's structure.

Reason: Docker's build context for the backend image is `./backend` only
(see `docker-compose.yml`) — a file outside that directory can't be
`COPY`'d into the image. Rather than widen the build context to the whole
repo (a bigger, riskier change with its own tradeoffs), the rules file
lives inside `backend/` where the build can actually see it.

Phase 7 (CI/CD) will reference this same file directly from
`backend/semgrep-rules/security-rules.yaml` when wiring Semgrep into the
GitHub Actions pipeline — no need to duplicate it here for that either.
