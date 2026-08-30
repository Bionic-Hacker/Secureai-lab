# SecureAI Lab — AI-Specific Incident Response Runbook

This runbook covers incident types specific to this platform's AI features
(the Security Assistant and RAG pipeline) and the areas where AI-driven
functionality intersects with traditional application security. It
deliberately does not restate a generic "how to run an incident response
process" document — every step below references a real endpoint, real
table, or real script that actually exists in this codebase today, not a
hypothetical capability.

Every command below assumes the standard local operating context used
throughout this project: `$REAL` set to the project root, `docker compose`
run from there, and a valid `security_engineer`/`administrator`-role
account for any `/governance/*` endpoint call (see Phase 8 — these
endpoints are role-gated; a `viewer`-role token will get a real 403, not
a partial response).

---

## 1. Prompt Injection Detected (Guardrail Blocked It)

**This is the well-instrumented, expected-working case** — the input
guardrail (`app/services/guardrails.py`) catches this before any request
reaches the model.

**Detection**: A blocked request produces `blocked: true`,
`guardrail_flags: ["prompt_injection_suspected"]`, and `latency_ms: 0` in
the `ai_requests` table — the zero latency is itself confirmation the
model was never called.

**Investigation**:
```
GET /api/v1/governance/ai-requests?blocked=true&limit=50
```
Review `prompt_redacted` for each entry to understand what was attempted
and by which account (`user_email`). A cluster of blocked attempts from
one account in a short window is worth escalating to Section 2 below —
repeated, systematic probing is a different risk profile than a single
curious/adversarial-testing attempt.

**Containment**: None needed for this case specifically — the control
already worked. If the volume suggests deliberate, sustained probing,
consider the account-lockout mechanism (`account_lockout_threshold`,
Phase 1) as a next escalation, though note it applies to failed *logins*,
not blocked AI requests — there is currently no automatic lockout tied to
guardrail-block volume specifically. That is a real gap, documented here
rather than implied to be covered.

---

## 2. Suspected Guardrail Bypass (Something Got Through)

The input guardrail is explicitly documented in its own source as "a
real, working first layer," not a claim of complete coverage
(`guardrails.py`'s own module docstring). A sophisticated injection
attempt worded to avoid all seven current regex patterns is a real,
acknowledged possibility, not a hypothetical.

**Detection**: No automatic signal exists for this today — a successful
bypass produces `blocked: false` and looks identical to a legitimate
request in `ai_requests`. Detection is currently manual: reviewing
`prompt_redacted` and `response_redacted` for entries that got a real
model response but whose *content* is concerning, even though the
guardrail didn't flag them.

```
GET /api/v1/governance/ai-requests?feature=security_assistant&blocked=false&limit=100
```

**Investigation**: For any suspicious-but-unblocked entry, check the
`response_redacted` field — did the model produce something it shouldn't
have (system-prompt disclosure, content unrelated to the security-tool
scope, anything resembling the model following an embedded instruction)?

**Containment**:
1. Add a new pattern to `_INJECTION_PATTERNS` in `guardrails.py` covering
   the specific phrasing that got through, following the project's own
   adversarial eval suite pattern (`tests/test_assistant_guardrails.py`)
   — add the new case there too, so this specific bypass becomes a
   permanent regression test, not just a one-time fix.
2. Rebuild and redeploy the backend.
3. Re-run the eval suite to confirm the new pattern catches the case
   without breaking the existing clean-question tests (the false-positive
   check in that same suite).

**Follow-up**: Record the incident and the pattern added via
`PATCH /api/v1/governance/findings/{id}/status` if a corresponding
finding is tracked, or note it in the audit log's `metadata` field for
the relevant manual review action, so the governance dashboard reflects
that this happened and was addressed, not just that it was fixed
silently in code.

---

## 3. Suspected RAG Cross-Tenant Data Leakage

**The highest-severity scenario this platform could face** — one user's
document content surfacing in another user's retrieval results. This is
the exact risk the Phase 3 isolation architecture and the Phase 6
self-assessment threat model were built to prevent, and the one this
project has invested the most direct testing effort in.

**Detection**: No automated alerting exists for this today (a real gap,
noted rather than glossed over). The signal would most likely be a user
report ("I saw content I shouldn't have") or an anomaly noticed during
manual `ai-requests`/RAG-query review.

**Immediate verification — do this first, before anything else**:
```
docker compose exec backend python3 -m app.scripts.verify_rag_canary \
    <owner_email> <owner_password> <other_email> <other_password>
```
This is the same canary/honeytoken script built and verified in Phase 8
— it plants a fresh, uniquely-generated secret through the real upload
pipeline and confirms whether it leaks to a second real account, through
the real API surface. Run this immediately on any leakage report,
using the two accounts actually involved if known, or two fresh test
accounts otherwise. A `PASS` result here doesn't rule out every possible
cause, but a `FAIL` result is an immediate, unambiguous confirmation the
isolation guarantee has genuinely broken — not a false alarm.

**Containment (if the canary check fails)**:
1. This is severe enough to warrant taking the RAG query endpoint offline
   while investigating — there is no existing feature-flag for this
   specifically; the fastest real containment is stopping the `vector-db`
   (ChromaDB) container or blocking the `/api/v1/rag/query` route at the
   nginx layer.
2. Review `app/services/vector_store.py` — specifically whether
   `allowed_document_ids` is being correctly computed and passed on every
   call path, and whether the `$in` metadata filter is genuinely being
   applied server-side rather than accidentally bypassed.
3. Check the audit log for recent changes to permission-related code or
   configuration:
```
GET /api/v1/governance/audit-log?event_category=upload&limit=100
```

**Recovery**: Re-run the canary script after any fix, before considering
the endpoint safe to bring back online. A single passing run is the
minimum bar, not sufficient proof on its own for an incident this
severe — consider running it multiple times with different account pairs.

---

## 4. Malware Detected in an Uploaded Document

**This is also a well-instrumented, expected-working case** — ClamAV
(Phase 2) scans every upload before it's ever shelved/indexed.

**Detection**: `malware_scan_status: "infected"` on the document record;
the document is never made available for download or RAG ingestion.

**Investigation**:
```
GET /api/v1/governance/audit-log?event_category=upload&outcome=failure
```
Combined with checking which account uploaded the file, and whether that
account has uploaded other suspicious content recently.

**Containment**: Already automatic — an infected file is blocked from
ever being persisted in usable form (Phase 2's `document_service`
rejects it before ingestion). No manual action is required for the file
itself. Consider account-level review if the same account has multiple
infected-upload attempts.

---

## 5. Leaked or Compromised API Credentials

**Not a hypothetical for this project** — an OpenAI API key was
genuinely exposed earlier in this project's history and required
rotation. This section reflects lessons from that real event, not a
generic template.

**Immediate containment**:
1. Revoke the exposed key at the provider immediately (OpenAI dashboard,
   or the equivalent for whichever provider is affected).
2. Rotate to a new key in `.env` — never commit the new key; confirm
   `.env` remains in `.gitignore` before doing anything else.
3. If the key was ever committed to git history (not just present in an
   uncommitted local file), treat it as permanently compromised even
   after rotation and removal — git history rewriting is a separate,
   more invasive follow-up decision, not a substitute for rotation.

**Investigation**: Check whether Gitleaks (Phase 7's `security.yml`,
secret-detection job) should have caught this and didn't — if so, that's
a gap in the detection layer itself worth understanding, not just the
exposure incident in isolation.

**Prevention check**: Confirm the CI secret-scanning gate
(`docker run zricethezav/gitleaks:latest detect --source /repo`) is
still active and scanning full git history (`--no-git` flag scope,
Phase 7) on every push, not just the working tree.

---

## 6. Local Model Provider (Ollama) Unavailable

**A real operational scenario this project has directly experienced** —
cold-start latency on the local model can run 60-100+ seconds, and the
provider can be entirely unreachable if the `ollama` container isn't
running or the model hasn't been pulled.

**Detection**: Assistant requests fail or hang; `ai_requests` entries (if
they complete at all) would show unusually high `latency_ms` or the
request errors out before a row is even written.

**Immediate check**:
```
docker compose ps ollama
docker compose exec ollama ollama list
```

**Containment**: This project supports both a `local` and `n/a`/hosted
provider path (`AI_PROVIDER` setting, Phase 4) — switching
`AI_PROVIDER` in `.env` and restarting the backend is the fastest
mitigation if the local provider is down and a hosted fallback is
configured and acceptable for the situation.

**Follow-up**: No automatic health check or alerting currently exists
specifically for Ollama's availability, beyond the general Prometheus
service-health dashboard (Phase 1) showing the container as up/down.
Model-response-latency-specific alerting is a real gap, not yet built.

---

## 7. Actively-Exploited Dependency CVE

**Directly informed by Phase 7's real remediation history** — this
project has already gone through this exact process multiple times
(the `starlette` BadHost auth bypass being the most severe example) and
this section reflects what that process actually looked like, not a
theoretical procedure.

**Detection**: Trivy (Container Scan) or `pip-audit` (Security Scans)
flags a new CVE in a dependency on the next scheduled/triggered CI run,
or via a public disclosure/advisory reaching you directly.

**Triage** — three real, distinct outcomes, matching the actual pattern
established in this project's own `.trivyignore` and commit history:
1. **Fix directly** if a compatible patched version exists — verify the
   fix locally (`docker compose up --build`), re-test the affected
   functionality specifically (not just "the container starts"), then
   commit.
2. **Document as accepted risk** if a fix genuinely conflicts with
   another real constraint (see the `setuptools`/Semgrep conflict,
   Phase 7) — every accepted-risk entry in `.trivyignore` requires a
   real, specific technical justification and an expiry date forcing
   periodic re-review, not just "can't fix it right now."
3. **Defer with documentation** if the fix itself is blocked by a deeper
   dependency-resolution issue (see `protobuf`, Phase 7) — document the
   attempts made and the real root cause, so the next person doesn't
   have to re-diagnose from zero.

**Never**: silently ignore a flagged CVE, or dismiss a GitHub Code
Scanning alert without either a real fix or a documented, justified
reason in both the alert itself and `.trivyignore`.

---

## Escalation & Ownership

This is a portfolio/lab project with a single maintainer — there is no
multi-person on-call rotation to define here. What this section
documents instead is the actual decision trail every incident above
should leave behind:

1. The real finding or event, in `audit_log` or `ai_requests` (already
   automatic for anything that goes through those tables).
2. The remediation or containment action taken.
3. A `PATCH /api/v1/governance/findings/{id}/status` update if the
   incident corresponds to a tracked finding, with the status change
   itself audit-logged automatically (Phase 8).
4. A note in this document if the incident reveals a genuine gap in
   detection or process — several are already flagged above (no
   automated leakage alerting, no guardrail-bypass detection, no
   Ollama-specific health alerting) rather than papered over.
