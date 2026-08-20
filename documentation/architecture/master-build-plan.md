# SecureAI Lab — Master Build Plan & Framework Mapping

This document is the north star for the rest of the build: every phase below
ships code, every control maps to a named framework requirement, and the
mapping tables are what you'll point to in interviews or a portfolio writeup
("here's my JWT rotation logic, here's the OWASP API4:2023 control it
satisfies, here's the NIST 800-53 control ID behind it").

---

## 0. Platform decision: GitHub + Vercel

Vercel is excellent for the **frontend** (React/TS, edge network, preview
deployments per PR, zero-config HTTPS) and fine for **stateless serverless
functions**. It is the wrong home for:

- PostgreSQL (no persistent storage)
- ChromaDB (needs a persistent process + disk)
- ClamAV (long-running daemon, large virus-definition files)
- A stateful FastAPI app with WebSocket/streaming AI responses beyond ~60s
  serverless execution limits (Vercel Functions have a max duration; Hobby
  tier is far shorter than Pro/Enterprise)

**Revised architecture:**

| Component | Where it runs | Why |
|---|---|---|
| Frontend (React/TS/Tailwind) | **Vercel** | Native fit — SSG/ISR, preview URLs per PR, edge CDN |
| FastAPI backend | **Fly.io / Railway / Render** (containerized, same Dockerfile from Phase 1) | Needs persistent connections, background jobs (embedding generation, malware scans), longer request lifetimes |
| PostgreSQL | **Neon / Supabase / Railway Postgres** (managed) | Managed backups, PITR, connection pooling (pgbouncer) — don't hand-roll HA Postgres for a portfolio project |
| ChromaDB | Same host as backend, or **Chroma Cloud** | Needs to sit close to the backend for latency; can be a sidecar container on Fly/Railway |
| ClamAV | Sidecar container next to backend | Same reasoning |
| Redis (rate limiting, session state) | **Upstash Redis** (serverless-friendly, REST API works from Vercel edge too) | Matches serverless/edge runtime constraints if you ever move guardrail checks to Vercel edge middleware |
| Secrets | **GitHub Actions Secrets** (CI) + **Vercel Environment Variables** (frontend) + backend host's secret manager | Never in `.env` committed anywhere — `.env.example` stays the only committed env file |

This means `docker-compose.yml` from Phase 1 becomes your **local dev
environment**, and a separate `Docker/fly.toml` / `render.yaml` becomes the
actual deployment target. I'll build both — this is itself a good AppSec
portfolio point: local parity vs. production topology, documented explicitly
rather than assumed.

CI/CD becomes: **GitHub Actions runs all security gates → on pass, Vercel
auto-deploys frontend (native GitHub integration) → a deploy job pushes the
backend image to the container host.**

---

## 1. Enhancements beyond your original spec

Worth adding because they're exactly what senior AppSec/AI-security
reviewers look for and materially strengthen the framework mappings below:

1. **SBOM generation** (CycloneDX or Syft) on every build — required for
   NIST 800-53 (SA-15(10)/CM-8 alignment) and increasingly for EU/US supply-
   chain expectations. Cheap to add to CI, high signal.
2. **Model/prompt versioning + eval regression suite** — track system-prompt
   changes in git, run a fixed adversarial-prompt eval set on every PR that
   touches `ai-engine/`. This is the concrete artifact NIST AI RMF's MEASURE
   function and ISO 42001's performance-monitoring clause ask for.
3. **Dependency-confusion / typosquat check** for both `pip` and `npm` in
   CI, not just known-CVE scanning — different threat, same supply chain.
4. **Signed commits + branch protection + required reviews** on `main` —
   free with GitHub, satisfies NIST 800-53 CM-3/CM-5 and is a five-minute
   repo setting that's an easy interview talking point.
5. **Threat model as code**: a machine-readable YAML/JSON schema for the
   threat-modeling module's STRIDE output (not just prose), so it can be
   diffed in PRs like any other artifact — ties directly to ISO 42001's
   requirement for documented, repeatable risk assessment.
6. **AI Bill of Materials (AI-BOM)**: model name/version, provider, training
   data provenance disclaimer, known limitations — a governance-dashboard
   artifact that's explicitly what EU AI Act Article 13 (transparency) and
   NIST AI RMF GOVERN want.
7. **Canary/honeytoken prompts** in the RAG corpus during testing — a
   planted, uniquely-named fake secret that should *never* surface in a
   response; if it does, your output guardrail failed. Cheap, concrete
   demonstration of testing indirect prompt injection (OWASP LLM01/LLM03/
   ATLAS AML.T0051).
8. **Incident response runbook** for AI-specific incidents (prompt injection
   detected, data exfiltration via RAG, model provider outage) — most
   portfolio projects have generic IR docs; an AI-specific one stands out
   and maps to NIST AI RMF MANAGE and ISO 42001 clause 8.2.
9. **Preview-environment isolation on Vercel**: PR preview deployments must
   use a separate, sandboxed AI API key with a hard low rate/cost limit and
   point at a seeded, non-production database — otherwise every open PR is
   a live attack surface with prod-adjacent data. Worth documenting as a
   deliberate control, not an afterthought.
10. **Dual CVSS + a lightweight EPSS/KEV check** in the code-review engine's
    output — CVSS alone tells you severity, not exploitation likelihood;
    pairing it with a KEV/EPSS lookup is what real vuln-management programs
    do and is a nice differentiator for Feature 4.

---

## 2. Build plan (phases 2–8)

| Phase | Deliverable | Primary frameworks exercised |
|---|---|---|
| **2** | Secure document upload + storage (validation, ClamAV, sanitization, AES-256 at rest) | OWASP Web A03/A04/A08, NIST 800-53 SC-28/SI-3 |
| **3** | RAG pipeline: chunking, embeddings, ChromaDB with per-user collection isolation, retrieval-scoped auth | OWASP LLM08 (excessive agency)/LLM06 (sensitive info disclosure), NIST AI RMF MAP/MANAGE |
| **4** | AI Security Assistant: input guardrails (prompt injection/jailbreak classifiers), output guardrails (PII/secret redaction, hallucination flags), full request logging | OWASP LLM01 (prompt injection), LLM02 (insecure output handling), LLM09 (overreliance), MITRE ATLAS AML.T0051/T0054 |
| **5** | Secure Code Review Engine: Semgrep + Bandit orchestration, CVSS + EPSS scoring, remediation generation | OWASP Web A03 (injection detection), NIST 800-53 RA-5 |
| **6** | Threat Modeling Module: STRIDE automation, threat-model-as-code, attack tree generation | NIST AI RMF MAP, ISO 42001 §6.1 (risk assessment) |
| **7** | Security testing suite wired into CI: Semgrep/Bandit/Trivy/Gitleaks/ZAP/pip-audit/npm audit + SBOM | NIST 800-53 RA-5/CM-8, supply-chain controls |
| **8** | Governance dashboard + audit log UI, AI-BOM, disclaimers, explainability statements, IR runbook | NIST AI RMF GOVERN, ISO 42001 clauses 5/8/9, EU AI Act Art. 13/14/52 |

Each phase still gets full architecture/security/AI-security/governance
writeups plus production-quality code, exactly as before.

---

## 3. Framework mapping (living table — extended every phase)

### OWASP Top 10 for LLM Applications (2025)

| ID | Risk | Where addressed | Phase |
|---|---|---|---|
| LLM01 | Prompt Injection | Input guardrail service — classifier + rule-based filter before any prompt reaches the model; system-prompt/user-content separation enforced in the prompt template layer | 4 |
| LLM02 | Insecure Output Handling | Output guardrail — response validated/sanitized before rendering in React (no raw HTML injection), before execution in any code-suggestion path | 4 |
| LLM03 | Training Data Poisoning | N/A (no fine-tuning) — documented as out-of-scope with rationale; RAG corpus poisoning covered instead | 3 |
| LLM04 | Model Denial of Service | Token-budget caps per user/request, Redis rate limiting on AI endpoints specifically (tighter than general API limits) | 4 |
| LLM05 | Supply Chain Vulnerabilities | SBOM generation, pinned model versions, `pip-audit`/`npm audit` in CI | 7 |
| LLM06 | Sensitive Information Disclosure | Output guardrail PII/secret regex + entropy-based secret detection; document-level RAG permission checks at retrieval time, not just at storage time | 3, 4 |
| LLM07 | Insecure Plugin Design | N/A initially — documented; if tool-use/function-calling is added later, each tool gets its own least-privilege scope, ties to LLM08 | Future |
| LLM08 | Excessive Agency | AI assistant is read/advise-only in this build — no auto-remediation or auto-write actions without human approval, enforced at the API layer not just the prompt | 4 |
| LLM09 | Overreliance | Every AI response carries a disclaimer + confidence/limitation statement; human-review flag surfaced in governance dashboard | 8 |
| LLM10 | Model Theft | N/A (using hosted OpenAI + optional local model, no proprietary model weights) — documented | — |

### MITRE ATLAS (Adversarial Threat Landscape for AI Systems)

| Tactic/Technique (sample) | Where addressed |
|---|---|
| AML.T0051 (LLM Prompt Injection) | Input guardrail, canary/honeytoken prompts in test corpus |
| AML.T0054 (LLM Jailbreak) | Prompt classifier + adversarial eval regression suite (enhancement #2) |
| AML.T0057 (LLM Data Leakage) | Output guardrail sensitive-data filter, RAG permission enforcement |
| AML.T0018 (Backdoor ML Model) | N/A — no custom training; documented as accepted/out-of-scope given hosted-model architecture |
| AML.T0048 (External Harms via LLM misuse) | Content moderation on input, output validation, rate limiting |

Attack-scenario walkthroughs mapped to specific ATLAS technique IDs live in
`attack-scenarios/`, each with a reproduction script and the guardrail that
stops it.

### MITRE ATT&CK (traditional infra/app side)

| Tactic | Where addressed |
|---|---|
| Initial Access (T1190 — Exploit Public-Facing App) | WAF-style input validation, dependency scanning, ZAP DAST in CI |
| Credential Access (T1110 — Brute Force) | Account lockout + rate limiting (already built, Phase 1) |
| Persistence (T1098 — Account Manipulation) | Audit log on every role/permission change, admin-action alerts |
| Exfiltration (T1567) | Output guardrails, egress-restricted Docker networks (Phase 1), least-privilege DB roles |
| Defense Evasion (T1562 — Impair Defenses) | Audit log is INSERT-only for the app role (can't be tampered with by a compromised app process) |

### OWASP API Security Top 10 (2023)

| ID | Risk | Where addressed |
|---|---|---|
| API1 | Broken Object Level Authorization | Document-level permission table, checked per-request, not assumed from role alone |
| API2 | Broken Authentication | JWT + rotation + MFA + lockout (Phase 1) |
| API3 | Broken Object Property Level Authorization | Pydantic response schemas explicitly whitelist returned fields (never `**user.__dict__`) |
| API4 | Unrestricted Resource Consumption | Rate limiting (edge + app layer), upload size caps, AI token budgets |
| API5 | Broken Function Level Authorization | `require_roles()` dependency on every admin/privileged route |
| API6 | Unrestricted Access to Sensitive Business Flows | MFA-gated admin actions, anomaly logging on bulk operations |
| API7 | Server-Side Request Forgery | Outbound-URL allowlisting for any feature that fetches user-supplied URLs (threat-model diagram import, etc.) |
| API8 | Security Misconfiguration | Security headers middleware, docs disabled in prod, CORS allowlist (Phase 1) |
| API9 | Improper Inventory Management | OpenAPI spec generated + versioned; deprecated-endpoint policy documented |
| API10 | Unsafe Consumption of APIs | Local LLM / OpenAI responses treated as untrusted input to output guardrails, not blindly rendered |

### OWASP Top 10 (Web, 2021)

| ID | Where addressed |
|---|---|
| A01 Broken Access Control | RBAC + object-level checks throughout |
| A02 Cryptographic Failures | Argon2id, AES-256 field encryption, TLS termination at edge |
| A03 Injection | Parameterized queries via SQLAlchemy (never string-built SQL), Semgrep gate in CI |
| A04 Insecure Design | Threat model produced *before* each feature is built (dogfooding the platform's own Feature 5) |
| A05 Security Misconfiguration | Hardened Docker images, no default creds, headers middleware |
| A06 Vulnerable/Outdated Components | pip-audit + npm audit + Trivy in CI, Dependabot enabled |
| A07 Identification/Auth Failures | Phase 1 auth system |
| A08 Software/Data Integrity Failures | Signed commits, SBOM, CI artifact hashing |
| A09 Security Logging/Monitoring Failures | Audit log + Prometheus/Grafana alerting |
| A10 SSRF | Outbound allowlisting |

### NIST AI Risk Management Framework

| Function | Where addressed |
|---|---|
| GOVERN | Governance dashboard, AI-BOM, documented roles/RACI in `governance/` |
| MAP | Threat Modeling Module applied to the AI features themselves, not just traditional app components |
| MEASURE | Adversarial eval regression suite, guardrail hit-rate metrics in Grafana |
| MANAGE | Incident response runbook (AI-specific), human-review escalation path |

### ISO/IEC 42001 (AI Management System)

Mapped primarily in `governance/`: documented AI policy, risk assessment
procedure (feeds off Feature 5's threat models), performance monitoring
(eval suite + guardrail metrics), and a change-management process for
prompt/model updates (git-tracked, reviewed via PR like any other change).

### EU AI Act

This platform is a demonstration project, not a regulated deployment, but is
built as if the Security Assistant were a **limited-risk** system: Article
13 (transparency — disclaimers, explainability statements), Article 14
(human oversight — no auto-remediation, human-review flag), and Article 52-
adjacent disclosure that users are interacting with an AI system are all
implemented functionally, with a documentation note in `governance/` that
this is a good-faith alignment exercise, not a compliance certification.

### NIST 800-53 (selected control families)

| Family | Where addressed |
|---|---|
| AC (Access Control) | RBAC, object-level auth, least-privilege DB roles |
| AU (Audit & Accountability) | `audit_log` table, INSERT-only app grant |
| IA (Identification & Authentication) | JWT, MFA, password policy |
| SC (System & Comms Protection) | TLS, network segmentation, AES-256 at rest |
| SI (System & Information Integrity) | Malware scanning, input validation, dependency/container scanning |
| RA (Risk Assessment) | Threat Modeling Module, CI SAST/DAST gates |
| CM (Configuration Management) | IaC-style compose/deploy configs, SBOM, branch protection |

---

## 4. What I need from you to start Phase 2

Two quick calls before I build the upload/RAG pipeline against the
Vercel+GitHub topology:
