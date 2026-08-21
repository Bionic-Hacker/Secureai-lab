# Local setup

How to get SecureAI Lab running on a fresh Windows machine. Written for
Windows + Docker Desktop; the commands are PowerShell. macOS and Linux work
too — substitute `openssl` for the key script and skip the WSL section.

If you're an AI assistant helping someone through this: work one step at a
time, wait for the output of each command before moving on, and check the
Troubleshooting table below before improvising — every entry there is a real
failure that has already happened on this project.

---

## 0. What you're building

Seven containers: FastAPI backend, Postgres, Redis, ClamAV, ChromaDB, nginx,
Prometheus — plus a React frontend on Vite.

The API is reachable at `http://localhost:8080`, the UI at
`http://localhost:5173`. There is no login screen: the frontend signs in
automatically with dev credentials you create in step 5.

---

## 1. Prerequisites

- **Git** — https://git-scm.com
- **Docker Desktop** — https://www.docker.com/products/docker-desktop/
- **Admin rights** on the machine (the Docker installer needs them)

Verify:

```powershell
git --version
docker --version
docker ps
```

`docker ps` must return a table, not an error. If it errors, Docker Desktop
isn't running — launch it and wait for **Engine running** in the bottom-left.

### If Docker Desktop hangs on "Starting the Docker Engine"

Check that WSL is fully installed:

```powershell
wsl --version
```

This must print a version table. If it says *"The Windows Subsystem for Linux
is not installed"* while `wsl --status` works fine, the WSL optional Windows
feature is disabled — Docker checks `wsl --version` specifically and will hang
forever without it. In an **administrative** PowerShell:

```powershell
dism.exe /online /enable-feature /featurename:Microsoft-Windows-Subsystem-Linux /all /norestart
dism.exe /online /enable-feature /featurename:VirtualMachinePlatform /all /norestart
```

Reboot, then `wsl --update`. Confirm `wsl --version` works before continuing.

You can tell it worked when `wsl -l -v` lists a `docker-desktop` distro.

---

## 2. Clone

```powershell
cd $env:USERPROFILE\Documents
git clone https://github.com/Bionic-Hacker/Secureai-lab.git
cd Secureai-lab
```

Run every remaining command from this folder. Your prompt should read
`...\Secureai-lab>`.

---

## 3. Generate secrets

`.env` is gitignored — it holds secrets and is never committed. You generate
your own. `.env.example` is the template.

```powershell
powershell -ExecutionPolicy Bypass -File .\Fix-Keys.ps1
```

This creates `.env` with three cryptographic values plus a database password.
`-ExecutionPolicy Bypass` is needed because Windows blocks unsigned scripts; it
applies to that one run only.

The three keys are **different formats** and `config.py` validates each — the
app refuses to start if you swap them:

| Variable | Format |
|---|---|
| `JWT_SECRET_KEY` | hex, 32+ chars |
| `FIELD_ENCRYPTION_KEY` | hex, **exactly 64** chars |
| `MFA_ENCRYPTION_KEY` | Fernet key — 44 chars, base64url, ends in `=` |

`POSTGRES_PASSWORD` must also match the password embedded in `DATABASE_URL`.
The script keeps them in sync; if you edit by hand, change both.

---

## 4. Build and migrate

```powershell
docker compose up -d --build
```

First run takes 5–10 minutes: six images pulled, Python dependencies compiled.

```powershell
docker compose ps
```

Postgres and Redis should read `healthy`; backend, nginx, ClamAV, vector-db and
prometheus `running`.

Then create the schema:

```powershell
docker compose run --rm backend alembic upgrade head
```

You want two lines: `Running upgrade  -> 0001` and `Running upgrade 0001 -> 0002`.
If it prints nothing, the migration files are missing from
`backend/alembic/versions/`.

Check the API is alive:

```powershell
curl.exe http://localhost:8080/healthz
```

Expect `{"status":"ok"}`. Use `curl.exe`, not `curl` — in PowerShell bare `curl`
is an alias for `Invoke-WebRequest`, which takes different arguments.

---

## 5. Create your user

The database is empty. Register an account — this is also a full end-to-end test
of nginx, FastAPI, argon2 hashing, and Postgres:

```powershell
curl.exe -X POST http://localhost:8080/api/v1/auth/register -H "Content-Type: application/json" -d '{\"email\":\"you@example.com\",\"password\":\"Str0ng-Passw0rd!\",\"display_name\":\"You\"}'
```

A JSON body with an `id` and `role: viewer` means it worked. Note the email and
password — the frontend needs them next.

---

## 6. Start the frontend

The Vite dev server runs in a container. On locked-down Windows machines,
Application Control (WDAC) blocks the unsigned native binaries Vite needs —
Rollup's `.node` module and esbuild's `.exe` — so running it on the host fails
with *"An Application Control policy has blocked this file."* Inside a Linux
container those policies don't apply.

Create `frontend\.env.local` with the account from step 5:

```powershell
@"
VITE_DEV_EMAIL=you@example.com
VITE_DEV_PASSWORD=Str0ng-Passw0rd!
"@ | Set-Content .\frontend\.env.local -Encoding ASCII
```

`-Encoding ASCII` matters. Windows PowerShell's `-Encoding UTF8` writes a BOM,
which turns the first variable name into `\ufeffVITE_DEV_EMAIL` and makes
sign-in fail confusingly.

Then:

```powershell
docker compose up -d frontend
docker compose logs -f frontend
```

Wait for `VITE v5.x ready`, then `Ctrl+C` to stop following (the container keeps
running). Open **http://localhost:5173**.

You should see the intake bench with your display name under **Custodian**.
That header confirms the whole chain: React → Vite proxy → nginx → FastAPI →
Postgres.

Source files live on your host and are editable in VS Code. Hot reload works
via polling — Windows bind mounts don't emit inotify events to Linux
containers — so changes appear in about a second.

---

## 7. Verify uploads

Make a test file and drop it on the intake slot, or use **Choose a file**:

```powershell
"test document" | Set-Content .\test-document.txt
```

A custody tag should appear with the filename, size, and full SHA-256. The stamp
reads **In scan**, then flips to **Cleared** once ClamAV responds — the list
polls every four seconds while anything is pending.

A `503 — Malware scanning is temporarily unavailable` means ClamAV isn't ready.
That's the system failing closed rather than storing an unscanned file, which is
correct. Check `docker compose logs clamav` for `socket found, clamd started.`

---

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| Docker hangs at "Starting the Docker Engine", 0% CPU | `wsl --version` fails. See §1. |
| `exited (127)`, `setpriv: setresuid failed` | Container needs capabilities back after `cap_drop: ALL`. Add `SETGID, SETUID` to that service's `cap_add`. |
| `install: can't change permissions` | Same cause; that service also needs `DAC_OVERRIDE, FOWNER`. |
| ClamAV: `Could not resolve hostname` | It's on the `internal: true` network with no egress. Its `networks:` line needs `[backend_net, frontend_net]`. |
| `type "user_role" already exists` | The enum in `0001` needs `create_type=False`. Then `docker compose down -v` and re-migrate. |
| Migration changes ignored | Migrations are baked into the image. Rebuild: `docker compose up -d --build`. |
| `Failed to load PostCSS config ... not valid JSON` | UTF-8 BOM in `package.json`. Rewrite it with `-Encoding ASCII`. |
| `An Application Control policy has blocked this file` | Run Vite in Docker (§6), not on the host. |
| `Elevated permissions are required` | Open a *new* PowerShell via right-click → Run as administrator. You can't elevate an existing window. |
| `Method invocation is supported only on core types` | PowerShell Constrained Language Mode. Use external programs (`openssl.exe`, `whoami`) instead of .NET calls. |
| Uploads return `422` | The multipart field name doesn't match. Check `POST /api/v1/documents` at `/docs` and update `UPLOAD_FIELD` in `frontend/src/api.js`. |

---

## Daily use

```powershell
docker compose up -d        # start everything
docker compose down         # stop, keep data
docker compose down -v      # stop and WIPE the database
docker compose logs -f backend
```

`down -v` deletes your user and documents. You'd need to re-run the migration
and re-register.

---

## Notes

- `http://localhost:8080/` returns 404 by design — nginx proxies only `/api/`
  and `/healthz`.
- To reach FastAPI's interactive docs at `/docs`, add
  `ports: ["127.0.0.1:8000:8000"]` to the `backend` service, then browse to
  `http://localhost:8000/docs`. Keep it bound to loopback: it exposes the whole
  API surface.
- ClamAV's signatures are bundled in the image and updates are off, so it warns
  that the database is over 7 days old. Fine for a lab, not for production.
- The test suite needs `backend/requirements-dev.txt` and a `.env.test` file
  that doesn't exist yet.
- `app/models/user.py` declares the role column with `native_enum=False`, so
  `Base.metadata.create_all` (used by tests) builds a VARCHAR while the
  migration builds a native Postgres enum. Tests exercise a different schema
  than production — worth reconciling.
