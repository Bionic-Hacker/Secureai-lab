<#
    Fix-Keys.ps1
    ------------
    Generates the three secrets and writes .env — without calling into .NET,
    so it works under PowerShell Constrained Language Mode (AppLocker / WDAC).

    Run from the Secureai-lab repo root:

        powershell -ExecutionPolicy Bypass -File .\Fix-Keys.ps1

    Prefers the openssl.exe bundled with Git for Windows. Falls back to
    Get-Random only if openssl cannot be found (see the warning it prints).
#>

$ErrorActionPreference = 'Stop'

if (-not (Test-Path '.\.env.example')) {
    Write-Host ""
    Write-Host "  .env.example not found - run this from the Secureai-lab repo root." -ForegroundColor Red
    Write-Host "  Current folder: $((Get-Location).Path)" -ForegroundColor DarkGray
    Write-Host ""
    exit 1
}

Write-Host ""
Write-Host "Locating openssl..." -ForegroundColor Cyan

# ------------------------------------------------------------- find openssl --
$openssl = $null

$onPath = Get-Command openssl.exe -ErrorAction SilentlyContinue
if ($onPath) {
    $openssl = $onPath.Source
} else {
    $candidates = @(
        "$env:ProgramFiles\Git\usr\bin\openssl.exe"
        "${env:ProgramFiles(x86)}\Git\usr\bin\openssl.exe"
        "$env:LOCALAPPDATA\Programs\Git\usr\bin\openssl.exe"
        "$env:ProgramFiles\Git\mingw64\bin\openssl.exe"
        "$env:SystemRoot\System32\OpenSSH\openssl.exe"
    )
    foreach ($c in $candidates) {
        if (Test-Path $c) { $openssl = $c; break }
    }
}

if ($openssl) {
    Write-Host "  Using $openssl" -ForegroundColor Green
} else {
    Write-Host "  openssl.exe not found - falling back to Get-Random." -ForegroundColor Yellow
    Write-Host "  Get-Random is NOT cryptographically secure. Fine for a local" -ForegroundColor Yellow
    Write-Host "  dev box; regenerate these with openssl before any real use." -ForegroundColor Yellow
}

# ----------------------------------------------------------- generators -----
$hexChars = [char[]]'0123456789abcdef'
# base64url alphabet, used for the Fernet key
$b64Chars = [char[]]'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'
# A 32-byte Fernet key base64-encodes to 43 chars + '='. The 43rd character
# carries only 4 bits of real data, so it must come from this reduced set for
# the key to decode back to exactly 32 bytes.
$b64Tail  = [char[]]'AEIMQUYcgkosw048'

function New-Hex([int]$charCount) {
    if ($openssl) {
        $bytes = $charCount / 2
        $out = & $openssl rand -hex $bytes 2>$null
        if ($LASTEXITCODE -eq 0 -and $out) { return ($out.Trim()) }
    }
    return -join (1..$charCount | ForEach-Object { Get-Random -InputObject $hexChars })
}

function New-FernetKey {
    if ($openssl) {
        $out = & $openssl rand -base64 32 2>$null
        if ($LASTEXITCODE -eq 0 -and $out) {
            # standard base64 -> url-safe, using operators rather than .Replace()
            return (($out.Trim()) -replace '\+', '-' -replace '/', '_')
        }
    }
    $body = -join (1..42 | ForEach-Object { Get-Random -InputObject $b64Chars })
    $tail = Get-Random -InputObject $b64Tail
    return "$body$tail="
}

Write-Host ""
Write-Host "Generating keys..." -ForegroundColor Cyan

$pgPassword = New-Hex 24
$values = @{
    'JWT_SECRET_KEY'       = (New-Hex 128)
    'FIELD_ENCRYPTION_KEY' = (New-Hex 64)
    'MFA_ENCRYPTION_KEY'   = (New-FernetKey)
    'CHROMA_AUTH_TOKEN'    = (New-Hex 32)
    'POSTGRES_PASSWORD'    = $pgPassword
    'DATABASE_URL'         = "postgresql+asyncpg://secureai:$pgPassword@postgres:5432/secureai_lab"
}

# ------------------------------------------------------------- write .env ---
if (Test-Path '.\.env') {
    $backup = ".\.env.backup-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
    Copy-Item '.\.env' $backup
    Write-Host "  Existing .env backed up to $backup" -ForegroundColor Yellow
}

$out = foreach ($line in (Get-Content '.\.env.example')) {
    $replaced = $false
    foreach ($key in $values.Keys) {
        if ($line -match "^\s*$key\s*=") {
            "$key=$($values[$key])"
            $replaced = $true
            break
        }
    }
    if (-not $replaced) { $line }
}
Set-Content -Path '.\.env' -Value $out -Encoding ASCII
Write-Host "  .env written" -ForegroundColor Green

# ---------------------------------------------------------------- verify ----
Write-Host ""
Write-Host "Verifying..." -ForegroundColor Cyan

$failures = 0
function Check($label, $ok) {
    if ($ok) {
        Write-Host "  [ OK ]  $label" -ForegroundColor Green
    } else {
        Write-Host "  [FAIL]  $label" -ForegroundColor Red
        $script:failures++
    }
}

# Note: -match and -like operators are permitted in Constrained Language Mode.
# [regex]::Escape() is not, which is why it does not appear here.
$envText = Get-Content '.\.env' -Raw

Check "JWT_SECRET_KEY is 128 hex chars"          ($envText -match 'JWT_SECRET_KEY=[0-9a-f]{128}')
Check "FIELD_ENCRYPTION_KEY is 64 hex chars"     ($envText -match 'FIELD_ENCRYPTION_KEY=[0-9a-f]{64}[^0-9a-f]')
Check "MFA_ENCRYPTION_KEY is a valid Fernet key" ($envText -match 'MFA_ENCRYPTION_KEY=[A-Za-z0-9_\-]{43}=')
Check "DATABASE_URL uses the asyncpg driver"     ($envText -match 'DATABASE_URL=postgresql\+asyncpg://')
Check "DATABASE_URL password matches"            ($envText -match "://secureai:$pgPassword@postgres:5432/")
Check "no placeholders left in crypto keys"      ($envText -notmatch '(JWT_SECRET_KEY|FIELD_ENCRYPTION_KEY|MFA_ENCRYPTION_KEY|POSTGRES_PASSWORD)=replace_with')

foreach ($f in @(
    'docker-compose.yml',
    '.gitignore',
    'backend\requirements-dev.txt',
    'backend\alembic\versions\0001_initial_schema.py',
    'backend\alembic\versions\0002_documents.py'
)) {
    Check "$f present" (Test-Path ".\$f")
}

Write-Host ""
Write-Host ("-" * 66) -ForegroundColor DarkGray
if ($failures -eq 0) {
    Write-Host " Keys generated. Run these three, in order:" -ForegroundColor Green
    Write-Host ""
    Write-Host "   docker compose up -d --build" -ForegroundColor White
    Write-Host "   docker compose run --rm backend alembic upgrade head" -ForegroundColor White
    Write-Host "   curl http://localhost:8080/healthz" -ForegroundColor White
    Write-Host ""
    Write-Host " The first command takes 5-10 minutes on its first run." -ForegroundColor DarkGray
} else {
    Write-Host " $failures check(s) failed - see the [FAIL] lines above." -ForegroundColor Red
}
Write-Host ("-" * 66) -ForegroundColor DarkGray
Write-Host ""
