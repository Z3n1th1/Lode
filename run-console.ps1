[CmdletBinding()]
param(
    [string]$StateDir = (Join-Path $PSScriptRoot 'lode-state'),
    [ValidateRange(1, 65535)]
    [int]$Port = 8088,
    # Override the interpreter; defaults to PA_PYTHON (from .env) then a 3.10+ probe.
    [string]$Python = ''
)

[Console]::InputEncoding = [System.Text.UTF8Encoding]::new($false)
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$OutputEncoding = [Console]::OutputEncoding
$env:PYTHONUTF8 = '1'
$env:PYTHONIOENCODING = 'utf-8'

# Auto-load .env (values already in env win)
$envFile = Join-Path $PSScriptRoot '.env'
if (Test-Path -LiteralPath $envFile) {
    foreach ($line in Get-Content -LiteralPath $envFile -Encoding UTF8) {
        $line = $line.Trim()
        if (-not $line -or $line.StartsWith('#')) { continue }
        $idx = $line.IndexOf('=')
        if ($idx -lt 1) { continue }
        $key = $line.Substring(0, $idx).Trim()
        $val = $line.Substring($idx + 1).Trim().Trim('"').Trim("'")
        if ($key -and -not [Environment]::GetEnvironmentVariable($key)) {
            [Environment]::SetEnvironmentVariable($key, $val, 'Process')
        }
    }
}

$pythonExe = $null
$pythonPrefix = @()
$pythonCandidates = @()
if (-not $Python) { $Python = $env:PA_PYTHON }
if ($Python) {
    $pythonCandidates += [pscustomobject]@{ Exe = $Python; Prefix = @() }
} else {
    $pyLauncher = Get-Command 'py' -ErrorAction SilentlyContinue
    if ($pyLauncher) { $pythonCandidates += [pscustomobject]@{ Exe = $pyLauncher.Source; Prefix = @('-3') } }
    foreach ($name in @('python', 'python3')) {
        $command = Get-Command $name -ErrorAction SilentlyContinue
        if ($command) { $pythonCandidates += [pscustomobject]@{ Exe = $command.Source; Prefix = @() } }
    }
}
foreach ($candidate in $pythonCandidates) {
    try {
        & $candidate.Exe @($candidate.Prefix) -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)' 2>$null
        if ($LASTEXITCODE -eq 0) {
            $pythonExe = $candidate.Exe
            $pythonPrefix = @($candidate.Prefix)
            break
        }
    } catch { continue }
}
if (-not $pythonExe) {
    throw 'Python 3.10+ runtime not found. Install Python or set PA_PYTHON to its executable.'
}
Write-Host "Lode Console using $pythonExe" -ForegroundColor DarkGray

if (-not $env:LODE_ADMIN_PASSWORD) {
    throw 'LODE_ADMIN_PASSWORD is required and must be at least 12 characters.'
}
if (-not $env:LODE_SESSION_SECRET) {
    throw 'LODE_SESSION_SECRET is required and must be at least 32 characters.'
}

$previousLocation = Get-Location
try {
    Set-Location -LiteralPath $PSScriptRoot
    & $pythonExe @pythonPrefix -m console.server `
        --state-dir $StateDir `
        --static-dir (Join-Path $PSScriptRoot 'console\dist') `
        --port $Port
    exit $LASTEXITCODE
} finally {
    Set-Location -LiteralPath $previousLocation
}
