[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Scope,
    [Parameter(Mandatory = $true)]
    [string]$Blackboard,
    [int]$MaxCycles = 20,
    [int]$MaxExplore = 3,
    [string]$ReasonerPrefer = 'deepseek',
    [string]$ExplorerPrefer = '',
    [string]$WorkerId = '',
    [double]$Timeout = 60.0,
    [int]$RecallLimit = 5,
    [switch]$NoRecall,
    [switch]$NoDependencies,
    [switch]$NoTimelineCompress,
    # Override the interpreter; defaults to PA_PYTHON (from .env) then a 3.10+ probe.
    [string]$Python = ''
)

[Console]::InputEncoding = [System.Text.UTF8Encoding]::new($false)
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$OutputEncoding = [Console]::OutputEncoding
$env:PYTHONUTF8 = '1'
$env:PYTHONIOENCODING = 'utf-8'

# Auto-load .env (values already in env win) — matches run-console.ps1.
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

# Resolve a Python 3.10+ runtime: -Python > PA_PYTHON (.env) > py -3 / python / python3.
if (-not $Python) { $Python = $env:PA_PYTHON }
$pythonCandidates = @()
if ($Python) { $pythonCandidates += [pscustomobject]@{ Exe = $Python; Prefix = @() } }
foreach ($name in @('py', 'python', 'python3')) {
    $command = Get-Command $name -ErrorAction SilentlyContinue
    if ($command) {
        $prefix = if ($name -eq 'py') { @('-3') } else { @() }
        $pythonCandidates += [pscustomobject]@{ Exe = $command.Source; Prefix = $prefix }
    }
}
$pythonExe = $null
$pythonPrefix = @()
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
    throw 'Python 3.10+ runtime not found. Set PA_PYTHON in .env (e.g. D:\Environment\Python\miniforge\envs\py310\python.exe) or pass -Python.'
}

$argsList = @('src_agent.py', '--scope', $Scope, '--blackboard', $Blackboard,
    '--max-cycles', $MaxCycles, '--max-explore', $MaxExplore,
    '--reasoner-prefer', $ReasonerPrefer, '--timeout', $Timeout,
    '--recall-limit', $RecallLimit)
if ($ExplorerPrefer) { $argsList += @('--explorer-prefer', $ExplorerPrefer) }
if ($WorkerId) { $argsList += @('--worker-id', $WorkerId) }
if ($NoRecall) { $argsList += '--no-recall' }
if ($NoDependencies) { $argsList += '--no-dependencies' }
if ($NoTimelineCompress) { $argsList += '--no-timeline-compress' }

$previousLocation = Get-Location
try {
    Set-Location -LiteralPath $PSScriptRoot
    Write-Host "Lode SRC agent using $pythonExe" -ForegroundColor DarkGray
    & $pythonExe @pythonPrefix @argsList
    exit $LASTEXITCODE
} finally {
    Set-Location -LiteralPath $previousLocation
}
