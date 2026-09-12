[CmdletBinding()]
param(
    [ValidateSet('collect', 'watch')]
    [string]$Mode = 'collect',
    [string]$Scope = (Join-Path $PSScriptRoot 'scope.example.json'),
    [string]$OutDir = (Join-Path $PSScriptRoot 'intel-data'),
    [string]$Registry = '',
    [string[]]$InputFile = @(),
    [switch]$NoNetwork,
    [double]$Timeout = 8,
    [int]$MaxItems = 200,
    [double]$IntervalSec = 900,
    [int]$MaxRuns = 0,
    [int]$MaxConsecutiveErrors = 5,
    [switch]$Feishu,
    [switch]$FeishuDryRun,
    [double]$FeishuMinScore = 60,
    [int]$FeishuMaxItems = 5
)

[Console]::InputEncoding = [System.Text.UTF8Encoding]::new($false)
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$OutputEncoding = [Console]::OutputEncoding
$env:PYTHONUTF8 = '1'
$env:PYTHONIOENCODING = 'utf-8'

$pythonExe = $null
$pythonPrefix = @()
$pythonCandidates = @()
if ($env:PA_PYTHON) {
    $pythonCandidates += [pscustomobject]@{ Exe = $env:PA_PYTHON; Prefix = @() }
} else {
    $pyLauncher = Get-Command 'py' -ErrorAction SilentlyContinue
    if ($pyLauncher) {
        $pythonCandidates += [pscustomobject]@{ Exe = $pyLauncher.Source; Prefix = @('-3') }
    }
    foreach ($name in @('python', 'python3')) {
        $command = Get-Command $name -ErrorAction SilentlyContinue
        if ($command) {
            $pythonCandidates += [pscustomobject]@{ Exe = $command.Source; Prefix = @() }
        }
    }
}

# Windows App execution aliases can appear in PATH without a Python install.
# Probe each candidate before using it so a broken ``py.exe`` does not mask a
# working interpreter later in PATH.
foreach ($candidate in $pythonCandidates) {
    try {
        & $candidate.Exe @($candidate.Prefix) -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)' 2>$null
        if ($LASTEXITCODE -eq 0) {
            $pythonExe = $candidate.Exe
            $pythonPrefix = @($candidate.Prefix)
            break
        }
    } catch {
        continue
    }
}
if (-not $pythonExe) {
    throw 'Python 3.10+ runtime not found. Install Python or set PA_PYTHON to its executable.'
}

$intelArgs = @('-m', 'intel', $Mode, '--scope', $Scope, '--out-dir', $OutDir, '--timeout', $Timeout, '--max-items', $MaxItems)
if ($Registry) { $intelArgs += @('--registry', $Registry) }
foreach ($item in $InputFile) { $intelArgs += @('--file', $item) }
if ($NoNetwork) { $intelArgs += '--no-network' }
if ($Mode -eq 'watch') {
    $intelArgs += @('--interval-sec', $IntervalSec, '--max-runs', $MaxRuns, '--max-consecutive-errors', $MaxConsecutiveErrors)
    $intelArgs += @('--feishu-min-score', $FeishuMinScore, '--feishu-max-items', $FeishuMaxItems)
    if ($Feishu -or $FeishuDryRun) { $intelArgs += '--feishu' }
    if ($FeishuDryRun) { $intelArgs += '--feishu-dry-run' }
}

$previousLocation = Get-Location
try {
    Set-Location -LiteralPath $PSScriptRoot
    & $pythonExe @pythonPrefix @intelArgs
    exit $LASTEXITCODE
} finally {
    Set-Location -LiteralPath $previousLocation
}
