[CmdletBinding()]
param(
    [ValidateSet('run', 'collect', 'watch')][string]$Mode = 'watch',
    [string]$OutDir = (Join-Path $PSScriptRoot 'news-data'),
    [string]$Registry = (Join-Path $PSScriptRoot 'sources.news.example.json'),
    [ValidateRange(1, 30)][double]$Timeout = 8,
    [ValidateRange(60, 86400)][double]$IntervalSec = 1800,
    [ValidateRange(0, 1000000)][int]$MaxRuns = 0,
    [ValidateRange(0, 1000000)][int]$MaxConsecutiveErrors = 5,
    [ValidateRange(1, 20)][int]$MaxAiItems = 5,
    [switch]$NoAi,
    [switch]$Feishu,
    [ValidateRange(1, 10)][int]$FeishuMaxItems = 3
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

# Windows Store aliases may exist without a usable interpreter.
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

$newsArgs = @('-m', 'news', 'run', '--registry', $Registry, '--state-dir', $OutDir,
    '--max-ai-items', $MaxAiItems, '--max-messages', $FeishuMaxItems,
    '--timeout', $Timeout, '--allow-missing-ai')
if ($NoAi) { $newsArgs += '--no-ai' }
if ($Feishu) { $newsArgs += '--feishu' }

$runCount = 0
$consecutiveErrors = 0
$cycleExitCode = 0
$previousLocation = Get-Location
try {
    Set-Location -LiteralPath $PSScriptRoot
    do {
        & $pythonExe @pythonPrefix @newsArgs
        $cycleExitCode = $LASTEXITCODE
        $runCount += 1
        if ($cycleExitCode -eq 0) { $consecutiveErrors = 0 } else { $consecutiveErrors += 1 }
        if ($Mode -ne 'watch' -or ($MaxRuns -gt 0 -and $runCount -ge $MaxRuns)) { break }
        if ($MaxConsecutiveErrors -gt 0 -and $consecutiveErrors -ge $MaxConsecutiveErrors) { break }
        Start-Sleep -Seconds $IntervalSec
    } while ($true)
} finally {
    Set-Location -LiteralPath $previousLocation
}
exit $cycleExitCode
