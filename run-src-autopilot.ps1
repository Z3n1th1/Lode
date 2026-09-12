[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Scope,
    [Parameter(Mandatory = $true)]
    [string]$Target,
    [string]$OutDir = (Join-Path $PSScriptRoot 'src-autopilot-data'),
    [string[]]$ResultFile = @(),
    [int]$MaxRounds = 3,
    [int]$MaxCandidates = 100,
    [int]$MaxNoNewRounds = 2,
    [int]$MaxScripts = 40
)

[Console]::InputEncoding = [System.Text.UTF8Encoding]::new($false)
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$OutputEncoding = [Console]::OutputEncoding
$env:PYTHONUTF8 = '1'
$env:PYTHONIOENCODING = 'utf-8'

$pythonExe = $env:PA_PYTHON
$pythonPrefix = @()
if (-not $pythonExe) {
    $pyLauncher = Get-Command 'py' -ErrorAction SilentlyContinue
    if ($pyLauncher) {
        $pythonExe = $pyLauncher.Source
        $pythonPrefix = @('-3')
    } else {
        $pythonCommand = Get-Command 'python' -ErrorAction SilentlyContinue
        if (-not $pythonCommand) {
            throw 'Python 3 not found. Set PA_PYTHON to a Python 3.10+ executable.'
        }
        $pythonExe = $pythonCommand.Source
    }
}

$argsList = @('src_autopilot.py', '--scope', $Scope, '--target', $Target,
    '--out-dir', $OutDir, '--max-rounds', $MaxRounds, '--max-candidates', $MaxCandidates,
    '--max-no-new-rounds', $MaxNoNewRounds, '--max-scripts', $MaxScripts)
foreach ($file in $ResultFile) {
    if ($file) { $argsList += @('--result-file', $file) }
}

$previousLocation = Get-Location
try {
    Set-Location -LiteralPath $PSScriptRoot
    & $pythonExe @pythonPrefix @argsList
    exit $LASTEXITCODE
} finally {
    Set-Location -LiteralPath $previousLocation
}
