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
    [double]$Timeout = 60.0
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

$argsList = @('src_agent.py', '--scope', $Scope, '--blackboard', $Blackboard,
    '--max-cycles', $MaxCycles, '--max-explore', $MaxExplore,
    '--reasoner-prefer', $ReasonerPrefer, '--timeout', $Timeout)
if ($ExplorerPrefer) { $argsList += @('--explorer-prefer', $ExplorerPrefer) }
if ($WorkerId) { $argsList += @('--worker-id', $WorkerId) }

$previousLocation = Get-Location
try {
    Set-Location -LiteralPath $PSScriptRoot
    & $pythonExe @pythonPrefix @argsList
    exit $LASTEXITCODE
} finally {
    Set-Location -LiteralPath $previousLocation
}
