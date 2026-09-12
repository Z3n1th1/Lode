[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Target,
    [string]$Scope = (Join-Path $PSScriptRoot 'scope.example.json'),
    [string]$OutDir = (Join-Path $PSScriptRoot 'surface-data'),
    [int]$MaxScripts = 40,
    [double]$Timeout = 8,
    [double]$DelaySec = 0.4
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

$surfaceArgs = @(
    'src_surface.py', '--scope', $Scope, '--target', $Target,
    '--out-dir', $OutDir, '--max-scripts', $MaxScripts,
    '--timeout', $Timeout, '--delay-sec', $DelaySec
)
$previousLocation = Get-Location
try {
    Set-Location -LiteralPath $PSScriptRoot
    & $pythonExe @pythonPrefix @surfaceArgs
    exit $LASTEXITCODE
} finally {
    Set-Location -LiteralPath $previousLocation
}
