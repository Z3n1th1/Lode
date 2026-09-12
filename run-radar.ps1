[CmdletBinding()]
param(
    [ValidateSet('collect', 'watch')]
    [string]$Mode = 'watch',
    [string]$Scope = (Join-Path $PSScriptRoot 'scope.example.json'),
    [string]$OutDir = (Join-Path $PSScriptRoot 'radar-data'),
    [string]$Registry = (Join-Path $PSScriptRoot 'sources.security.example.json'),
    [string[]]$InputFile = @(),
    [double]$Timeout = 8,
    [int]$MaxItems = 200,
    [double]$IntervalSec = 1800,
    [int]$MaxRuns = 0,
    [int]$MaxConsecutiveErrors = 5,
    [switch]$NoNetwork,
    [switch]$Feishu,
    [switch]$FeishuDryRun,
    [double]$FeishuMinScore = 60,
    [int]$FeishuMaxItems = 5
)

$forward = @{
    Mode = $Mode; Scope = $Scope; OutDir = $OutDir; Registry = $Registry
    Timeout = $Timeout; MaxItems = $MaxItems; IntervalSec = $IntervalSec; MaxRuns = $MaxRuns
    MaxConsecutiveErrors = $MaxConsecutiveErrors
    InputFile = $InputFile
    FeishuMinScore = $FeishuMinScore; FeishuMaxItems = $FeishuMaxItems
}
if ($NoNetwork) { $forward.NoNetwork = $true }
if ($Feishu) { $forward.Feishu = $true }
if ($FeishuDryRun) { $forward.FeishuDryRun = $true }
& (Join-Path $PSScriptRoot 'run-intel.ps1') @forward
exit $LASTEXITCODE
