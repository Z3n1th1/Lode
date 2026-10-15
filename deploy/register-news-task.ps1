[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidateRange(5, 1440)][int]$IntervalMinutes = 30,
    [switch]$Feishu,
    [switch]$Discord,
    [switch]$NoAi,
    [string]$TaskName = 'Pulse'
)

$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$repoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$runner = Join-Path $repoRoot 'run-news.ps1'
$shellPath = (Get-Process -Id $PID).Path
if ([IO.Path]::GetFileName($shellPath) -notin @('pwsh.exe', 'powershell.exe')) {
    throw 'Run this installer from PowerShell.'
}
$arguments = '-NoLogo -NoProfile -NonInteractive -WindowStyle Hidden -File "' + $runner + '" -Mode run'
if ($Feishu) { $arguments += ' -Feishu' }
if ($Discord) { $arguments += ' -Discord' }
if ($NoAi) { $arguments += ' -NoAi' }
$existing = Get-ScheduledTask -TaskName $TaskName -TaskPath '\' -ErrorAction SilentlyContinue
if ($existing -and ($existing.Actions.Arguments -join ' ') -notlike ('*"' + $runner + '"*')) {
    throw 'A different task already uses this name; choose another TaskName.'
}
$action = New-ScheduledTaskAction -Execute $shellPath -Argument $arguments -WorkingDirectory $repoRoot
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes $IntervalMinutes)
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -MultipleInstances IgnoreNew `
    -ExecutionTimeLimit (New-TimeSpan -Minutes 10) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
$userId = [Security.Principal.WindowsIdentity]::GetCurrent().Name
$principal = New-ScheduledTaskPrincipal -UserId $userId -LogonType Interactive -RunLevel Limited
if ($PSCmdlet.ShouldProcess($TaskName, "Run Pulse every $IntervalMinutes minutes as $userId")) {
    $task = New-ScheduledTask -Action $action -Trigger $trigger -Settings $settings -Principal $principal `
        -Description 'Pulse: collect public news and deliver to the explicitly selected channel.'
    Register-ScheduledTask -TaskName $TaskName -TaskPath '\' -InputObject $task -Force | Out-Null
    Get-ScheduledTask -TaskName $TaskName -TaskPath '\' | Select-Object TaskName, State
    Get-ScheduledTaskInfo -TaskName $TaskName -TaskPath '\' | Select-Object LastRunTime, LastTaskResult, NextRunTime
}
