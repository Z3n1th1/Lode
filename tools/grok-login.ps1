param(
    [ValidateSet('oauth', 'device-code')]
    [string]$Mode = 'oauth',
    [string]$GrokHome = (Join-Path $env:USERPROFILE '.grok-lode-grok-build'),
    [switch]$Verify
)

$ErrorActionPreference = 'Stop'

function Find-CommandPath {
    param([string[]]$Names)
    foreach ($name in $Names) {
        $command = Get-Command $name -ErrorAction SilentlyContinue
        if ($command) { return $command.Source }
    }
    throw 'Grok CLI not found. Install @xai-official/grok first.'
}

function Read-ProcessOutput {
    param([string]$Path)
    try { return Get-Content -LiteralPath $Path -Raw -ErrorAction SilentlyContinue }
    catch { return '' }
}

function Open-FreshBrowser {
    param([string]$Url)

    $browserCandidates = @(
        'C:\Program Files\Google\Chrome\Application\chrome.exe',
        'C:\Program Files (x86)\Google\Chrome\Application\chrome.exe',
        'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe',
        'C:\Program Files\Microsoft\Edge\Application\msedge.exe'
    )
    $browser = $browserCandidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
    if (-not $browser) {
        Write-Host "Open this URL manually:`n$Url"
        return
    }

    # A unique profile prevents an already-running Chrome from reusing the
    # operator's normal account. --incognito alone is not sufficient.
    $browserProfile = Join-Path ([IO.Path]::GetTempPath()) `
        ('lode-grok-oauth-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Force -Path $browserProfile | Out-Null
    Start-Process -FilePath $browser -ArgumentList @(
        '--user-data-dir=' + $browserProfile,
        '--profile-directory=Default',
        '--no-first-run',
        '--no-default-browser-check',
        '--disable-sync',
        '--new-window',
        '--incognito',
        $Url
    ) -WindowStyle Normal
    Write-Host "Opened a fresh browser profile: $browserProfile"
}

function Invoke-GrokLogin {
    param([string[]]$Arguments)

    $logRoot = Join-Path ([IO.Path]::GetTempPath()) `
        ('lode-grok-login-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Force -Path $logRoot | Out-Null
    $stdoutPath = Join-Path $logRoot 'stdout.log'
    $stderrPath = Join-Path $logRoot 'stderr.log'
    $process = Start-Process -FilePath $grok -ArgumentList $Arguments `
        -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath `
        -PassThru -WindowStyle Hidden

    $browserOpened = $false
    $authorizeUrl = ''
    $deviceCode = ''
    $deadline = [DateTime]::UtcNow.AddMinutes(10)
    while (-not $process.HasExited -and [DateTime]::UtcNow -lt $deadline) {
        Start-Sleep -Milliseconds 250
        # Grok prints login URLs and codes on stderr on Windows.
        $output = ((Read-ProcessOutput $stdoutPath), (Read-ProcessOutput $stderrPath)) -join "`n"
        if (-not $authorizeUrl -and $output) {
            $match = [regex]::Match($output, 'https://[^\s]+')
            if ($match.Success) { $authorizeUrl = $match.Value.TrimEnd('.', ',', ')') }
        }
        if (-not $deviceCode -and $output) {
            $match = [regex]::Match($output, '(?im)(?:code|code:|user code)\s*[:=]?\s*([A-Z0-9]{4,8}(?:-[A-Z0-9]{3,8})?)')
            if ($match.Success) {
                $deviceCode = $match.Groups[1].Value
                Write-Host "Grok device code: $deviceCode"
            }
        }
        if ($authorizeUrl -and -not $browserOpened) {
            Open-FreshBrowser $authorizeUrl
            $browserOpened = $true
        }
    }

    if (-not $process.HasExited) {
        $process.Kill()
        throw 'Grok login timed out after 10 minutes.'
    }
    if ($process.ExitCode -ne 0) {
        $errorText = (Read-ProcessOutput $stderrPath).Trim()
        throw "Grok login failed. Details were saved under $logRoot. $errorText"
    }
}

$env:GROK_HOME = $GrokHome
New-Item -ItemType Directory -Force -Path $GrokHome | Out-Null
$grok = Find-CommandPath @('grok.cmd', 'grok.exe', 'grok')

if ($Mode -eq 'device-code') {
    Invoke-GrokLogin @('login', '--device-code')
} else {
    # OAuth fallback. Device-code is the default because it never asks the CLI
    # to open the normal browser before this script can launch the fresh profile.
    Invoke-GrokLogin @('login', '--oauth')
}

if ($Verify) {
    & $grok --single 'Reply with exactly READY.' --output-format json `
        --no-subagents --permission-mode plan --disable-web-search
    exit $LASTEXITCODE
}

Write-Host "Grok login completed in isolated GROK_HOME: $GrokHome"
Write-Host 'Run with -Verify to perform a harmless READY check.'
