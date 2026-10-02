$ErrorActionPreference = 'Stop'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this script from PowerShell as Administrator.'
}

$tlsSource = Join-Path $PSScriptRoot 'private\hec-tls'
$tlsTarget = 'C:\Program Files\Splunk\etc\auth\gmail-hec-lab'
$inputPath = 'C:\Program Files\Splunk\etc\apps\splunk_httpinput\local\inputs.conf'
if (-not (Test-Path -LiteralPath $inputPath)) {
    throw 'Expected HEC inputs.conf was not found. Stop and check the installation.'
}
$content = [IO.File]::ReadAllText($inputPath)
$sectionRegex = [regex]::new('(?ms)^\[http\]\s*\r?\n(?<body>.*?)(?=^\[|\z)')
$httpSection = $sectionRegex.Match($content)
if (-not $httpSection.Success) { throw 'Global [http] section not found.' }
$backup = $inputPath + '.gmail-tls-backup-' + (Get-Date -Format 'yyyyMMddHHmmss')
Copy-Item -LiteralPath $inputPath -Destination $backup
New-Item -ItemType Directory -Path $tlsTarget -Force | Out-Null
Copy-Item -LiteralPath (Join-Path $tlsSource 'hec-server.pem') -Destination $tlsTarget
Copy-Item -LiteralPath (Join-Path $tlsSource 'hec-ca.pem') -Destination $tlsTarget
$settings = Get-Content -LiteralPath (Join-Path $tlsSource 'install-settings.json') -Raw | ConvertFrom-Json
$body = [regex]::Replace($httpSection.Groups['body'].Value, '(?m)^\s*(serverCert|sslPassword)\s*=.*\r?\n?', '')
$replacement = "[http]`r`nserverCert = $tlsTarget\hec-server.pem`r`nsslPassword = " + $settings.sslPassword + "`r`n" + $body
$updated = $content.Substring(0, $httpSection.Index) + $replacement + $content.Substring($httpSection.Index + $httpSection.Length)
[IO.File]::WriteAllText($inputPath, $updated, [Text.UTF8Encoding]::new($false))
try {
    $service = Get-Service -Name Splunkd
    if ($service.Status -eq 'StopPending') {
        $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(60))
        $service.Refresh()
    }
    if ($service.Status -eq 'StartPending') {
        $service.WaitForStatus('Running', [TimeSpan]::FromSeconds(60))
        $service.Refresh()
    }
    if ($service.Status -eq 'Running') {
        Stop-Service -Name Splunkd
        (Get-Service Splunkd).WaitForStatus('Stopped', [TimeSpan]::FromSeconds(60))
    }
    Start-Service -Name Splunkd
    (Get-Service Splunkd).WaitForStatus('Running', [TimeSpan]::FromSeconds(60))
    Write-Host 'HEC certificate installed. Splunkd is running.'
    Write-Host ('Configuration backup: ' + $backup)
} catch {
    Copy-Item -LiteralPath $backup -Destination $inputPath -Force
    Write-Warning 'Original configuration restored. Start Splunkd and inspect the local Splunk logs.'
    throw
}
