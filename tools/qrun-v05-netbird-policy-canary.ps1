[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$BindIp,
    [Parameter(Mandatory)][string]$StopFile,
    [Parameter(Mandatory)][string]$LogFile,
    [int]$MaxSeconds = 1800
)

$ErrorActionPreference = "Stop"
$listeners = @()
$deadline = [DateTime]::UtcNow.AddSeconds($MaxSeconds)
try {
    $ip = [System.Net.IPAddress]::Parse($BindIp)
    $octets = $ip.GetAddressBytes()
    if ($octets[0] -ne 100 -or $octets[1] -lt 64 -or $octets[1] -gt 127) {
        throw "Canary bind IP must be a NetBird overlay address."
    }
    foreach ($port in @(49339,49340)) {
        $listener = [System.Net.Sockets.TcpListener]::new($ip,$port)
        $listener.Start(8)
        $listeners += $listener
    }
    Set-Content -LiteralPath $LogFile -Value ("CANARY_READY=" + $BindIp) -Encoding ASCII
    while ([DateTime]::UtcNow -lt $deadline -and -not (Test-Path -LiteralPath $StopFile)) {
        foreach ($listener in $listeners) {
            if ($listener.Pending()) {
                $client = $listener.AcceptTcpClient()
                try {
                    $endpoint = $client.Client.RemoteEndPoint.ToString()
                    Add-Content -LiteralPath $LogFile -Value "UNEXPECTED_CONNECT=$endpoint"
                } finally {
                    $client.Dispose()
                }
            }
        }
        Start-Sleep -Milliseconds 100
    }
}
finally {
    foreach ($listener in $listeners) {
        try { $listener.Stop() } catch {}
    }
    Add-Content -LiteralPath $LogFile -Value ("CANARY_STOPPED=" + [DateTime]::UtcNow.ToString("o")) -ErrorAction SilentlyContinue
}
