[CmdletBinding()]
param(
    [ValidateRange(1024,65535)]
    [int]$ListenPort = 31000
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$SeedHost = 'heymed.tail2a756d.ts.net'
$SeedPort = 443
if (-not [Environment]::Is64BitOperatingSystem) { throw 'This package requires Windows x64.' }
$os = Get-CimInstance Win32_OperatingSystem
$freeRamGB = [math]::Round(($os.FreePhysicalMemory * 1KB) / 1GB, 2)
$drive = [System.IO.Path]::GetPathRoot($Root).Substring(0,1)
$freeDisk = (Get-PSDrive -Name $drive).Free
Write-Host ("OS: {0} ({1})" -f $os.Caption,$os.OSArchitecture)
Write-Host ("Free RAM: {0} GB" -f $freeRamGB)
Write-Host ("Free disk on package drive: {0} GB" -f [math]::Round($freeDisk / 1GB,2))
if ($freeRamGB -lt 2) { throw 'At least 2 GB free RAM is required before node startup.' }
if ($freeDisk -lt 1GB) { throw 'At least 1 GB free disk space is required.' }
$probe = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Any,$ListenPort)
try { $probe.Start(); Write-Host ("Local listen port {0}: available" -f $ListenPort) }
catch { throw "Local port $ListenPort is unavailable: $($_.Exception.Message)" }
finally { $probe.Stop() }
try {
    $resolved = Resolve-DnsName -Name $SeedHost -ErrorAction Stop |
        Where-Object { $_.IPAddress } | Select-Object -ExpandProperty IPAddress -Unique
    if (!$resolved) { throw 'No address records returned.' }
    Write-Host ("Seed DNS routes: " + ($resolved -join ', '))
} catch { throw "Seed DNS resolution failed: $($_.Exception.Message)" }
$tcp = Test-NetConnection -ComputerName $SeedHost -Port $SeedPort -WarningAction SilentlyContinue
if (!$tcp.TcpTestSucceeded) { throw ("Outbound TCP to " + $SeedHost + ":" + $SeedPort + " failed. No firewall change was attempted.") }
Write-Host 'Pinned Seed TCP/443 reachability: PASS'
Write-Host 'No firewall, router, NAT, tunnel, service, key or node setting was changed.'
Write-Host 'QFP6_PUBLIC_ALPHA_HOST_PREFLIGHT=PASS'