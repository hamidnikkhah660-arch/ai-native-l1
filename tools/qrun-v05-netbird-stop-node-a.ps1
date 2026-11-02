[CmdletBinding()]
param([Parameter(Mandatory)][string]$PublicConfigPath)

$ErrorActionPreference = "Stop"
$configPath = (Resolve-Path -LiteralPath $PublicConfigPath).Path
$cfg = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
$root = [IO.Path]::GetFullPath([string]$cfg.local_secure_root)
$allowed = [IO.Path]::GetFullPath((Join-Path $env:LOCALAPPDATA "QRun")) + [IO.Path]::DirectorySeparatorChar
if (-not $root.StartsWith($allowed, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Refusing to clean a path outside the dedicated QRun cross-host temp root."
}

$stopFile = Join-Path $root "canary.stop"
New-Item -ItemType File -Path $stopFile -Force | Out-Null
$canaryPidPath = Join-Path $root "canary.pid"
if (Test-Path $canaryPidPath) {
    $canaryPid = 0
    $rawCanaryPid = (Get-Content -LiteralPath $canaryPidPath -Raw).Trim()
    if ([int]::TryParse($rawCanaryPid,[ref]$canaryPid) -and $canaryPid -gt 0) {
        $canaryInfo = Get-CimInstance Win32_Process -Filter "ProcessId=$canaryPid" -ErrorAction SilentlyContinue
        if ($canaryInfo -and $canaryInfo.CommandLine -match "qrun-v05-netbird-policy-canary\.ps1") {
            Stop-Process -Id $canaryPid -Force -ErrorAction SilentlyContinue
            Wait-Process -Id $canaryPid -Timeout 10 -ErrorAction SilentlyContinue
            Write-Host "STOPPED=QRun policy canary"
        }
    }
}

foreach ($name in @("node-a.pid","authority.pid")) {
    $pidPath = Join-Path $root $name
    if (Test-Path $pidPath) {
        $rawPid = (Get-Content -LiteralPath $pidPath -Raw).Trim()
        $processId = 0
        if ([int]::TryParse($rawPid, [ref]$processId) -and $processId -gt 0) {
            $proc = Get-Process -Id $processId -ErrorAction SilentlyContinue
            if ($proc -and $proc.ProcessName -match "^qrun_v05_") {
                Stop-Process -Id $processId -Force -ErrorAction SilentlyContinue
                Wait-Process -Id $processId -Timeout 10 -ErrorAction SilentlyContinue
                Write-Host "STOPPED=$($proc.ProcessName)"
            }
        }
    }
}
if (Test-Path $root) {
    Remove-Item -LiteralPath $root -Recurse -Force
}
Write-Host "NODE_A_TEMP_KEYS_AND_DATA_REMOVED=PASS"
Write-Host "mainnet=false"
