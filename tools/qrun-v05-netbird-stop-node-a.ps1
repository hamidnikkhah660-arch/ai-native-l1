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

# Re-enable the workstation's fail-closed inbound posture after stopping QRun listeners.
$netbirdExe = "C:\Program Files\NetBird\netbird.exe"
if (Test-Path $netbirdExe) {
    # Force a reconnect because "up" on an already-connected client may not
    # apply changes to the block-inbound flag (it can return "Already connected").
    & $netbirdExe down 2>&1 | Out-Null
    & $netbirdExe up --block-inbound 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Could not restore NetBird block-inbound protection." }
    $restoredStatus = (& $netbirdExe status 2>&1 | Out-String)
    if ($LASTEXITCODE -ne 0 -or $restoredStatus -notmatch "Management:\s+Connected" -or $restoredStatus -notmatch "Signal:\s+Connected") {
        throw "NetBird did not reconnect after restoring fail-closed inbound protection."
    }
    Write-Host "NETBIRD_BLOCK_INBOUND_RESTORED=PASS"
}

if (Test-Path $root) {
    Remove-Item -LiteralPath $root -Recurse -Force
}
Write-Host "NODE_A_TEMP_KEYS_AND_DATA_REMOVED=PASS"
Write-Host "mainnet=false"
