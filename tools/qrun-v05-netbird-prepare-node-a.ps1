[CmdletBinding()]
param(
    [switch]$ConfirmRestrictiveNetBirdPolicyVerified,
    [string]$OverlayIp
)

$ErrorActionPreference = "Stop"
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$target = Join-Path $repoRoot "src/native/pow_bench/target/release"
$nodeExe = Join-Path $target "qrun_v05_pow_local_node.exe"
$authorityExe = Join-Path $target "qrun_v05_reference_time_authority.exe"
$noiseExe = Join-Path $target "qrun_v05_noise_key_provision.exe"
$smokeExe = Join-Path $target "qrun_v05_public_alpha_process_smoke.exe"
$netbirdExe = "C:\Program Files\NetBird\netbird.exe"
$root = $null
$authorityProcess = $null
$nodeProcess = $null
$canaryProcess = $null

function Assert-Hex32([string]$Name, [string]$Value) {
    if ($Value -notmatch '^[0-9a-fA-F]{64}$' -or $Value -match '^0{64}$') {
        throw "$Name is not a nonzero 32-byte hexadecimal value."
    }
}

function ConvertTo-QuotedArgument([string]$Value) {
    return '"' + $Value.Replace('"', '\"') + '"'
}

function Stop-Child([System.Diagnostics.Process]$Process) {
    if ($Process) {
        try {
            $Process.Refresh()
            if (-not $Process.HasExited) {
                Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue
                Wait-Process -Id $Process.Id -Timeout 10 -ErrorAction SilentlyContinue
            }
        } catch {}
    }
}

try {
    if (-not $ConfirmRestrictiveNetBirdPolicyVerified) {
        throw "Refusing to open Node A listeners until restrictive NetBird policies have been independently re-verified."
    }
    if (-not (Test-Path $netbirdExe)) { throw "NetBird CLI is not installed." }
    # Clear the client-side block-inbound override only after the operator has verified
    # that Default all-to-all is disabled and the qrun-node-b -> qrun-node-a ACLs are exact.
    & $netbirdExe up --block-inbound=false
    if ($LASTEXITCODE -ne 0) { throw "Could not apply the policy-scoped NetBird inbound mode." }
    foreach ($path in @($nodeExe,$authorityExe,$noiseExe,$smokeExe)) {
        if (-not (Test-Path $path)) { throw "Required release binary is missing: $path" }
    }

    $status = (& $netbirdExe status 2>&1 | Out-String)
    if ($LASTEXITCODE -ne 0 -or $status -notmatch "Management:\s+Connected" -or $status -notmatch "Signal:\s+Connected") {
        throw "NetBird is not connected to Management and Signal."
    }
    $ipMatch = [regex]::Match($status, "NetBird IP:\s+([0-9]{1,3}(?:\.[0-9]{1,3}){3})")
    if (-not $ipMatch.Success) { throw "Could not determine the local NetBird IPv4 address." }
    $detectedIp = $ipMatch.Groups[1].Value
    if ($OverlayIp -and $OverlayIp -ne $detectedIp) { throw "Supplied overlay IP does not match the local NetBird interface." }
    $OverlayIp = $detectedIp
    $ip = [System.Net.IPAddress]::Parse($OverlayIp)
    $octets = $ip.GetAddressBytes()
    if ($octets[0] -ne 100 -or $octets[1] -lt 64 -or $octets[1] -gt 127) {
        throw "Detected address is outside the NetBird CGNAT overlay range."
    }
    if ($status -match "Peers count:\s+[1-9]") {
        throw "Unexpected NetBird peer already connected; inspect before proceeding with this isolated qualification."
    }

    $root = Join-Path $env:LOCALAPPDATA ("QRun\cross-host-" + [guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Path $root | Out-Null
    $networkBytes = New-Object byte[] 32
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($networkBytes) } finally { $rng.Dispose() }
    $networkId = ([System.BitConverter]::ToString($networkBytes)).Replace("-","").ToLowerInvariant()
    $genesisEpoch = ([DateTimeOffset]::UtcNow.ToUnixTimeSeconds() - 5).ToString()

    $identityLines = & $smokeExe identity
    if ($LASTEXITCODE -ne 0) { throw "Disposable test identity generation failed." }
    $ownerAccount = (($identityLines | Where-Object { "$_" -match "^owner_account_id_hex=" } | Select-Object -First 1) -replace "^owner_account_id_hex=","").Trim()
    $ownerPublic = (($identityLines | Where-Object { "$_" -match "^owner_public_key_hex=" } | Select-Object -First 1) -replace "^owner_public_key_hex=","").Trim()
    Assert-Hex32 "Owner account" $ownerAccount
    Assert-Hex32 "Owner public key" $ownerPublic

    $authorityKey = Join-Path $root "reference-time-authority.ask1"
    $adminKey = Join-Path $root "reference-time-policy-admin.ask1"
    $authorityState = Join-Path $root "authority.rts1"
    $policyFile = Join-Path $root "public-alpha.rtp1"
    $noiseKey = Join-Path $root "node-a.npk1"
    $nodeData = Join-Path $root "node-a-data"
    $nodeTimeState = Join-Path $root "node-a-reference-time.rts1"

    $authorityOutput = & $authorityExe provision-key --network-id-hex $networkId --role reference-time-authority --output $authorityKey
    if ($LASTEXITCODE -ne 0) { throw "Reference-time authority key provisioning failed." }
    $authorityPublic = (($authorityOutput | Where-Object { "$_" -match "^public_key=" } | Select-Object -First 1) -replace "^public_key=","").Trim()
    Assert-Hex32 "Authority public key" $authorityPublic

    $adminOutput = & $authorityExe provision-key --network-id-hex $networkId --role reference-time-policy-admin --output $adminKey
    if ($LASTEXITCODE -ne 0) { throw "Reference-time policy-admin key provisioning failed." }
    $adminPublic = (($adminOutput | Where-Object { "$_" -match "^public_key=" } | Select-Object -First 1) -replace "^public_key=","").Trim()
    Assert-Hex32 "Reference-time admin public key" $adminPublic

    $policyOutput = & $authorityExe create-policy --network-id-hex $networkId --authority-public-key-hex $authorityPublic --policy-admin-key-file $adminKey --policy-admin-public-key-hex $adminPublic --sequence 1 --max-round-trip-ms 5000 --max-local-clock-skew-secs 300 --output $policyFile
    if ($LASTEXITCODE -ne 0) { throw "Signed RTP1 policy creation failed." }
    $policyBytes = [System.IO.File]::ReadAllBytes($policyFile)
    $policyBase64 = [Convert]::ToBase64String($policyBytes)

    $noiseOutput = & $noiseExe --network-id-hex $networkId --output $noiseKey
    if ($LASTEXITCODE -ne 0) { throw "Node A Noise key provisioning failed." }
    $noisePublic = (($noiseOutput | Where-Object { "$_" -match "^public_key_hex=" } | Select-Object -First 1) -replace "^public_key_hex=","").Trim()
    Assert-Hex32 "Node A Noise public key" $noisePublic

    $authorityOut = Join-Path $root "authority.stdout.log"
    $authorityErr = Join-Path $root "authority.stderr.log"
    $authorityArgs = @(
        "serve","--network-id-hex",$networkId,
        "--authority-key-file",$authorityKey,
        "--state-file",$authorityState,
        "--listen",($OverlayIp + ":49550"),
        "--allow-non-loopback","true"
    )
    $quotedAuthority = $authorityArgs | ForEach-Object { ConvertTo-QuotedArgument "$_" }
    $authorityProcess = Start-Process -FilePath $authorityExe -ArgumentList $quotedAuthority -PassThru -WindowStyle Hidden -RedirectStandardOutput $authorityOut -RedirectStandardError $authorityErr
    Set-Content -LiteralPath (Join-Path $root "authority.pid") -Value $authorityProcess.Id -Encoding ASCII

    $authorityReady = $false
    for ($i=0; $i -lt 100; $i++) {
        $authorityProcess.Refresh()
        if ($authorityProcess.HasExited) {
            throw "Reference-time authority exited: $(Get-Content $authorityErr -Raw -ErrorAction SilentlyContinue)"
        }
        $text = Get-Content $authorityOut -Raw -ErrorAction SilentlyContinue
        if ($text -match "qrun_reference_time_authority_ready") { $authorityReady=$true; break }
        Start-Sleep -Milliseconds 100
    }
    if (-not $authorityReady) { throw "Reference-time authority did not become ready." }

    $probeState = Join-Path $root "authority-probe.rts1"
    & $authorityExe probe --network-id-hex $networkId --policy-file $policyFile --policy-admin-public-key-hex $adminPublic --address ($OverlayIp + ":49550") --state-file $probeState
    if ($LASTEXITCODE -ne 0) { throw "Authenticated reference-time probe failed." }

    $nodeOut = Join-Path $root "node-a.stdout.log"
    $nodeErr = Join-Path $root "node-a.stderr.log"
    $nodeArgs = @(
        "--public-alpha",
        "--network-id-hex",$networkId,
        "--owner-account-id-hex",$ownerAccount,
        "--owner-public-key-hex",$ownerPublic,
        "--genesis-time-unix-secs",$genesisEpoch,
        "--data-dir",$nodeData,
        "--rpc-listen","127.0.0.1:49339",
        "--tx-listen","127.0.0.1:49340",
        "--block-listen",($OverlayIp + ":49341"),
        "--noise-private-key-file",$noiseKey,
        "--reference-time-policy-file",$policyFile,
        "--reference-time-admin-public-key-hex",$adminPublic,
        "--reference-time-address",($OverlayIp + ":49550"),
        "--reference-time-state-file",$nodeTimeState
    )
    $quotedNode = $nodeArgs | ForEach-Object { ConvertTo-QuotedArgument "$_" }
    $nodeProcess = Start-Process -FilePath $nodeExe -ArgumentList $quotedNode -PassThru -WindowStyle Hidden -RedirectStandardOutput $nodeOut -RedirectStandardError $nodeErr
    Set-Content -LiteralPath (Join-Path $root "node-a.pid") -Value $nodeProcess.Id -Encoding ASCII

    $stdout = ""
    $statusJson = $null
    for ($i=0; $i -lt 180; $i++) {
        $nodeProcess.Refresh()
        if ($nodeProcess.HasExited) {
            throw "Node A exited: $(Get-Content $nodeErr -Raw -ErrorAction SilentlyContinue)"
        }
        $stdout = Get-Content $nodeOut -Raw -ErrorAction SilentlyContinue
        if ($stdout -match "qrun_pow_local_rpc_ready" -and
            $stdout -match "qrun_pow_local_tx_ready" -and
            $stdout -match "qrun_pow_local_block_ready" -and
            $stdout -match "qrun_reference_time_ready source=ed25519-attested-time-v1 provenance=ConfiguredProvider" -and
            $stdout -match "network_class=public_alpha_experimental_not_mainnet" -and
            $stdout -match "mainnet=false") {
            $statusJson = Invoke-RestMethod -Method Get -Uri "http://127.0.0.1:49339/v1/status" -TimeoutSec 5
            break
        }
        Start-Sleep -Milliseconds 250
    }
    if (-not $statusJson) { throw "Node A failed Public Alpha startup: $(Get-Content $nodeErr -Raw -ErrorAction SilentlyContinue)" }
    if ($statusJson.network_id -ne $networkId) { throw "Node A status reported an unexpected network ID." }

    # These two throwaway TCP canaries make a blocked remote RPC/TX port measurable.
    # The canaries accept no application data and are bound only to the private overlay.
    $canaryScript = Join-Path $PSScriptRoot "qrun-v05-netbird-policy-canary.ps1"
    $canaryStop = Join-Path $root "canary.stop"
    $canaryLog = Join-Path $root "canary.log"
    $canaryArgs = @(
        "-NoProfile","-ExecutionPolicy","Bypass","-File",$canaryScript,
        "-BindIp",$OverlayIp,"-StopFile",$canaryStop,"-LogFile",$canaryLog,"-MaxSeconds","1800"
    )
    $quotedCanary = $canaryArgs | ForEach-Object { ConvertTo-QuotedArgument "$_" }
    $canaryProcess = Start-Process -FilePath (Join-Path $PSHOME "powershell.exe") -ArgumentList $quotedCanary -PassThru -WindowStyle Hidden
    Set-Content -LiteralPath (Join-Path $root "canary.pid") -Value $canaryProcess.Id -Encoding ASCII
    $canaryReady = $false
    for ($i=0; $i -lt 50; $i++) {
        $canaryProcess.Refresh()
        if ($canaryProcess.HasExited) { throw "RPC/TX policy canary exited before readiness." }
        $canaryText = Get-Content -LiteralPath $canaryLog -Raw -ErrorAction SilentlyContinue
        if ($canaryText -match "CANARY_READY=") { $canaryReady=$true; break }
        Start-Sleep -Milliseconds 100
    }
    if (-not $canaryReady) { throw "RPC/TX policy canary did not become ready." }

    $listeners = Get-NetTCPConnection -State Listen -ErrorAction Stop | Where-Object { $_.LocalPort -in 49339,49340,49341,49550 }
    $expected = @(
        @{Port=49339; Address="127.0.0.1"},
        @{Port=49340; Address="127.0.0.1"},
        @{Port=49339; Address=$OverlayIp},
        @{Port=49340; Address=$OverlayIp},
        @{Port=49341; Address=$OverlayIp},
        @{Port=49550; Address=$OverlayIp}
    )
    foreach ($item in $expected) {
        if (-not ($listeners | Where-Object { $_.LocalPort -eq $item.Port -and $_.LocalAddress -eq $item.Address })) {
            throw "Listener $($item.Address):$($item.Port) is missing or bound to an unexpected address."
        }
    }

    $publicConfig = [ordered]@{
        node_a_overlay_ip = $OverlayIp
        network_id_hex = $networkId
        owner_account_id_hex = $ownerAccount
        owner_public_key_hex = $ownerPublic
        genesis_time_unix_secs = $genesisEpoch
        node_a_noise_public_key_hex = $noisePublic
        reference_time_admin_public_key_hex = $adminPublic
        reference_time_policy_base64 = $policyBase64
        qrun_profile_id = $statusJson.profile_id
        node_a_data_dir = $nodeData
        local_secure_root = $root
        mainnet = $false
    }
    $configPath = Join-Path $root "public-runner-config.json"
    $publicConfig | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $configPath -Encoding UTF8

    Write-Host "NODE_A_PUBLIC_ALPHA_READY=PASS"
    Write-Host "AUTHENTICATED_REFERENCE_TIME_READY=PASS"
    Write-Host "NODE_A_P2P_BOUND_TO_NETBIRD_ONLY=PASS"
    Write-Host "RPC_LOOPBACK_ONLY=PASS"
    Write-Host "TRANSACTION_INGRESS_LOOPBACK_ONLY=PASS"
    Write-Host "mainnet=false"
    Write-Host "PUBLIC_CONFIG_PATH=$configPath"
    Write-Host "PUBLIC_CONFIG_JSON_BEGIN"
    $publicConfig | ConvertTo-Json -Depth 4
    Write-Host "PUBLIC_CONFIG_JSON_END"
    Write-Host "PRIVATE_KEY_OUTPUT=NEVER"
    Write-Host "Node A processes will stay running for the cross-host workflow."
}
catch {
    if ($canaryProcess -and $root) {
        New-Item -ItemType File -Path (Join-Path $root "canary.stop") -Force -ErrorAction SilentlyContinue | Out-Null
        Start-Sleep -Milliseconds 300
        Stop-Child $canaryProcess
    }
    Stop-Child $nodeProcess
    Stop-Child $authorityProcess
    if ($root -and (Test-Path $root)) {
        Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
    }
    throw
}
