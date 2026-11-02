param([switch]$Release)

$ErrorActionPreference = "Stop"
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { throw "This smoke requires Windows DPAPI." }
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$manifest = Join-Path $repoRoot "src/native/pow_bench/Cargo.toml"
$profile = if ($Release) { "release" } else { "debug" }
$target = Join-Path $repoRoot ("src/native/pow_bench/target/" + $profile)
$nodeExe = Join-Path $target "qrun_v05_pow_local_node.exe"
$authorityExe = Join-Path $target "qrun_v05_reference_time_authority.exe"
$noiseExe = Join-Path $target "qrun_v05_noise_key_provision.exe"
$smokeExe = Join-Path $target "qrun_v05_public_alpha_process_smoke.exe"
$proxyExe = Join-Path $target "qrun_v05_partition_proxy.exe"

function Get-FreePort {
    for ($i=0; $i -lt 40; $i++) {
        $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
        $listener.Start(); $port = ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port; $listener.Stop()
        if (!$script:ports.ContainsKey($port)) { $script:ports[$port]=$true; return $port }
    }
    throw "Unable to allocate a unique loopback port."
}
function Quote-Arg([string]$v) { return '"' + $v.Replace('"','\"') + '"' }
function Stop-Safe($p) {
    if ($p) { try { $p.Refresh(); if (!$p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue; Wait-Process -Id $p.Id -Timeout 10 -ErrorAction SilentlyContinue } } catch {} }
}
function Start-Logged([string]$file,[string[]]$Arguments,[string]$out,[string]$err,[string]$label) {
    $quoted = $Arguments | ForEach-Object { Quote-Arg $_ }
    if (!$quoted -or $quoted.Count -eq 0) { throw "No arguments supplied to process $label." }
    $p = Start-Process -FilePath $file -ArgumentList $quoted -PassThru -WindowStyle Hidden -RedirectStandardOutput $out -RedirectStandardError $err
    $script:children.Add($p)
    Write-Host ($label + "_PID=" + $p.Id)
    return $p
}
function Wait-Marker($p,[string]$out,[string]$marker,[string]$label,[int]$limit=200) {
    for ($i=0; $i -lt $limit; $i++) {
        $p.Refresh()
        if ($p.HasExited) { throw "$label exited before marker $marker. $(Get-Content -LiteralPath $out -Raw -ErrorAction SilentlyContinue)" }
        $text = Get-Content -LiteralPath $out -Raw -ErrorAction SilentlyContinue
        if ($text -and $text.Contains($marker)) { return }
        Start-Sleep -Milliseconds 100
    }
    throw "$label marker timeout: $marker"
}
function Start-Proxy([string]$label,[int]$listen,[int]$dest,[string]$gate,[string]$out,[string]$err) {
    $p = Start-Logged $proxyExe @("--listen","127.0.0.1:$listen","--target","127.0.0.1:$dest","--gate-file",$gate) $out $err $label
    Wait-Marker $p $out "qrun_partition_proxy_ready" $label
    return $p
}
function Start-Node(
    [string]$label,[string]$data,[string]$timeState,[string]$noise,[string]$peer,[string]$peerKey,
    [int]$rpc,[int]$tx,[int]$block,[string]$out,[string]$err,[bool]$sync
) {
    $args = @(
        "--public-alpha","--network-id-hex",$script:network,"--owner-account-id-hex",$script:owner,
        "--owner-public-key-hex",$script:ownerKey,"--genesis-time-unix-secs",$script:genesis,
        "--data-dir",$data,"--rpc-listen","127.0.0.1:$rpc","--tx-listen","127.0.0.1:$tx",
        "--block-listen","127.0.0.1:$block","--noise-private-key-file",$noise,
        "--peer",$peer,"--peer-static-public-key-hex",$peerKey,
        "--reference-time-policy-file",$script:policy,"--reference-time-admin-public-key-hex",$script:adminKey,
        "--reference-time-address",$script:authorityAddress,"--reference-time-state-file",$timeState
    )
    if ($sync) { $args += @("--sync-on-start","true") }
    $p = Start-Logged $nodeExe $args $out $err $label
    for ($i=0; $i -lt 900; $i++) {
        $p.Refresh()
        if ($p.HasExited) { throw "$label exited. STDOUT=$(Get-Content -LiteralPath $out -Raw -ErrorAction SilentlyContinue) STDERR=$(Get-Content -LiteralPath $err -Raw -ErrorAction SilentlyContinue)" }
        $text = Get-Content -LiteralPath $out -Raw -ErrorAction SilentlyContinue
        if ($text -and $text.Contains("qrun_pow_local_rpc_ready") -and $text.Contains("qrun_pow_local_tx_ready") -and $text.Contains("qrun_pow_local_block_ready")) {
            Start-Sleep -Milliseconds 150
            $text = Get-Content -LiteralPath $out -Raw -ErrorAction SilentlyContinue
            if (!$text.Contains("qrun_reference_time_ready source=ed25519-attested-time-v1 provenance=ConfiguredProvider")) { throw "$label did not report authenticated reference time." }
            if ($sync -and $text -notmatch "qrun_pow_authenticated_startup_sync_complete") { throw "$label reached listeners without successful sync." }
            return $p
        }
        Start-Sleep -Milliseconds 100
    }
    throw "$label startup/sync readiness timeout."
}
function Get-Status([int]$port) { Invoke-RestMethod -Method Get -Uri "http://127.0.0.1:$port/v1/status" -TimeoutSec 5 }
function Get-Tx([int]$port,[string]$id) { Invoke-RestMethod -Method Get -Uri "http://127.0.0.1:$port/v1/transaction/$id" -TimeoutSec 5 }
function Get-Balance([int]$port,[string]$id) { Invoke-RestMethod -Method Get -Uri "http://127.0.0.1:$port/v1/balance/$id" -TimeoutSec 5 }
function Wait-Height([int]$port,[uint64]$height,[string]$label) {
    for ($i=0; $i -lt 1800; $i++) {
        try { $s=Get-Status $port; if ([uint64]$s.height -ge $height) { return $s } } catch {}
        Start-Sleep -Milliseconds 250
    }
    throw "$label did not reach height $height."
}
function Submit-Tx([string]$mode,[int]$port,[string]$label) {
    $lines = & $smokeExe $mode --network-id-hex $script:network --address "127.0.0.1:$port"
    if ($LASTEXITCODE -ne 0) { throw "$label QZTS submission failed: $($lines -join ' ')" }
    $idLine = $lines | Where-Object { $_ -match "^transaction_id=" } | Select-Object -First 1
    $statusLine = $lines | Where-Object { $_ -match "^qzts_status=" } | Select-Object -First 1
    $id = $idLine -replace "^transaction_id=",""
    if ($id.Length -ne 64 -or ($statusLine -replace "^qzts_status=","") -ne "Accepted") { throw "$label QZTA ACK invalid." }
    Write-Host ($label + "_TXID=" + $id)
    Write-Host ($label + "_ACCEPTED=PASS")
    return $id
}

$root = Join-Path $env:TEMP ("qrun-public-alpha-partition-reorg-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $root | Out-Null
$script:ports = @{}
$script:children = New-Object System.Collections.Generic.List[object]
$success = $false
try {
    Write-Host "=== Build node, signed-time authority, test signer and TCP partition proxies ==="
    $build = @("build","--manifest-path",$manifest,"--bin","qrun_v05_pow_local_node","--bin","qrun_v05_reference_time_authority","--bin","qrun_v05_noise_key_provision","--bin","qrun_v05_public_alpha_process_smoke","--bin","qrun_v05_partition_proxy","--locked","--offline")
    if ($Release) { $build += "--release" }
    & cargo @build
    if ($LASTEXITCODE -ne 0) { throw "Offline $profile build failed." }

    $identity = & $smokeExe identity
    if ($LASTEXITCODE -ne 0) { throw "Disposable signer identity failed." }
    $script:owner = (($identity | Where-Object {$_ -match "^owner_account_id_hex="} | Select-Object -First 1) -replace "^owner_account_id_hex=","")
    $script:ownerKey = (($identity | Where-Object {$_ -match "^owner_public_key_hex="} | Select-Object -First 1) -replace "^owner_public_key_hex=","")
    if ($owner.Length -ne 64 -or $ownerKey.Length -ne 64) { throw "Test signer identity invalid." }
    $bytes = New-Object byte[] 32
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {$rng.GetBytes($bytes)} finally {$rng.Dispose()}
    $script:network = ([BitConverter]::ToString($bytes)).Replace("-","").ToLowerInvariant()
    $script:genesis = ([DateTimeOffset]::UtcNow.ToUnixTimeSeconds()-5).ToString()

    $authKeyFile = Join-Path $root "authority.ask1"
    $adminKeyFile = Join-Path $root "policy-admin.ask1"
    $script:policy = Join-Path $root "public-alpha.rtp1"
    $authState = Join-Path $root "authority.rts1"
    $authOut = Join-Path $root "authority.stdout.log"
    $authErr = Join-Path $root "authority.stderr.log"
    $o = & $authorityExe provision-key --network-id-hex $network --role reference-time-authority --output $authKeyFile
    if ($LASTEXITCODE -ne 0) { throw "Authority key provision failed." }
    $authPublic = (($o | Where-Object {$_ -match "^public_key="} | Select-Object -First 1) -replace "^public_key=","")
    $o = & $authorityExe provision-key --network-id-hex $network --role reference-time-policy-admin --output $adminKeyFile
    if ($LASTEXITCODE -ne 0) { throw "Policy admin provision failed." }
    $script:adminKey = (($o | Where-Object {$_ -match "^public_key="} | Select-Object -First 1) -replace "^public_key=","")
    $o = & $authorityExe create-policy --network-id-hex $network --authority-public-key-hex $authPublic --policy-admin-key-file $adminKeyFile --policy-admin-public-key-hex $adminKey --sequence 1 --max-round-trip-ms 5000 --max-local-clock-skew-secs 300 --output $policy
    if ($LASTEXITCODE -ne 0) { throw "RTP1 creation failed." }
    $authPort=Get-FreePort
    $script:authorityAddress="127.0.0.1:$authPort"
    $authority=Start-Logged $authorityExe @("serve","--network-id-hex",$network,"--authority-key-file",$authKeyFile,"--state-file",$authState,"--listen",$authorityAddress) $authOut $authErr "authority"
    Wait-Marker $authority $authOut "qrun_reference_time_authority_ready" "Authority"

    $noiseA=Join-Path $root "node-a.npk1"; $noiseB=Join-Path $root "node-b.npk1"
    $noiseOutA=& $noiseExe --network-id-hex $network --output $noiseA
    if ($LASTEXITCODE -ne 0) { throw "Noise key A provision failed." }
    $noiseOutB=& $noiseExe --network-id-hex $network --output $noiseB
    if ($LASTEXITCODE -ne 0) { throw "Noise key B provision failed." }
    $pubA=(($noiseOutA | Where-Object {$_ -match "^public_key_hex="} | Select-Object -First 1) -replace "^public_key_hex=","")
    $pubB=(($noiseOutB | Where-Object {$_ -match "^public_key_hex="} | Select-Object -First 1) -replace "^public_key_hex=","")
    if ($pubA.Length -ne 64 -or $pubB.Length -ne 64 -or $pubA -eq $pubB) { throw "Noise static keys are not distinct." }

    $rpcA=Get-FreePort; $txA=Get-FreePort; $blockA=Get-FreePort
    $rpcB=Get-FreePort; $txB=Get-FreePort; $blockB=Get-FreePort
    $proxyAB=Get-FreePort; $proxyBA=Get-FreePort
    $gateAB=Join-Path $root "gate-a-to-b.open"; $gateBA=Join-Path $root "gate-b-to-a.open"
    $dataA=Join-Path $root "node-a-data"; $dataB=Join-Path $root "node-b-data"
    $timeA=Join-Path $root "node-a-time.rts1"; $timeB=Join-Path $root "node-b-time.rts1"
    $outA=Join-Path $root "node-a.stdout.log"; $errA=Join-Path $root "node-a.stderr.log"
    $outB=Join-Path $root "node-b.stdout.log"; $errB=Join-Path $root "node-b.stderr.log"
    $pOutA=Join-Path $root "proxy-a.stdout.log"; $pErrA=Join-Path $root "proxy-a.stderr.log"
    $pOutB=Join-Path $root "proxy-b.stdout.log"; $pErrB=Join-Path $root "proxy-b.stderr.log"

    Write-Host "=== Start two directional proxies with gates closed ==="
    $proxyA=Start-Proxy "proxy-a-to-b" $proxyAB $blockB $gateAB $pOutA $pErrA
    $proxyB=Start-Proxy "proxy-b-to-a" $proxyBA $blockA $gateBA $pOutB $pErrB
    Write-Host "PARTITION_GATES_CLOSED=PASS"

    Write-Host "=== Start both independent Public Alpha node processes ==="
    $nodeA=Start-Node "node-a" $dataA $timeA $noiseA "127.0.0.1:$proxyAB" $pubB $rpcA $txA $blockA $outA $errA $false
    $nodeB=Start-Node "node-b" $dataB $timeB $noiseB "127.0.0.1:$proxyBA" $pubA $rpcB $txB $blockB $outB $errB $false
    $sA=Get-Status $rpcA; $sB=Get-Status $rpcB
    if ($sA.height -ne 0 -or $sB.height -ne 0 -or $sA.tip -ne $sB.tip -or $sA.genesis_id -ne $sB.genesis_id -or $sA.profile_id -ne $sB.profile_id) {
        throw "Two node processes did not open the same fresh Genesis/profile."
    }
    Write-Host "TWO_PROCESS_SHARED_GENESIS=PASS"

    Write-Host "=== Partitioned Node A creates its own nonce-1 branch ==="
    $txA1=Submit-Tx "submit" $txA "branch-a"
    $sA=Wait-Height $rpcA 1 "Node A"; $sB=Get-Status $rpcB
    if ($sA.height -ne 1 -or $sB.height -ne 0) { throw "Node B received a block while the partition was closed." }
    if ((Get-Tx $rpcA $txA1).status -ne "confirmed" -or (Get-Tx $rpcB $txA1).status -ne "not_found_in_canonical_chain") {
        throw "Branch-A receipt crossed the closed partition."
    }
    Write-Host "PARTITION_BRANCH_A_HEIGHT1=PASS"

    Write-Host "=== Partitioned Node B creates a conflicting nonce-1 branch ==="
    $txB1=Submit-Tx "submit-conflict" $txB "branch-b-nonce1"
    $sB=Wait-Height $rpcB 1 "Node B height 1"; $sA=Get-Status $rpcA
    if ($sB.height -ne 1 -or $sA.height -ne 1 -or $sA.tip -eq $sB.tip) { throw "Competing height-1 branches were not kept isolated." }
    if ((Get-Tx $rpcB $txB1).status -ne "confirmed" -or (Get-Tx $rpcA $txB1).status -ne "not_found_in_canonical_chain") {
        throw "Branch-B nonce-1 receipt crossed the closed partition."
    }
    Write-Host "PARTITION_CONFLICTING_NONCE1=PASS"

    Write-Host "=== Node B extends its branch with nonce 2 ==="
    $txB2=Submit-Tx "submit-next" $txB "branch-b-nonce2"
    $sB=Wait-Height $rpcB 2 "Node B height 2"; $sA=Get-Status $rpcA
    if ($sB.height -ne 2 -or $sA.height -ne 1 -or $sA.tip -eq $sB.tip) { throw "Expected height-1/height-2 divergent partition was not produced." }
    if ((Get-Tx $rpcB $txB2).status -ne "confirmed" -or (Get-Tx $rpcA $txB2).status -ne "not_found_in_canonical_chain") {
        throw "Branch-B nonce-2 receipt crossed the closed partition."
    }
    $logAB=Get-Content -LiteralPath $pOutA -Raw; $logBA=Get-Content -LiteralPath $pOutB -Raw
    if ($logAB -notmatch "qrun_partition_proxy_denied" -or $logBA -notmatch "qrun_partition_proxy_denied") {
        throw "Both directional proxies did not record denied connections."
    }
    Write-Host "TWO_PROCESS_PARTITION_DIVERGENCE=PASS"
    Write-Host "partition_a_height=$($sA.height)"
    Write-Host "partition_b_height=$($sB.height)"

    Write-Host "=== Heal network and restart Node A with pinned authenticated sync ==="
    New-Item -ItemType File -Path $gateAB | Out-Null
    New-Item -ItemType File -Path $gateBA | Out-Null
    Stop-Safe $nodeA
    $nodeA=Start-Node "node-a-startup-sync" $dataA $timeA $noiseA "127.0.0.1:$proxyAB" $pubB $rpcA $txA $blockA $outA $errA $true
    $syncedA=Get-Status $rpcA; $syncedB=Get-Status $rpcB
    if ($syncedA.height -ne 2 -or $syncedA.tip -ne $syncedB.tip -or $syncedA.state_root -ne $syncedB.state_root) {
        throw "Node A did not reorg to the greater-cumulative-work Node B branch."
    }
    if ((Get-Tx $rpcA $txA1).status -ne "not_found_in_canonical_chain" -or (Get-Tx $rpcA $txB1).status -ne "confirmed" -or (Get-Tx $rpcA $txB2).status -ne "confirmed") {
        throw "Canonical transaction receipts were not switched to branch B."
    }
    $ownerA=Get-Balance $rpcA $owner; $ownerB=Get-Balance $rpcB $owner
    $recipientB1=("79" * 32); $recipientB2=("7a" * 32)
    $balanceB1=Get-Balance $rpcA $recipientB1; $balanceB2=Get-Balance $rpcA $recipientB2
    if ($ownerA.nonce -ne 2 -or $ownerA.nonce -ne $ownerB.nonce -or $ownerA.balance_atoms -ne $ownerB.balance_atoms -or $balanceB1.balance_atoms -ne 2000 -or $balanceB2.balance_atoms -ne 3000) {
        throw "Owner nonce/balance or winning-branch recipient balances mismatch after reorg."
    }
    Write-Host "AUTHENTICATED_STARTUP_SYNC_REORG=PASS"
    Write-Host "CANONICAL_RECEIPTS_AND_BALANCES_CORRECTED=PASS"

    Write-Host "=== Restart Node A again without sync and verify durable selected tip/receipts ==="
    Stop-Safe $nodeA
    $nodeA=Start-Node "node-a-durable-reopen" $dataA $timeA $noiseA "127.0.0.1:$proxyAB" $pubB $rpcA $txA $blockA $outA $errA $false
    $reopened=Get-Status $rpcA
    if ($reopened.height -ne 2 -or $reopened.tip -ne $syncedB.tip -or $reopened.state_root -ne $syncedB.state_root) {
        throw "Durable reopen did not retain the post-reorg canonical branch."
    }
    if ((Get-Tx $rpcA $txA1).status -ne "not_found_in_canonical_chain" -or (Get-Tx $rpcA $txB1).status -ne "confirmed" -or (Get-Tx $rpcA $txB2).status -ne "confirmed") {
        throw "Durable reopen restored stale canonical receipt state."
    }
    $reopenedOwner=Get-Balance $rpcA $owner
    if ($reopenedOwner.nonce -ne 2 -or $reopenedOwner.balance_atoms -ne $ownerB.balance_atoms) { throw "Owner ledger changed after durable reopen." }

    Write-Host "MULTIPROCESS_PARTITION_RECONNECT_REORG=PASS"
    Write-Host "DURABLE_REOPEN_AFTER_NETWORK_REORG=PASS"
    Write-Host "node_a_height=$($reopened.height)"
    Write-Host "node_b_height=$($syncedB.height)"
    Write-Host "canonical_tip=$($reopened.tip)"
    Write-Host "canonical_state_root=$($reopened.state_root)"
    Write-Host "orphaned_tx=$txA1"
    Write-Host "canonical_branch_tx_nonce1=$txB1"
    Write-Host "canonical_branch_tx_nonce2=$txB2"
    Write-Host "mainnet=false"
    Write-Host "QRun_PUBLIC_ALPHA_PARTITION_REORG_MULTIPROCESS_SMOKE=PASS"
    $success=$true
}
catch {
    Write-Host "QRun_PUBLIC_ALPHA_PARTITION_REORG_MULTIPROCESS_SMOKE=FAIL"
    Write-Host "SMOKE_ARTIFACTS_PRESERVED=$root"
    throw
}
finally {
    foreach ($p in $script:children) { Stop-Safe $p }
    if ($success) { Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue }
}
