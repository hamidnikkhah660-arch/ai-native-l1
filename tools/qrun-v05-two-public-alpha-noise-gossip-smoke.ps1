param()

$ErrorActionPreference = "Stop"
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$manifest = Join-Path $repoRoot "src/native/pow_bench/Cargo.toml"
$target = Join-Path $repoRoot "src/native/pow_bench/target/debug"
$authorityExe = Join-Path $target "qrun_v05_reference_time_authority.exe"
$nodeExe = Join-Path $target "qrun_v05_pow_local_node.exe"
$noiseExe = Join-Path $target "qrun_v05_noise_key_provision.exe"
$txBuilderExe = Join-Path $target "qrun_v05_smoke_tx_builder.exe"
$txSenderExe = Join-Path $target "qrun_v05_smoke_tx_sender.exe"

function Get-FreeLoopbackPort {
    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    $listener.Start()
    $port = ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port
    $listener.Stop()
    return $port
}

function ConvertTo-StartProcessArgument([string]$Value) {
    return '"' + $Value + '"'
}

function Stop-ProcessSafe($Process) {
    if ($Process -and !$Process.HasExited) {
        Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue
        Wait-Process -Id $Process.Id -Timeout 10 -ErrorAction SilentlyContinue
    }
}

function Start-Authority {
    $script:authorityProcess = Start-Process -FilePath $authorityExe -ArgumentList @(
        "serve", "--network-id-hex", $networkId,
        "--authority-key-file", $authorityKey,
        "--state-file", $authorityState,
        "--listen", $authorityAddress
    ) -PassThru -WindowStyle Hidden -RedirectStandardOutput $authorityStdout -RedirectStandardError $authorityStderr

    for ($i = 0; $i -lt 120; $i++) {
        if ($script:authorityProcess.HasExited) {
            $outText = Get-Content -LiteralPath $authorityStdout -Raw -ErrorAction SilentlyContinue
            $errText = Get-Content -LiteralPath $authorityStderr -Raw -ErrorAction SilentlyContinue
            throw "Authority exited before readiness. STDOUT=$outText STDERR=$errText"
        }
        $outText = Get-Content -LiteralPath $authorityStdout -Raw -ErrorAction SilentlyContinue
        if ($outText -match "qrun_reference_time_authority_ready") { return }
        Start-Sleep -Milliseconds 100
    }
    throw "Authority readiness marker was not observed."
}

function Start-QRunNode(
    [string]$Label,
    [string]$DataDir,
    [string]$StateFile,
    [string]$NoiseKey,
    [string]$NoisePeerPin,
    [int]$RpcPort,
    [int]$TxPort,
    [int]$BlockPort,
    [int]$PeerPort,
    [string]$Stdout,
    [string]$Stderr
) {
    $arguments = @(
        "--public-alpha",
        "--network-id-hex", $networkId,
        "--owner-account-id-hex", $ownerAccount,
        "--owner-public-key-hex", $ownerPublicKey,
        "--genesis-time-unix-secs", $genesisEpoch,
        "--data-dir", $DataDir,
        "--rpc-listen", "127.0.0.1:$RpcPort",
        "--tx-listen", "127.0.0.1:$TxPort",
        "--block-listen", "127.0.0.1:$BlockPort",
        "--noise-private-key-file", $NoiseKey,
        "--peer", "127.0.0.1:$PeerPort",
        "--peer-static-public-key-hex", $NoisePeerPin,
        "--reference-time-policy-file", $policyFile,
        "--reference-time-admin-public-key-hex", $adminPublicKey,
        "--reference-time-address", $authorityAddress,
        "--reference-time-state-file", $StateFile
    )
    $quoted = $arguments | ForEach-Object { ConvertTo-StartProcessArgument $_ }
    $process = Start-Process -FilePath $nodeExe -ArgumentList $quoted -PassThru -WindowStyle Hidden -RedirectStandardOutput $Stdout -RedirectStandardError $Stderr

    for ($i = 0; $i -lt 300; $i++) {
        if ($process.HasExited) {
            $outText = Get-Content -LiteralPath $Stdout -Raw -ErrorAction SilentlyContinue
            $errText = Get-Content -LiteralPath $Stderr -Raw -ErrorAction SilentlyContinue
            throw "$Label exited during startup (exit $($process.ExitCode)). STDOUT=$outText STDERR=$errText"
        }
        $outText = Get-Content -LiteralPath $Stdout -Raw -ErrorAction SilentlyContinue
        if ($outText -match "qrun_pow_local_block_ready" -and $outText -match "qrun_pow_local_tx_ready") {
            if ($outText -notmatch "qrun_reference_time_ready source=ed25519-attested-time-v1 provenance=ConfiguredProvider") {
                throw "$Label did not report the authenticated reference-time provider."
            }
            if ($outText -notmatch "configured_peer_count=1" -or $outText -notmatch "mainnet=false") {
                throw "$Label is missing peer or experimental-network telemetry."
            }
            return $process
        }
        Start-Sleep -Milliseconds 100
    }
    Stop-ProcessSafe $process
    $outText = Get-Content -LiteralPath $Stdout -Raw -ErrorAction SilentlyContinue
    $errText = Get-Content -LiteralPath $Stderr -Raw -ErrorAction SilentlyContinue
    throw "$Label did not become ready. STDOUT=$outText STDERR=$errText"
}

if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw "This smoke test uses Windows CurrentUser DPAPI and must run on Windows."
}

$root = Join-Path $env:TEMP ("qrun-two-public-alpha-noise-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $root | Out-Null
$authorityProcess = $null
$nodeA = $null
$nodeB = $null
try {
    Write-Host "=== Build actual node, Authority, Noise-key provisioner and ephemeral TXN2 builder ==="
    & cargo build --manifest-path $manifest --bin qrun_v05_pow_local_node --bin qrun_v05_reference_time_authority --bin qrun_v05_noise_key_provision --bin qrun_v05_smoke_tx_builder --bin qrun_v05_smoke_tx_sender --locked --offline
    if ($LASTEXITCODE -ne 0) { throw "QRun smoke binaries did not build (exit $LASTEXITCODE)." }

    $networkBytes = New-Object byte[] 32
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($networkBytes) } finally { $rng.Dispose() }
    $networkId = -join ($networkBytes | ForEach-Object { $_.ToString("x2") })
    $genesisEpoch = ([DateTimeOffset]::UtcNow.ToUnixTimeSeconds() - 3).ToString()
    $expiry = ([DateTimeOffset]::UtcNow.ToUnixTimeSeconds() + 3600).ToString()

    $authorityKey = Join-Path $root "authority.ask1"
    $adminKey = Join-Path $root "policy-admin.ask1"
    $authorityState = Join-Path $root "authority.rts1"
    $policyFile = Join-Path $root "shared.rtp1"
    $authorityStdout = Join-Path $root "authority.stdout.log"
    $authorityStderr = Join-Path $root "authority.stderr.log"

    $noiseA = Join-Path $root "node-a.npk1"
    $noiseB = Join-Path $root "node-b.npk1"
    $stateA = Join-Path $root "node-a-reference-time.rts1"
    $stateB = Join-Path $root "node-b-reference-time.rts1"
    $dataA = Join-Path $root "node-a-data"
    $dataB = Join-Path $root "node-b-data"
    $stdoutA = Join-Path $root "node-a.stdout.log"
    $stderrA = Join-Path $root "node-a.stderr.log"
    $stdoutB = Join-Path $root "node-b.stdout.log"
    $stderrB = Join-Path $root "node-b.stderr.log"

    Write-Host "=== Create ephemeral network identity and signed reference-time policy ==="
    $ownerOutPath = Join-Path $root "signed-tx-nonce1.qzts"
    $ownerOutPath2 = Join-Path $root "signed-tx-nonce2.qzts"
    $authorityOut = & $authorityExe provision-key --network-id-hex $networkId --role reference-time-authority --output $authorityKey
    if ($LASTEXITCODE -ne 0) { throw "Authority provisioning failed: $($authorityOut -join ' ')" }
    $authorityPublicKey = ($authorityOut | Where-Object { $_ -match "^public_key=" } | Select-Object -First 1) -replace "^public_key=", ""
    $adminOut = & $authorityExe provision-key --network-id-hex $networkId --role reference-time-policy-admin --output $adminKey
    if ($LASTEXITCODE -ne 0) { throw "Policy Admin provisioning failed: $($adminOut -join ' ')" }
    $adminPublicKey = ($adminOut | Where-Object { $_ -match "^public_key=" } | Select-Object -First 1) -replace "^public_key=", ""
    if (!$authorityPublicKey -or !$adminPublicKey) { throw "Missing reference-time public key pins." }
    $policyOut = & $authorityExe create-policy --network-id-hex $networkId --authority-public-key-hex $authorityPublicKey --policy-admin-key-file $adminKey --policy-admin-public-key-hex $adminPublicKey --sequence 1 --max-round-trip-ms 5000 --max-local-clock-skew-secs 300 --output $policyFile
    if ($LASTEXITCODE -ne 0) { throw "RTP1 policy creation failed: $($policyOut -join ' ')" }

    Write-Host "=== Generate disposable owner identity and real signed TXN2/QZTS request ==="
    $txOut = & $txBuilderExe --network-id-hex $networkId --expires-at-unix-secs $expiry --output $ownerOutPath --second-output $ownerOutPath2
    if ($LASTEXITCODE -ne 0) { throw "Temporary signed transaction creation failed: $($txOut -join ' ')" }
    $ownerAccount = ($txOut | Where-Object { $_ -match "^smoke_owner_account_id_hex=" } | Select-Object -First 1) -replace "^smoke_owner_account_id_hex=", ""
    $ownerPublicKey = ($txOut | Where-Object { $_ -match "^smoke_owner_public_key_hex=" } | Select-Object -First 1) -replace "^smoke_owner_public_key_hex=", ""
    $transactionId = ($txOut | Where-Object { $_ -match "^smoke_transaction_id_nonce1_hex=" } | Select-Object -First 1) -replace "^smoke_transaction_id_nonce1_hex=", ""
    $transactionId2 = ($txOut | Where-Object { $_ -match "^smoke_transaction_id_nonce2_hex=" } | Select-Object -First 1) -replace "^smoke_transaction_id_nonce2_hex=", ""
    if ($ownerAccount.Length -ne 64 -or $ownerPublicKey.Length -ne 64 -or $transactionId.Length -ne 64 -or $transactionId2.Length -ne 64 -or $transactionId -eq $transactionId2) {
        throw "Ephemeral owner identity or two distinct sequential TXN2 identifiers were not emitted correctly."
    }
    if (($txOut -join [Environment]::NewLine) -match "private_seed=") {
        throw "The smoke TXN2 builder leaked its ephemeral private seed."
    }
    Write-Host "ephemeral_owner_account_id_hex=$ownerAccount"
    Write-Host "ephemeral_transaction_id_nonce1_hex=$transactionId"
    Write-Host "ephemeral_transaction_id_nonce2_hex=$transactionId2"
    Write-Host "ephemeral_two_sequential_txn2_created=PASS"

    Write-Host "=== Provision two independent DPAPI-bound Noise XX static keys ==="
    $noiseOutA = & $noiseExe --network-id-hex $networkId --output $noiseA
    if ($LASTEXITCODE -ne 0) { throw "Node A Noise key provision failed: $($noiseOutA -join ' ')" }
    $noiseOutB = & $noiseExe --network-id-hex $networkId --output $noiseB
    if ($LASTEXITCODE -ne 0) { throw "Node B Noise key provision failed: $($noiseOutB -join ' ')" }
    $noisePublicA = ($noiseOutA | Where-Object { $_ -match "^public_key_hex=" } | Select-Object -First 1) -replace "^public_key_hex=", ""
    $noisePublicB = ($noiseOutB | Where-Object { $_ -match "^public_key_hex=" } | Select-Object -First 1) -replace "^public_key_hex=", ""
    if ($noisePublicA.Length -ne 64 -or $noisePublicB.Length -ne 64 -or $noisePublicA -eq $noisePublicB) {
        throw "Two distinct protected Noise public keys were not provisioned."
    }
    Write-Host "NOISE_KEY_A_DPAPI=PASS"
    Write-Host "NOISE_KEY_B_DPAPI=PASS"
    Write-Host "independent_noise_keys_distinct=PASS"

    $authorityPort = Get-FreeLoopbackPort
    $authorityAddress = "127.0.0.1:$authorityPort"
    Start-Authority
    Write-Host "REFERENCE_TIME_AUTHORITY_READY=PASS"

    $rpcA = Get-FreeLoopbackPort; $txA = Get-FreeLoopbackPort; $blockA = Get-FreeLoopbackPort
    $rpcB = Get-FreeLoopbackPort; $txB = Get-FreeLoopbackPort; $blockB = Get-FreeLoopbackPort

    Write-Host "=== Start first Public Alpha process with pinned Noise peer B ==="
    $nodeA = Start-QRunNode "node-A" $dataA $stateA $noiseA $noisePublicB $rpcA $txA $blockA $blockB $stdoutA $stderrA
    Write-Host "NODE_A_PUBLIC_ALPHA_READY=PASS"

    Write-Host "=== Start second Public Alpha process with pinned Noise peer A ==="
    $nodeB = Start-QRunNode "node-B" $dataB $stateB $noiseB $noisePublicA $rpcB $txB $blockB $blockA $stdoutB $stderrB
    Write-Host "NODE_B_PUBLIC_ALPHA_READY=PASS"
    Write-Host "two_node_shared_network_genesis_profile=PASS"

    Write-Host "=== Submit real Ed25519-signed QZTS/1 transaction to node A ==="
    try {
        $senderOut = & $txSenderExe --address "127.0.0.1:$txA" --request-file $ownerOutPath --expected-txid-hex $transactionId
        if ($LASTEXITCODE -ne 0) {
            throw "Rust QZTS/1 sender failed: $($senderOut -join ' ')"
        }
        $txidAck = ($senderOut | Where-Object { $_ -match "^qzta_transaction_id_hex=" } | Select-Object -First 1) -replace "^qzta_transaction_id_hex=", ""
        $senderOut | ForEach-Object { Write-Host $_ }
    } catch {
        $outA = Get-Content -LiteralPath $stdoutA -Raw -ErrorAction SilentlyContinue
        $errA = Get-Content -LiteralPath $stderrA -Raw -ErrorAction SilentlyContinue
        $outB = Get-Content -LiteralPath $stdoutB -Raw -ErrorAction SilentlyContinue
        $errB = Get-Content -LiteralPath $stderrB -Raw -ErrorAction SilentlyContinue
        Write-Host "NODE_A_STDOUT_BEGIN"; Write-Host $outA; Write-Host "NODE_A_STDOUT_END"
        Write-Host "NODE_A_STDERR_BEGIN"; Write-Host $errA; Write-Host "NODE_A_STDERR_END"
        Write-Host "NODE_B_STDOUT_BEGIN"; Write-Host $outB; Write-Host "NODE_B_STDOUT_END"
        Write-Host "NODE_B_STDERR_BEGIN"; Write-Host $errB; Write-Host "NODE_B_STDERR_END"
        throw
    }
    if ($txidAck -ne $transactionId) {
        throw "Node A ACK transaction ID differs from the signed TXN2 ($txidAck != $transactionId)."
    }
    Write-Host "NODE_A_TXN2_NONCE1_ACCEPTED=PASS"
    Write-Host "TXID_NONCE1=$txidAck"

    Write-Host "=== Wait for A-to-B Noise block gossip and canonical convergence at height 1 ==="
    $height1Ready = $false
    $tipA1 = $null
    $tipB1 = $null
    for ($i = 0; $i -lt 900; $i++) {
        if ($nodeA.HasExited -or $nodeB.HasExited) {
            $outA = Get-Content -LiteralPath $stdoutA -Raw -ErrorAction SilentlyContinue
            $errA = Get-Content -LiteralPath $stderrA -Raw -ErrorAction SilentlyContinue
            $outB = Get-Content -LiteralPath $stdoutB -Raw -ErrorAction SilentlyContinue
            $errB = Get-Content -LiteralPath $stderrB -Raw -ErrorAction SilentlyContinue
            throw "A QRun node exited before height-1 convergence. A=$outA $errA B=$outB $errB"
        }
        $outA = Get-Content -LiteralPath $stdoutA -Raw -ErrorAction SilentlyContinue
        $outB = Get-Content -LiteralPath $stdoutB -Raw -ErrorAction SilentlyContinue
        $lineA = [regex]::Matches($outA, "qrun_pow_local_tx_ingress accepted_pow_candidate .*canonical_height=1 canonical_tip=([0-9a-f]{64})") | Select-Object -Last 1
        $lineB = [regex]::Matches($outB, "qrun_pow_local_block_gossip accepted height=1 canonical_height=1 canonical_tip=([0-9a-f]{64})") | Select-Object -Last 1
        if ($lineA -and $lineB) {
            $tipA1 = $lineA.Groups[1].Value
            $tipB1 = $lineB.Groups[1].Value
            if ($tipA1 -ne $tipB1) {
                throw "Height-1 canonical tips differ: A=$tipA1 B=$tipB1"
            }
            $height1Ready = $true
            break
        }
        Start-Sleep -Milliseconds 100
    }
    if (!$height1Ready) {
        $outA = Get-Content -LiteralPath $stdoutA -Raw -ErrorAction SilentlyContinue
        $errA = Get-Content -LiteralPath $stderrA -Raw -ErrorAction SilentlyContinue
        $outB = Get-Content -LiteralPath $stdoutB -Raw -ErrorAction SilentlyContinue
        $errB = Get-Content -LiteralPath $stderrB -Raw -ErrorAction SilentlyContinue
        throw "Node B did not confirm the height-1 QFP5 block within 90 seconds. A=$outA STDERR_A=$errA B=$outB STDERR_B=$errB"
    }
    $outA = Get-Content -LiteralPath $stdoutA -Raw
    $outB = Get-Content -LiteralPath $stdoutB -Raw
    if ($outA -notmatch "qrun_pow_local_block_broadcast peer=127\.0\.0\.1:$blockB") {
        throw "Node A does not show the height-1 outbound block broadcast."
    }
    if ($outB -notmatch "qrun_pow_local_block_gossip accepted height=1") {
        throw "Node B does not show independent height-1 block acceptance."
    }
    Write-Host "NODE_A_TO_NODE_B_NOISE_QFP5_GOSSIP=PASS"
    Write-Host "HEIGHT1_CANONICAL_TIP_MATCH=PASS"
    Write-Host "height1_tip_hex=$tipA1"

    Write-Host "=== Submit nonce-2 Ed25519 transaction to node B and verify reverse block gossip ==="
    $senderOut2 = & $txSenderExe --address "127.0.0.1:$txB" --request-file $ownerOutPath2 --expected-txid-hex $transactionId2
    if ($LASTEXITCODE -ne 0) {
        $outA = Get-Content -LiteralPath $stdoutA -Raw -ErrorAction SilentlyContinue
        $errA = Get-Content -LiteralPath $stderrA -Raw -ErrorAction SilentlyContinue
        $outB = Get-Content -LiteralPath $stdoutB -Raw -ErrorAction SilentlyContinue
        $errB = Get-Content -LiteralPath $stderrB -Raw -ErrorAction SilentlyContinue
        Write-Host $outA; Write-Host $errA; Write-Host $outB; Write-Host $errB
        throw "Node B nonce-2 TXN2 was not accepted: $($senderOut2 -join ' ')"
    }
    $txidAck2 = ($senderOut2 | Where-Object { $_ -match "^qzta_transaction_id_hex=" } | Select-Object -First 1) -replace "^qzta_transaction_id_hex=", ""
    if ($txidAck2 -ne $transactionId2) {
        throw "Node B ACK transaction ID differs from nonce-2 signed TXN2 ($txidAck2 != $transactionId2)."
    }
    $senderOut2 | ForEach-Object { Write-Host $_ }
    Write-Host "NODE_B_TXN2_NONCE2_ACCEPTED=PASS"

    Write-Host "=== Wait for B-to-A Noise block gossip and canonical convergence at height 2 ==="
    $height2Ready = $false
    $tipA2 = $null
    $tipB2 = $null
    for ($i = 0; $i -lt 900; $i++) {
        if ($nodeA.HasExited -or $nodeB.HasExited) {
            $outA = Get-Content -LiteralPath $stdoutA -Raw -ErrorAction SilentlyContinue
            $errA = Get-Content -LiteralPath $stderrA -Raw -ErrorAction SilentlyContinue
            $outB = Get-Content -LiteralPath $stdoutB -Raw -ErrorAction SilentlyContinue
            $errB = Get-Content -LiteralPath $stderrB -Raw -ErrorAction SilentlyContinue
            throw "A QRun node exited before height-2 convergence. A=$outA $errA B=$outB $errB"
        }
        $outA = Get-Content -LiteralPath $stdoutA -Raw -ErrorAction SilentlyContinue
        $outB = Get-Content -LiteralPath $stdoutB -Raw -ErrorAction SilentlyContinue
        $lineA2 = [regex]::Matches($outA, "qrun_pow_local_block_gossip accepted height=2 canonical_height=2 canonical_tip=([0-9a-f]{64})") | Select-Object -Last 1
        $lineB2 = [regex]::Matches($outB, "qrun_pow_local_tx_ingress accepted_pow_candidate .*canonical_height=2 canonical_tip=([0-9a-f]{64})") | Select-Object -Last 1
        if ($lineA2 -and $lineB2) {
            $tipA2 = $lineA2.Groups[1].Value
            $tipB2 = $lineB2.Groups[1].Value
            if ($tipA2 -ne $tipB2) {
                throw "Height-2 canonical tips differ: A=$tipA2 B=$tipB2"
            }
            $height2Ready = $true
            break
        }
        Start-Sleep -Milliseconds 100
    }
    if (!$height2Ready) {
        $outA = Get-Content -LiteralPath $stdoutA -Raw -ErrorAction SilentlyContinue
        $errA = Get-Content -LiteralPath $stderrA -Raw -ErrorAction SilentlyContinue
        $outB = Get-Content -LiteralPath $stdoutB -Raw -ErrorAction SilentlyContinue
        $errB = Get-Content -LiteralPath $stderrB -Raw -ErrorAction SilentlyContinue
        throw "Node A did not confirm the height-2 block from node B within 90 seconds. A=$outA STDERR_A=$errA B=$outB STDERR_B=$errB"
    }
    $outA = Get-Content -LiteralPath $stdoutA -Raw
    $outB = Get-Content -LiteralPath $stdoutB -Raw
    if ($outB -notmatch "qrun_pow_local_block_broadcast peer=127\.0\.0\.1:$blockA") {
        throw "Node B does not show the height-2 outbound block broadcast."
    }
    if ($outA -notmatch "qrun_pow_local_block_gossip accepted height=2") {
        throw "Node A does not show independent height-2 block acceptance."
    }
    Write-Host "NODE_B_TO_NODE_A_NOISE_QFP5_GOSSIP=PASS"
    Write-Host "NODE_A_INDEPENDENT_QFP5_ACCEPT=PASS"
    Write-Host "HEIGHT2_CANONICAL_TIP_MATCH=PASS"
    Write-Host "canonical_height=2"
    Write-Host "canonical_tip_hex=$tipA2"
    Write-Host "BIDIRECTIONAL_TWO_PROCESS_PUBLIC_ALPHA_NOISE_GOSSIP=PASS"
    Write-Host "mainnet=false"
}
finally {
    Stop-ProcessSafe $nodeA
    Stop-ProcessSafe $nodeB
    Stop-ProcessSafe $authorityProcess
    Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
}
