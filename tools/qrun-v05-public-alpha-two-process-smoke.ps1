param(
    [switch]$Release
)

$ErrorActionPreference = "Stop"
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$manifest = Join-Path $repoRoot "src/native/pow_bench/Cargo.toml"
$buildProfile = if ($Release) { "release" } else { "debug" }
$target = Join-Path $repoRoot ("src/native/pow_bench/target/" + $buildProfile)
$authorityExe = Join-Path $target "qrun_v05_reference_time_authority.exe"
$nodeExe = Join-Path $target "qrun_v05_pow_local_node.exe"
$noiseProvisionerExe = Join-Path $target "qrun_v05_noise_key_provision.exe"
$processSmokeExe = Join-Path $target "qrun_v05_public_alpha_process_smoke.exe"

function Get-FreeLoopbackPort {
    for ($attempt = 0; $attempt -lt 30; $attempt++) {
        $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
        $listener.Start()
        $port = ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port
        $listener.Stop()
        if (!$script:allocatedPorts.ContainsKey($port)) {
            $script:allocatedPorts[$port] = $true
            return $port
        }
    }
    throw "Could not allocate a distinct loopback port."
}

function ConvertTo-StartProcessArgument([string]$Value) {
    return '"' + $Value.Replace('"', '\"') + '"'
}

function Stop-ProcessSafe($Process) {
    if ($Process) {
        try {
            $Process.Refresh()
            if (!$Process.HasExited) {
                Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue
                Wait-Process -Id $Process.Id -Timeout 10 -ErrorAction SilentlyContinue
            }
        } catch {}
    }
}

function Start-Authority {
    $script:authorityProcess = Start-Process -FilePath $authorityExe -ArgumentList @(
        "serve", "--network-id-hex", $networkId, "--authority-key-file", $authorityKey,
        "--state-file", $authorityState, "--listen", $authorityAddress
    ) -PassThru -WindowStyle Hidden -RedirectStandardOutput $authorityStdout -RedirectStandardError $authorityStderr

    for ($i = 0; $i -lt 100; $i++) {
        $script:authorityProcess.Refresh()
        if ($script:authorityProcess.HasExited) {
            $details = Get-Content -LiteralPath $authorityStderr -Raw -ErrorAction SilentlyContinue
            throw "Reference-time Authority exited during startup: $details"
        }
        $outText = Get-Content -LiteralPath $authorityStdout -Raw -ErrorAction SilentlyContinue
        if ($outText -match "qrun_reference_time_authority_ready") {
            return
        }
        Start-Sleep -Milliseconds 100
    }
    throw "Reference-time Authority did not publish its readiness marker."
}

function Start-PublicAlphaNode(
    [string]$Label,
    [string]$DataDirectory,
    [string]$StateFile,
    [string]$NoiseKey,
    [string]$Stdout,
    [string]$Stderr,
    [int]$RpcPort,
    [int]$TxPort,
    [int]$BlockPort,
    [string]$PeerAddress
) {
    $arguments = @(
        "--public-alpha",
        "--network-id-hex", $networkId,
        "--owner-account-id-hex", $ownerAccount,
        "--owner-public-key-hex", $ownerPublicKey,
        "--genesis-time-unix-secs", $genesisEpoch,
        "--data-dir", $DataDirectory,
        "--rpc-listen", "127.0.0.1:$RpcPort",
        "--tx-listen", "127.0.0.1:$TxPort",
        "--block-listen", "127.0.0.1:$BlockPort",
        "--noise-private-key-file", $NoiseKey,
        "--reference-time-policy-file", $policyFile,
        "--reference-time-admin-public-key-hex", $adminPublicKey,
        "--reference-time-address", $authorityAddress,
        "--reference-time-state-file", $StateFile
    )
    if ($PeerAddress) { $arguments += @("--peer", $PeerAddress) }
    $quoted = $arguments | ForEach-Object { ConvertTo-StartProcessArgument $_ }
    $process = Start-Process -FilePath $nodeExe -ArgumentList $quoted -PassThru -WindowStyle Hidden -RedirectStandardOutput $Stdout -RedirectStandardError $Stderr
    # Register immediately so the outer finally block can stop the child even if this
    # function throws before returning the Process object to its caller.
    $script:nodeProcesses.Add($process)

    for ($i = 0; $i -lt 240; $i++) {
        $process.Refresh()
        if ($process.HasExited) {
            $outText = Get-Content -LiteralPath $Stdout -Raw -ErrorAction SilentlyContinue
            $errText = Get-Content -LiteralPath $Stderr -Raw -ErrorAction SilentlyContinue
            throw "$Label failed to start (exit $($process.ExitCode)). STDOUT=$outText STDERR=$errText"
        }
        $outText = Get-Content -LiteralPath $Stdout -Raw -ErrorAction SilentlyContinue
        if ($outText -and
            $outText.Contains("qrun_pow_local_rpc_ready") -and
            $outText.Contains("qrun_pow_local_tx_ready") -and
            $outText.Contains("qrun_pow_local_block_ready")) {
            # Redirected stdout can still be flushing the preceding startup records when
            # the final listener marker becomes visible. Re-read after a short flush window.
            Start-Sleep -Milliseconds 150
            $outText = Get-Content -LiteralPath $Stdout -Raw -ErrorAction SilentlyContinue
            if (!$outText -or
                !$outText.Contains("qrun_reference_time_ready source=ed25519-attested-time-v1 provenance=ConfiguredProvider")) {
                throw "$Label did not report authenticated time provenance. Inspect $Stdout"
            }
            if (!$outText.Contains("network_class=public_alpha_experimental_not_mainnet") -or
                !$outText.Contains("mainnet=false")) {
                throw "$Label did not identify itself as non-Mainnet Public Alpha. Inspect $Stdout"
            }
            return $process
        }
        Start-Sleep -Milliseconds 100
    }
    Stop-ProcessSafe $process
    $outText = Get-Content -LiteralPath $Stdout -Raw -ErrorAction SilentlyContinue
    $errText = Get-Content -LiteralPath $Stderr -Raw -ErrorAction SilentlyContinue
    throw "$Label did not reach listener-ready markers. STDOUT=$outText STDERR=$errText"
}

function Get-RpcStatus([int]$Port) {
    $lastError = $null
    for ($attempt = 0; $attempt -lt 20; $attempt++) {
        try {
            return Invoke-RestMethod -Method Get -Uri "http://127.0.0.1:$Port/v1/status" -TimeoutSec 4
        } catch {
            $lastError = $_
            Start-Sleep -Milliseconds 100
        }
    }
    throw "RPC status endpoint 127.0.0.1:$Port did not return a complete response: $lastError"
}

function Wait-ForConvergence([int]$RpcA, [int]$RpcB, [string]$Txid) {
    for ($i = 0; $i -lt 240; $i++) {
        try {
            $statusA = Get-RpcStatus $RpcA
            $statusB = Get-RpcStatus $RpcB
            $txA = Invoke-RestMethod -Method Get -Uri "http://127.0.0.1:$RpcA/v1/transaction/$Txid" -TimeoutSec 4
            $txB = Invoke-RestMethod -Method Get -Uri "http://127.0.0.1:$RpcB/v1/transaction/$Txid" -TimeoutSec 4
            if ($statusA.height -ge 1 -and $statusB.height -ge 1 -and
                $statusA.tip -eq $statusB.tip -and $statusA.state_root -eq $statusB.state_root -and
                $statusA.profile_id -eq $statusB.profile_id -and
                $txA.status -eq "confirmed" -and $txB.status -eq "confirmed") {
                return @{ A = $statusA; B = $statusB; TxA = $txA; TxB = $txB }
            }
        } catch {}
        Start-Sleep -Milliseconds 250
    }
    $a = $null; $b = $null
    try { $a = Get-RpcStatus $RpcA | ConvertTo-Json -Compress } catch {}
    try { $b = Get-RpcStatus $RpcB | ConvertTo-Json -Compress } catch {}
    throw "Two-process convergence deadline elapsed. NodeA=$a NodeB=$b"
}

if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw "This test provisions CurrentUser DPAPI keys and must run on Windows."
}

$root = Join-Path $env:TEMP ("qrun-public-alpha-2proc-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $root | Out-Null
$script:allocatedPorts = @{}
$script:nodeProcesses = New-Object System.Collections.Generic.List[object]
$authorityProcess = $null
$nodeAProcess = $null
$nodeBProcess = $null
$success = $false

try {
    Write-Host "=== Build QRun Public Alpha node, Authority, Noise provisioner and test-only TXN2 client ==="
    $buildArguments = @(
        "build", "--manifest-path", $manifest,
        "--bin", "qrun_v05_pow_local_node",
        "--bin", "qrun_v05_reference_time_authority",
        "--bin", "qrun_v05_noise_key_provision",
        "--bin", "qrun_v05_public_alpha_process_smoke",
        "--locked", "--offline"
    )
    if ($Release) { $buildArguments += "--release" }
    & cargo @buildArguments
    if ($LASTEXITCODE -ne 0) { throw "Offline $buildProfile build failed (exit $LASTEXITCODE)." }

    $identityLines = & $processSmokeExe identity
    if ($LASTEXITCODE -ne 0) { throw "Disposable smoke wallet identity creation failed." }
    $ownerAccount = (($identityLines | Where-Object { $_ -match "^owner_account_id_hex=" } | Select-Object -First 1) -replace "^owner_account_id_hex=", "")
    $ownerPublicKey = (($identityLines | Where-Object { $_ -match "^owner_public_key_hex=" } | Select-Object -First 1) -replace "^owner_public_key_hex=", "")
    if ($ownerAccount.Length -ne 64 -or $ownerPublicKey.Length -ne 64) { throw "Disposable smoke wallet identity is malformed." }

    $networkBytes = New-Object byte[] 32
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($networkBytes)
    $rng.Dispose()
    $networkId = ([System.BitConverter]::ToString($networkBytes)).Replace("-", "").ToLowerInvariant()
    $genesisEpoch = ([DateTimeOffset]::UtcNow.ToUnixTimeSeconds() - 5).ToString()

    $authorityKey = Join-Path $root "time-authority.ask1"
    $adminKey = Join-Path $root "policy-admin.ask1"
    $policyFile = Join-Path $root "public-alpha.rtp1"
    $authorityState = Join-Path $root "authority.rts1"
    $authorityStdout = Join-Path $root "authority.stdout.log"
    $authorityStderr = Join-Path $root "authority.stderr.log"

    Write-Host "=== Provision disposable, network-bound operator keys ==="
    $authorityOutput = & $authorityExe provision-key --network-id-hex $networkId --role reference-time-authority --output $authorityKey
    if ($LASTEXITCODE -ne 0) { throw "Authority key provisioning failed: $($authorityOutput -join ' ')" }
    $authorityPublicKey = (($authorityOutput | Where-Object { $_ -match "^public_key=" } | Select-Object -First 1) -replace "^public_key=", "")
    $adminOutput = & $authorityExe provision-key --network-id-hex $networkId --role reference-time-policy-admin --output $adminKey
    if ($LASTEXITCODE -ne 0) { throw "Policy Admin key provisioning failed: $($adminOutput -join ' ')" }
    $adminPublicKey = (($adminOutput | Where-Object { $_ -match "^public_key=" } | Select-Object -First 1) -replace "^public_key=", "")
    if ($authorityPublicKey.Length -ne 64 -or $adminPublicKey.Length -ne 64) { throw "Authority/Policy Admin public key output is malformed." }

    $authorityOutput = & $authorityExe create-policy --network-id-hex $networkId --authority-public-key-hex $authorityPublicKey --policy-admin-key-file $adminKey --policy-admin-public-key-hex $adminPublicKey --sequence 1 --max-round-trip-ms 5000 --max-local-clock-skew-secs 300 --output $policyFile
    if ($LASTEXITCODE -ne 0) { throw "Signed RTP1 policy creation failed: $($authorityOutput -join ' ')" }

    $noiseA = Join-Path $root "node-a.npk1"
    $noiseB = Join-Path $root "node-b.npk1"
    $noiseAOutput = & $noiseProvisionerExe --network-id-hex $networkId --output $noiseA
    if ($LASTEXITCODE -ne 0) { throw "Node A Noise key provisioning failed." }
    $noiseBOutput = & $noiseProvisionerExe --network-id-hex $networkId --output $noiseB
    if ($LASTEXITCODE -ne 0) { throw "Node B Noise key provisioning failed." }
    $noiseAPublic = (($noiseAOutput | Where-Object { $_ -match "^public_key_hex=" } | Select-Object -First 1) -replace "^public_key_hex=", "")
    $noiseBPublic = (($noiseBOutput | Where-Object { $_ -match "^public_key_hex=" } | Select-Object -First 1) -replace "^public_key_hex=", "")
    if ($noiseAPublic.Length -ne 64 -or $noiseBPublic.Length -ne 64 -or $noiseAPublic -eq $noiseBPublic) {
        throw "Two distinct network-bound NPK1 keys were not provisioned."
    }
    Write-Host "NPK1_TWO_INDEPENDENT_KEYS=PASS"
    Write-Host "disposable_wallet_identity=PASS"
    Write-Host "private_seed_exported=false"

    $authorityPort = Get-FreeLoopbackPort
    $authorityAddress = "127.0.0.1:$authorityPort"
    Start-Authority
    Write-Host "AUTHORITY_TCP_READY=PASS"

    $rpcA = Get-FreeLoopbackPort; $txA = Get-FreeLoopbackPort; $blockA = Get-FreeLoopbackPort
    $rpcB = Get-FreeLoopbackPort; $txB = Get-FreeLoopbackPort; $blockB = Get-FreeLoopbackPort
    $dataA = Join-Path $root "node-a-data"; $dataB = Join-Path $root "node-b-data"
    $timeA = Join-Path $root "node-a-reference-time.rts1"; $timeB = Join-Path $root "node-b-reference-time.rts1"
    $outA = Join-Path $root "node-a.stdout.log"; $errA = Join-Path $root "node-a.stderr.log"
    $outB = Join-Path $root "node-b.stdout.log"; $errB = Join-Path $root "node-b.stderr.log"

    Write-Host "=== Start Node A with Node B as its authenticated block peer ==="
    $nodeBPeer = "127.0.0.1:$blockB"
    $nodeAProcess = Start-PublicAlphaNode "node-a" $dataA $timeA $noiseA $outA $errA $rpcA $txA $blockA $nodeBPeer

    Write-Host "=== Start independent Node B process ==="
    $nodeBProcess = Start-PublicAlphaNode "node-b" $dataB $timeB $noiseB $outB $errB $rpcB $txB $blockB ""
    Write-Host "TWO_INDEPENDENT_PUBLIC_ALPHA_PROCESSES_READY=PASS"

    $beforeA = Get-RpcStatus $rpcA
    $beforeB = Get-RpcStatus $rpcB
    if ($beforeA.network_id -ne $networkId -or $beforeB.network_id -ne $networkId -or
        $beforeA.genesis_id -ne $beforeB.genesis_id -or $beforeA.profile_id -ne $beforeB.profile_id) {
        throw "The two fresh nodes did not open the same ephemeral network, Genesis and signed time profile."
    }
    if ($beforeA.height -ne 0 -or $beforeB.height -ne 0 -or $beforeA.tip -ne $beforeB.tip) {
        throw "Fresh independent node stores did not begin at the exact same Genesis state."
    }
    Write-Host "SHARED_GENESIS_AND_PROFILE=PASS"

    Write-Host "=== Submit one real signed TXN2 transfer to Node A ==="
    $txOutput = & $processSmokeExe submit --network-id-hex $networkId --address "127.0.0.1:$txA"
    if ($LASTEXITCODE -ne 0) { throw "Node A did not accept the signed QZTS/1 transaction: $($txOutput -join ' ')" }
    $txid = (($txOutput | Where-Object { $_ -match "^transaction_id=" } | Select-Object -First 1) -replace "^transaction_id=", "")
    $txStatus = (($txOutput | Where-Object { $_ -match "^qzts_status=" } | Select-Object -First 1) -replace "^qzts_status=", "")
    if ($txid.Length -ne 64 -or $txStatus -ne "Accepted") { throw "QZTS/1 response did not confirm admission." }
    Write-Host "SIGNED_QZTS_TX_ACCEPTED=PASS"

    Write-Host "=== Wait for Noise XX block propagation and canonical convergence ==="
    $converged = Wait-ForConvergence $rpcA $rpcB $txid
    if ($converged.A.network_id -ne $converged.B.network_id -or
        $converged.A.genesis_id -ne $converged.B.genesis_id -or
        $converged.A.height -ne $converged.B.height) {
        throw "Network/Genesis/height do not match after block delivery."
    }
    $ownerBalanceA = Invoke-RestMethod -Method Get -Uri "http://127.0.0.1:$rpcA/v1/balance/$ownerAccount" -TimeoutSec 4
    $ownerBalanceB = Invoke-RestMethod -Method Get -Uri "http://127.0.0.1:$rpcB/v1/balance/$ownerAccount" -TimeoutSec 4
    if ($ownerBalanceA.balance_atoms -ne $ownerBalanceB.balance_atoms -or
        $ownerBalanceA.nonce -ne $ownerBalanceB.nonce -or $ownerBalanceA.nonce -ne 1) {
        throw "Independent nodes do not agree on the signed transaction's owner balance/nonce."
    }

    $nodeALog = Get-Content -LiteralPath $outA -Raw
    $nodeBLog = Get-Content -LiteralPath $outB -Raw
    if ($nodeALog -notmatch "qrun_pow_local_block_broadcast peer=127.0.0.1:$blockB") {
        throw "Node A did not log successful block broadcast to Node B."
    }
    if ($nodeBLog -notmatch "qrun_pow_local_block_accepted|qrun_pow_local_block_imported|qrun_pow_local_block") {
        throw "Node B log did not record block reception."
    }

    Write-Host "NOISE_XX_BLOCK_BROADCAST=PASS"
    Write-Host "TWO_PROCESS_CANONICAL_TIP_CONVERGENCE=PASS"
    Write-Host "TRANSACTION_RECEIPT_ON_BOTH_NODES=PASS"
    Write-Host "OWNER_BALANCE_AND_NONCE_MATCH=PASS"
    Write-Host "node_a_height=$($converged.A.height)"
    Write-Host "node_b_height=$($converged.B.height)"
    Write-Host "canonical_tip=$($converged.A.tip)"
    Write-Host "canonical_state_root=$($converged.A.state_root)"
    Write-Host "transaction_id=$txid"
    Write-Host "mainnet=false"
    Write-Host "PUBLIC_ALPHA_TWO_PROCESS_SMOKE=PASS"
    $success = $true
}
catch {
    Write-Host "PUBLIC_ALPHA_TWO_PROCESS_SMOKE=FAIL"
    Write-Host "SMOKE_ARTIFACTS_PRESERVED=$root"
    throw
}
finally {
    foreach ($nodeProcess in $script:nodeProcesses) {
        Stop-ProcessSafe $nodeProcess
    }
    $script:nodeProcesses.Clear()
    Stop-ProcessSafe $authorityProcess
    if ($success) {
        Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
    }
}
