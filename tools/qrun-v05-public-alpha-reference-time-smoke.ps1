param()

$ErrorActionPreference = "Stop"
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$manifest = Join-Path $repoRoot "src/native/pow_bench/Cargo.toml"
$target = Join-Path $repoRoot "src/native/pow_bench/target/debug"
$authorityExe = Join-Path $target "qrun_v05_reference_time_authority.exe"
$nodeExe = Join-Path $target "qrun_v05_pow_local_node.exe"
$noiseProvisionerExe = Join-Path $target "qrun_v05_noise_key_provision.exe"

function Get-FreeLoopbackPort {
    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    $listener.Start()
    $port = ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port
    $listener.Stop()
    return $port
}

function ConvertTo-StartProcessArgument([string]$Value) {
    return '"' + $Value.Replace('"', '\"') + '"'
}

function Start-Authority {
    $script:authorityProcess = Start-Process -FilePath $authorityExe -ArgumentList @(
        "serve", "--network-id-hex", $networkId, "--authority-key-file", $authorityKey,
        "--state-file", $authorityState, "--listen", $authorityAddress
    ) -PassThru -WindowStyle Hidden -RedirectStandardOutput $authorityStdout -RedirectStandardError $authorityStderr
    for ($i = 0; $i -lt 80; $i++) {
        if ($script:authorityProcess.HasExited) {
            $details = Get-Content -LiteralPath $authorityStderr -Raw -ErrorAction SilentlyContinue
            throw "Reference-time Authority exited during startup: $details"
        }
        $client = [System.Net.Sockets.TcpClient]::new()
        try {
            $client.Connect("127.0.0.1", $authorityPort)
            return
        } catch {
            Start-Sleep -Milliseconds 100
        } finally {
            $client.Dispose()
        }
    }
    throw "Reference-time Authority did not start listening."
}

function Stop-ProcessSafe($Process) {
    if ($Process -and !$Process.HasExited) {
        Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue
        Wait-Process -Id $Process.Id -Timeout 10 -ErrorAction SilentlyContinue
    }
}

function Start-PublicAlphaNode([string]$Label, [string]$DataDirectory, [string]$StateFile, [string]$Stdout, [string]$Stderr, [int]$RpcPort, [int]$TxPort, [int]$BlockPort) {
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
        "--noise-private-key-file", $noiseKey,
        "--reference-time-policy-file", $policyFile,
        "--reference-time-admin-public-key-hex", $adminPublicKey,
        "--reference-time-address", $authorityAddress,
        "--reference-time-state-file", $StateFile
    )
    $quoted = $arguments | ForEach-Object { ConvertTo-StartProcessArgument $_ }
    $process = Start-Process -FilePath $nodeExe -ArgumentList $quoted -PassThru -WindowStyle Hidden -RedirectStandardOutput $Stdout -RedirectStandardError $Stderr
    for ($i = 0; $i -lt 160; $i++) {
        if ($process.HasExited) {
            $outText = Get-Content -LiteralPath $Stdout -Raw -ErrorAction SilentlyContinue
            $errText = Get-Content -LiteralPath $Stderr -Raw -ErrorAction SilentlyContinue
            throw "$Label failed to start (exit $($process.ExitCode)). STDOUT=$outText STDERR=$errText"
        }
        $outText = Get-Content -LiteralPath $Stdout -Raw -ErrorAction SilentlyContinue
        if ($outText -match "qrun_pow_local_block_ready") {
            return $process
        }
        Start-Sleep -Milliseconds 100
    }
    Stop-ProcessSafe $process
    $outText = Get-Content -LiteralPath $Stdout -Raw -ErrorAction SilentlyContinue
    $errText = Get-Content -LiteralPath $Stderr -Raw -ErrorAction SilentlyContinue
    throw "$Label did not reach all listener-ready markers. STDOUT=$outText STDERR=$errText"
}

if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw "This smoke test provisions CurrentUser DPAPI keys and must run on Windows."
}

$root = Join-Path $env:TEMP ("qrun-public-alpha-smoke-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $root | Out-Null
$authorityProcess = $null
$nodeProcess = $null

try {
    Write-Host "=== Build QRun public node, Authority and Noise key provisioner ==="
    & cargo build --manifest-path $manifest --bin qrun_v05_pow_local_node --bin qrun_v05_reference_time_authority --bin qrun_v05_noise_key_provision --locked --offline
    if ($LASTEXITCODE -ne 0) { throw "Offline QRun binaries build failed (exit $LASTEXITCODE)." }

    # Current wallet-bound candidate identity is used only in this disposable loopback smoke.
    # Genesis epoch and time policy are ephemeral; no candidate pins or release identity are changed.
    $manifestPath = Join-Path $repoRoot "profiles/qrun_v05_wallet_bound_mainnet_identity_candidate.json"
    $identity = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    $networkId = $identity.network_id_hex
    $ownerAccount = $identity.owner_account_id_hex
    $ownerPublicKey = $identity.owner_public_key_hex
    $genesisEpoch = ([DateTimeOffset]::UtcNow.ToUnixTimeSeconds() - 2).ToString()

    $authorityKey = Join-Path $root "time-authority.ask1"
    $adminKey = Join-Path $root "policy-admin.ask1"
    $policyFile = Join-Path $root "public-alpha.rtp1"
    $authorityState = Join-Path $root "authority.rts1"
    $noiseKey = Join-Path $root "node-noise.npk1"
    $authorityStdout = Join-Path $root "authority.stdout.log"
    $authorityStderr = Join-Path $root "authority.stderr.log"

    Write-Host "=== Provision independent time Authority and Policy Admin keys ==="
    $authorityOutput = & $authorityExe provision-key --network-id-hex $networkId --role reference-time-authority --output $authorityKey
    if ($LASTEXITCODE -ne 0) { throw "Authority key provisioning failed: $($authorityOutput -join ' ')" }
    $authorityPublicKey = ($authorityOutput | Where-Object { $_ -match "^public_key=" } | Select-Object -First 1) -replace "^public_key=", ""
    if (!$authorityPublicKey -or $authorityPublicKey.Length -ne 64) { throw "Authority public key missing." }

    $adminOutput = & $authorityExe provision-key --network-id-hex $networkId --role reference-time-policy-admin --output $adminKey
    if ($LASTEXITCODE -ne 0) { throw "Policy Admin key provisioning failed: $($adminOutput -join ' ')" }
    $adminPublicKey = ($adminOutput | Where-Object { $_ -match "^public_key=" } | Select-Object -First 1) -replace "^public_key=", ""
    if (!$adminPublicKey -or $adminPublicKey.Length -ne 64) { throw "Policy Admin public key missing." }

    Write-Host "=== Create signed RTP1 policy and network-bound Noise key ==="
    $policyOutput = & $authorityExe create-policy --network-id-hex $networkId --authority-public-key-hex $authorityPublicKey --policy-admin-key-file $adminKey --policy-admin-public-key-hex $adminPublicKey --sequence 1 --max-round-trip-ms 5000 --max-local-clock-skew-secs 300 --output $policyFile
    if ($LASTEXITCODE -ne 0) { throw "Signed RTP1 policy creation failed: $($policyOutput -join ' ')" }
    $noiseOutput = & $noiseProvisionerExe --network-id-hex $networkId --output $noiseKey
    if ($LASTEXITCODE -ne 0) { throw "Noise key provisioning failed: $($noiseOutput -join ' ')" }
    if (!(Test-Path -LiteralPath $noiseKey -PathType Leaf)) { throw "NPK1 file was not created." }
    if (($noiseOutput -join [Environment]::NewLine) -match "private_key_hex=") { throw "Noise provisioner leaked private key material." }
    $noiseHashBefore = (Get-FileHash -LiteralPath $noiseKey -Algorithm SHA256).Hash
    $duplicateStdout = Join-Path $root "noise-duplicate.stdout.log"
    $duplicateStderr = Join-Path $root "noise-duplicate.stderr.log"
    $duplicateArgs = @("--network-id-hex", $networkId, "--output", $noiseKey)
    $duplicateQuoted = $duplicateArgs | ForEach-Object { ConvertTo-StartProcessArgument $_ }
    $duplicateProcess = Start-Process -FilePath $noiseProvisionerExe -ArgumentList $duplicateQuoted -PassThru -Wait -NoNewWindow -RedirectStandardOutput $duplicateStdout -RedirectStandardError $duplicateStderr
    $duplicateText = Get-Content -LiteralPath $duplicateStderr -Raw -ErrorAction SilentlyContinue
    if ($duplicateProcess.ExitCode -eq 0 -or $duplicateText -notmatch "refusing to overwrite") {
        throw "Noise key provisioner did not reject an existing output file: $duplicateText"
    }
    $noiseHashAfter = (Get-FileHash -LiteralPath $noiseKey -Algorithm SHA256).Hash
    if ($noiseHashBefore -ne $noiseHashAfter) { throw "Existing Noise key changed after rejected overwrite." }
    Write-Host "NPK1_DPAPI_PROVISION=PASS"
    Write-Host "NPK1_NO_OVERWRITE_GUARD=PASS"

    $authorityPort = Get-FreeLoopbackPort
    $authorityAddress = "127.0.0.1:$authorityPort"
    Start-Authority
    Write-Host "AUTHORITY_TCP_READY=PASS"

    Write-Host "=== Start actual QRun v0.5 Public Alpha node with authenticated time ==="
    $nodeData = Join-Path $root "node-data"
    $nodeState = Join-Path $root "node-reference-time.rts1"
    $nodeStdout = Join-Path $root "node.stdout.log"
    $nodeStderr = Join-Path $root "node.stderr.log"
    $nodeProcess = Start-PublicAlphaNode "public-alpha-node" $nodeData $nodeState $nodeStdout $nodeStderr (Get-FreeLoopbackPort) (Get-FreeLoopbackPort) (Get-FreeLoopbackPort)

    $nodeLog = Get-Content -LiteralPath $nodeStdout -Raw
    if ($nodeLog -notmatch "qrun_reference_time_ready source=ed25519-attested-time-v1 provenance=ConfiguredProvider") {
        throw "Node did not report authenticated reference-time provenance."
    }
    if ($nodeLog -notmatch "QRUN_V05_PUBLIC_ALPHA_CANDIDATE_READY" -or $nodeLog -notmatch "network_class=public_alpha_experimental_not_mainnet") {
        throw "Node did not report the expected experimental Public Alpha class."
    }
    if ($nodeLog -notmatch "qrun_pow_local_rpc_ready" -or $nodeLog -notmatch "qrun_pow_local_tx_ready" -or $nodeLog -notmatch "qrun_pow_local_block_ready") {
        throw "Node did not bind all three expected local listeners."
    }
    if ($nodeLog -notmatch "mainnet=false") { throw "Node reported an unexpected Mainnet status." }
    Write-Host "PUBLIC_ALPHA_AUTHENTICATED_STARTUP=PASS"
    Write-Host "PUBLIC_ALPHA_RPC_TX_P2P_LISTENERS=PASS"
    Write-Host "mainnet=false"

    Write-Host "=== Stop Authority; prove public node fails closed before node data creation ==="
    Stop-ProcessSafe $nodeProcess
    $nodeProcess = $null
    Stop-ProcessSafe $authorityProcess
    $authorityProcess = $null

    $outageData = Join-Path $root "node-outage-data"
    $outageState = Join-Path $root "node-outage-reference-time.rts1"
    $outageStdout = Join-Path $root "node-outage.stdout.log"
    $outageStderr = Join-Path $root "node-outage.stderr.log"
    $outageArgs = @(
        "--public-alpha", "--network-id-hex", $networkId,
        "--owner-account-id-hex", $ownerAccount,
        "--owner-public-key-hex", $ownerPublicKey,
        "--genesis-time-unix-secs", $genesisEpoch,
        "--data-dir", $outageData,
        "--rpc-listen", "127.0.0.1:$(Get-FreeLoopbackPort)",
        "--tx-listen", "127.0.0.1:$(Get-FreeLoopbackPort)",
        "--block-listen", "127.0.0.1:$(Get-FreeLoopbackPort)",
        "--noise-private-key-file", $noiseKey,
        "--reference-time-policy-file", $policyFile,
        "--reference-time-admin-public-key-hex", $adminPublicKey,
        "--reference-time-address", $authorityAddress,
        "--reference-time-state-file", $outageState
    )
    $outageQuoted = $outageArgs | ForEach-Object { ConvertTo-StartProcessArgument $_ }
    $outageProcess = Start-Process -FilePath $nodeExe -ArgumentList $outageQuoted -PassThru -Wait -NoNewWindow -RedirectStandardOutput $outageStdout -RedirectStandardError $outageStderr
    $outageError = Get-Content -LiteralPath $outageStderr -Raw -ErrorAction SilentlyContinue
    if ($outageProcess.ExitCode -eq 0 -or $outageError -notmatch "authenticated reference-time startup sample failed") {
        throw "Public node did not fail closed on Authority outage: $outageError"
    }
    if (Test-Path -LiteralPath $outageData) {
        throw "Node created its data directory despite Authority outage."
    }
    Write-Host "AUTHORITY_OUTAGE_FAIL_CLOSED=PASS"
    Write-Host "NODE_DATA_DIR_NOT_CREATED_ON_TIME_FAILURE=PASS"
    Write-Host "PUBLIC_ALPHA_REFERENCE_TIME_SMOKE=PASS"
    Write-Host "network_id_hex=$networkId"
    Write-Host "ephemeral_genesis_epoch_unix=$genesisEpoch"
}
finally {
    Stop-ProcessSafe $nodeProcess
    Stop-ProcessSafe $authorityProcess
    Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
}
