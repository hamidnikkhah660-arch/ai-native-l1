param(
    [string]$ExecutablePath = ""
)

$ErrorActionPreference = "Stop"

if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw "This smoke test provisions Windows CurrentUser DPAPI keys and must run on Windows."
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
if ([string]::IsNullOrWhiteSpace($ExecutablePath)) {
    $manifest = Join-Path $repoRoot "src/native/pow_bench/Cargo.toml"
    $ExecutablePath = Join-Path $repoRoot "src/native/pow_bench/target/debug/qrun_v05_reference_time_authority.exe"
    & cargo build --manifest-path $manifest --bin qrun_v05_reference_time_authority --locked --offline
    if ($LASTEXITCODE -ne 0) { throw "Could not build qrun_v05_reference_time_authority (exit $LASTEXITCODE)." }
}
if (!(Test-Path -LiteralPath $ExecutablePath -PathType Leaf)) {
    throw "Authority executable not found: $ExecutablePath"
}

$root = Join-Path $env:TEMP ("qrun-rta-smoke-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $root | Out-Null

$network = "a1" * 32
$authorityKey = Join-Path $root "authority.ask1"
$adminKey = Join-Path $root "policy-admin.ask1"
$policy = Join-Path $root "network.rtp1"
$authorityState = Join-Path $root "authority.rts1"
$probeState = Join-Path $root "probe-node1.rts1"
$probeState2 = Join-Path $root "probe-node2.rts1"
$stdout = Join-Path $root "authority.stdout.log"
$stderr = Join-Path $root "authority.stderr.log"
$server = $null

function Start-TimeAuthority {
    $script:server = Start-Process -FilePath $ExecutablePath -ArgumentList @(
        "serve",
        "--network-id-hex", $network,
        "--authority-key-file", $authorityKey,
        "--state-file", $authorityState,
        "--listen", $listen
    ) -PassThru -WindowStyle Hidden -RedirectStandardOutput $stdout -RedirectStandardError $stderr

    # Wait for the service's post-bind readiness marker rather than opening a dummy TCP
    # connection. A connect-and-close probe would occupy a handler for its full request timeout.
    $ready = $false
    for ($i = 0; $i -lt 120; $i++) {
        if ($script:server.HasExited) {
            $outDetails = Get-Content -LiteralPath $stdout -Raw -ErrorAction SilentlyContinue
            $errDetails = Get-Content -LiteralPath $stderr -Raw -ErrorAction SilentlyContinue
            throw "Reference-time authority exited during startup: STDOUT=$outDetails STDERR=$errDetails"
        }
        $readyText = Get-Content -LiteralPath $stdout -Raw -ErrorAction SilentlyContinue
        if ($readyText -match "qrun_reference_time_authority_ready") {
            $ready = $true
            break
        }
        Start-Sleep -Milliseconds 100
    }
    if (!$ready) {
        $outDetails = Get-Content -LiteralPath $stdout -Raw -ErrorAction SilentlyContinue
        $errDetails = Get-Content -LiteralPath $stderr -Raw -ErrorAction SilentlyContinue
        throw "Reference-time authority did not report readiness on $listen. STDOUT=$outDetails STDERR=$errDetails"
    }
}

function Invoke-TimeProbe([string]$label, [string]$clientState = $probeState) {
    $probeArgs = @("probe", "--network-id-hex", $network, "--policy-file", $policy, "--policy-admin-public-key-hex", $adminPublicKey, "--address", $listen, "--state-file", $clientState)
    $probeOutput = & $ExecutablePath @probeArgs
    if ($LASTEXITCODE -ne 0) {
        $authorityOut = Get-Content -LiteralPath $stdout -Raw -ErrorAction SilentlyContinue
        $authorityErr = Get-Content -LiteralPath $stderr -Raw -ErrorAction SilentlyContinue
        Write-Host "authority_stdout=$authorityOut"
        Write-Host "authority_stderr=$authorityErr"
        throw "$label failed: $($probeOutput -join ' ')"
    }
    foreach ($line in $probeOutput) { Write-Host "$label $line" }
    $sequenceLine = $probeOutput | Where-Object { $_ -match "^accepted_authority_sequence=" } | Select-Object -First 1
    if (!$sequenceLine) { throw "$label returned no accepted authority sequence." }
    return [int](($sequenceLine -replace "^accepted_authority_sequence=", ""))
}

try {
    Write-Host "=== Provision DPAPI-protected Authority key ==="
    $authorityArgs = @("provision-key", "--network-id-hex", $network, "--role", "reference-time-authority", "--output", $authorityKey)
    $authorityOutput = & $ExecutablePath @authorityArgs
    if ($LASTEXITCODE -ne 0) { throw "Authority-key provisioning failed: $($authorityOutput -join ' ')" }
    $authorityOutput | ForEach-Object { Write-Host $_ }
    $authorityPublicKey = ($authorityOutput | Where-Object { $_ -match "^public_key=" } | Select-Object -First 1) -replace "^public_key=", ""
    if (!$authorityPublicKey -or $authorityPublicKey.Length -ne 64) { throw "Authority public key was not returned." }

    Write-Host "=== Provision separate DPAPI-protected Policy Admin key ==="
    $adminArgs = @("provision-key", "--network-id-hex", $network, "--role", "reference-time-policy-admin", "--output", $adminKey)
    $adminOutput = & $ExecutablePath @adminArgs
    if ($LASTEXITCODE -ne 0) { throw "Policy-admin provisioning failed: $($adminOutput -join ' ')" }
    $adminOutput | ForEach-Object { Write-Host $_ }
    $adminPublicKey = ($adminOutput | Where-Object { $_ -match "^public_key=" } | Select-Object -First 1) -replace "^public_key=", ""
    if (!$adminPublicKey -or $adminPublicKey.Length -ne 64) { throw "Policy-admin public key was not returned." }

    Write-Host "=== Create signed RTP1 policy ==="
    $policyArgs = @("create-policy", "--network-id-hex", $network, "--authority-public-key-hex", $authorityPublicKey, "--policy-admin-key-file", $adminKey, "--policy-admin-public-key-hex", $adminPublicKey, "--sequence", "1", "--max-round-trip-ms", "5000", "--max-local-clock-skew-secs", "300", "--output", $policy)
    $policyOutput = & $ExecutablePath @policyArgs
    if ($LASTEXITCODE -ne 0) { throw "RTP1 policy creation failed: $($policyOutput -join ' ')" }
    $policyOutput | Where-Object { $_ -match "^(sequence|authority_public_key|policy_digest)=" } | ForEach-Object { Write-Host $_ }

    $tcp = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    $tcp.Start()
    $port = ([System.Net.IPEndPoint]$tcp.LocalEndpoint).Port
    $tcp.Stop()
    $listen = "127.0.0.1:$port"

    Write-Host "=== Non-loopback listener must require explicit opt-in ==="
    $deniedArgs = @("serve", "--network-id-hex", $network, "--authority-key-file", $authorityKey, "--state-file", $authorityState, "--listen", "0.0.0.0:$port")
    $deniedOut = Join-Path $root "nonloopback.stdout.log"
    $deniedErr = Join-Path $root "nonloopback.stderr.log"
    $deniedProcess = Start-Process -FilePath $ExecutablePath -ArgumentList $deniedArgs -PassThru -Wait -NoNewWindow -RedirectStandardOutput $deniedOut -RedirectStandardError $deniedErr
    $deniedText = Get-Content -LiteralPath $deniedErr -Raw -ErrorAction SilentlyContinue
    if ($deniedProcess.ExitCode -eq 0 -or $deniedText -notmatch "non-loopback bind requires explicit") {
        throw "Non-loopback bind did not fail closed as expected: $deniedText"
    }
    Write-Host "non_loopback_bind_guard=PASS"

    Write-Host "=== Start independent Authority process ==="
    Start-TimeAuthority
    $sequence1 = Invoke-TimeProbe "node1-probe1" $probeState
    $sequence2 = Invoke-TimeProbe "node2-independent-probe" $probeState2
    if ($sequence1 -ne 1 -or $sequence2 -ne 2) {
        throw "Unexpected initial sequence progression: $sequence1,$sequence2"
    }

    Write-Host "=== Restart Authority and prove durable sequence ==="
    Stop-Process -Id $server.Id -Force
    Wait-Process -Id $server.Id -Timeout 10
    Start-TimeAuthority
    $sequence3 = Invoke-TimeProbe "probe3-after-restart"
    if ($sequence3 -ne 65) {
        throw "Authority sequence lease did not advance safely after restart: got $sequence3, expected 65."
    }

    Write-Host "=== Policy-admin role separation negative check ==="
    $badPolicy = Join-Path $root "should-not-exist.rtp1"
    $wrongRoleArgs = @("create-policy", "--network-id-hex", $network, "--authority-public-key-hex", $authorityPublicKey, "--policy-admin-key-file", $authorityKey, "--policy-admin-public-key-hex", $authorityPublicKey, "--sequence", "2", "--max-round-trip-ms", "5000", "--max-local-clock-skew-secs", "300", "--output", $badPolicy)
    $wrongRoleOut = Join-Path $root "wrong-role.stdout.log"
    $wrongRoleErr = Join-Path $root "wrong-role.stderr.log"
    $wrongRoleProcess = Start-Process -FilePath $ExecutablePath -ArgumentList $wrongRoleArgs -PassThru -Wait -NoNewWindow -RedirectStandardOutput $wrongRoleOut -RedirectStandardError $wrongRoleErr
    $wrongRoleText = Get-Content -LiteralPath $wrongRoleErr -Raw -ErrorAction SilentlyContinue
    if ($wrongRoleProcess.ExitCode -eq 0 -or $wrongRoleText -notmatch "wrong role" -or (Test-Path -LiteralPath $badPolicy)) {
        throw "Authority key was incorrectly accepted as Policy Admin: $wrongRoleText"
    }
    Write-Host "policy_admin_role_separation=PASS"

    Write-Host "AUTHORITY_MULTI_PROCESS_SMOKE=PASS"
    Write-Host "sequence_progression=$sequence1,$sequence2,$sequence3"
    Write-Host "restart_reserved_range=65-128"
    Write-Host "network_id=$network"
}
finally {
    if ($server -and !$server.HasExited) {
        Stop-Process -Id $server.Id -Force -ErrorAction SilentlyContinue
        Wait-Process -Id $server.Id -Timeout 5 -ErrorAction SilentlyContinue
    }
    Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
}
