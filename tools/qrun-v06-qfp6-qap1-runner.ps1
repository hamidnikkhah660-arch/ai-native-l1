[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$manifest = Join-Path $repoRoot 'src/native/pow_bench/Cargo.toml'
$netbirdExe = 'C:\Program Files\NetBird\netbird.exe'
$tempRoot = Join-Path $env:TEMP ('qfp6-qap1-cross-host-' + [guid]::NewGuid().ToString('N'))
$privateEnvironmentNames = @(
    'QRUN_QFP6_QAP1_LISTENER_PRIVATE',
    'QRUN_QFP6_QAP1_PEER_PUBLIC',
    'QRUN_QFP6_QAP1_PROVIDER_CLIENT_PRIVATE',
    'QRUN_QFP6_QAP1_PROVIDER_SERVER_PUBLIC',
    'QRUN_QFP6_QAP1_ANCHOR_CLIENT_PRIVATE',
    'QRUN_QFP6_QAP1_ANCHOR_SERVER_PUBLIC',
    'QRUN_QFP6_QAP1_PROVIDER_RECEIPT_PUBLIC',
    'QRUN_QFP6_QAP1_ANCHOR_RECEIPT_PUBLIC'
)

function Assert-Hex32([string]$Name, [string]$Value) {
    if ($Value -notmatch '^[0-9a-fA-F]{64}$' -or $Value -match '^0{64}$') {
        throw "$Name must be a nonzero 32-byte hexadecimal value."
    }
}

function Assert-OverlayIPv4([string]$Name, [string]$Value) {
    $parsed = [System.Net.IPAddress]::Parse($Value)
    if ($parsed.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {
        throw "$Name must be IPv4."
    }
    $octets = $parsed.GetAddressBytes()
    if ($octets[0] -ne 100 -or $octets[1] -lt 64 -or $octets[1] -gt 127) {
        throw "$Name must be inside the NetBird 100.64.0.0/10 overlay range."
    }
    return $parsed
}

function ConvertTo-IPv4Endpoint([string]$Name, [string]$Value) {
    if ($Value -notmatch '^(?<ip>(?:[0-9]{1,3}\.){3}[0-9]{1,3}):(?<port>[0-9]{1,5})$') {
        throw "$Name must use IPv4:port notation."
    }
    $address = [System.Net.IPAddress]::Parse($Matches.ip)
    if ($address.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {
        throw "$Name must use IPv4."
    }
    $port = [int]$Matches.port
    if ($port -lt 1 -or $port -gt 65535) { throw "$Name port is outside 1..65535." }
    return [System.Net.IPEndPoint]::new($address, $port)
}

function Get-ConnectedOverlayAddress {
    $status = (& $netbirdExe status 2>&1 | Out-String)
    if ($LASTEXITCODE -ne 0 -or
        $status -notmatch 'Management:\s+Connected' -or
        $status -notmatch 'Signal:\s+Connected') {
        throw 'NetBird Management and Signal must both be Connected before QFP6 starts.'
    }
    $match = [regex]::Match($status, 'NetBird IP:\s+([0-9]{1,3}(?:\.[0-9]{1,3}){3})')
    if (-not $match.Success) { throw 'Could not determine the Runner NetBird IPv4 address.' }
    return $match.Groups[1].Value
}

function Invoke-Qfp6Worker([string]$Role, [string]$ExpectedAnchor, [string]$ExpectedHeight, [string]$ExpectedGeneration, [string]$ExpectedStateRoot) {
    $env:QRUN_QFP6_QAP1_PROCESS_ROLE = $Role
    if ($Role -eq 'server') { $env:QRUN_QFP6_QAP1_INITIALIZE_FLOOR = '1' }
    else { Remove-Item Env:QRUN_QFP6_QAP1_INITIALIZE_FLOOR -ErrorAction SilentlyContinue }
    $env:QRUN_QFP6_QAP1_LISTENER_TIMEOUT_SECS = '600'
    $env:QRUN_QFP6_QAP1_TRUSTED_MANIFEST_ANCHOR = $ExpectedAnchor
    if ($Role -eq 'restart') {
        $env:QRUN_QFP6_QAP1_EXPECTED_HEIGHT = $ExpectedHeight
        $env:QRUN_QFP6_QAP1_EXPECTED_GENERATION = $ExpectedGeneration
        $env:QRUN_QFP6_QAP1_EXPECTED_STATE_ROOT = $ExpectedStateRoot
    }
    $workerLog = Join-Path $env:TEMP ('qfp6-qap1-worker-' + $Role + '-' + [guid]::NewGuid().ToString('N') + '.log')
    $previousBacktrace = $env:RUST_BACKTRACE
    $env:RUST_BACKTRACE = '1'
    try {
        Write-Host ('QFP6_WORKER_ROLE_START=' + $Role)
        Write-Host ('QFP6_WORKER_LOG_PATH=' + $workerLog)
        & cargo test --locked --manifest-path $manifest --lib qrun_v06_node_runtime_candidate::tests::qfp6_qap1_process_worker -- --exact --nocapture 2>&1 | ForEach-Object {
            $line = [string]$_
            [System.IO.File]::AppendAllText($workerLog, $line + [Environment]::NewLine)
            Write-Host ('QFP6_WORKER_LOG: ' + $line)
        }
        $exitCode = $LASTEXITCODE
        $text = if (Test-Path -LiteralPath $workerLog) { [System.IO.File]::ReadAllText($workerLog) } else { '' }
        Write-Host ('QFP6_WORKER_ROLE_EXIT=' + $Role + ';CODE=' + $exitCode)
        if ($exitCode -ne 0) {
            if ([string]::IsNullOrWhiteSpace($text)) { Write-Host 'QFP6_WORKER_LOG_EMPTY=True' }
            throw "QFP6 QAP1 worker role '$Role' exited with code $exitCode."
        }
        return $text
    }
    finally {
        if ($null -eq $previousBacktrace) {
            Remove-Item Env:RUST_BACKTRACE -ErrorAction SilentlyContinue
        } else {
            $env:RUST_BACKTRACE = $previousBacktrace
        }
    }
}

try {
    if (-not (Test-Path -LiteralPath $netbirdExe -PathType Leaf)) {
        throw 'NetBird CLI is not installed on the ephemeral Runner.'
    }
    if (-not (Test-Path -LiteralPath $manifest -PathType Leaf)) {
        throw 'QRun pow_bench Cargo manifest is missing.'
    }
    if ([string]::IsNullOrWhiteSpace($env:QRUN_QFP6_QAP1_RUNNER_CONFIG_JSON)) {
        throw 'GitHub Actions secret QRUN_QFP6_QAP1_RUNNER_CONFIG_JSON is missing.'
    }

    # Parse once without ever echoing the secret-bearing JSON.
    $cfg = $env:QRUN_QFP6_QAP1_RUNNER_CONFIG_JSON | ConvertFrom-Json
    $requiredNames = @(
        'node_a_provider_address',
        'node_a_anchor_address',
        'node_a_callback_address',
        'callback_nonce_hex',
        'node_b_listener_port',
        'node_b_listener_private_hex',
        'node_b_listener_public_hex',
        'node_a_peer_public_hex',
        'provider_client_private_hex',
        'provider_server_public_hex',
        'anchor_client_private_hex',
        'anchor_server_public_hex',
        'provider_receipt_public_hex',
        'anchor_receipt_public_hex'
    )
    foreach ($name in $requiredNames) {
        $property = $cfg.PSObject.Properties[$name]
        if (-not $property -or [string]::IsNullOrWhiteSpace([string]$property.Value)) {
            throw "Runner configuration is missing required field: $name"
        }
    }

    $providerEndpoint = ConvertTo-IPv4Endpoint 'Node A Provider endpoint' ([string]$cfg.node_a_provider_address)
    $anchorEndpoint = ConvertTo-IPv4Endpoint 'Node A Q6EA endpoint' ([string]$cfg.node_a_anchor_address)
    $callbackEndpoint = ConvertTo-IPv4Endpoint 'Node A callback endpoint' ([string]$cfg.node_a_callback_address)
    [void](Assert-OverlayIPv4 'Node A Provider endpoint' $providerEndpoint.Address.ToString())
    [void](Assert-OverlayIPv4 'Node A Q6EA endpoint' $anchorEndpoint.Address.ToString())
    [void](Assert-OverlayIPv4 'Node A callback endpoint' $callbackEndpoint.Address.ToString())
    if ($providerEndpoint.Port -lt 1024 -or $anchorEndpoint.Port -lt 1024 -or $callbackEndpoint.Port -lt 1024 -or @($providerEndpoint.Port,$anchorEndpoint.Port,$callbackEndpoint.Port | Select-Object -Unique).Count -ne 3) {
        throw 'Provider, Q6EA and callback must use distinct non-privileged TCP ports.'
    }
    $listenerPort = [int]$cfg.node_b_listener_port
    if ($listenerPort -lt 1024 -or $listenerPort -gt 65535) {
        throw 'Node B QFP6 listener port is outside the allowed range.'
    }

    Assert-Hex32 'QFP6 listener private key' ([string]$cfg.node_b_listener_private_hex)
    Assert-Hex32 'QFP6 listener public key' ([string]$cfg.node_b_listener_public_hex)
    Assert-Hex32 'Node A callback nonce' ([string]$cfg.callback_nonce_hex)
    Assert-Hex32 'Node A peer public key' ([string]$cfg.node_a_peer_public_hex)
    Assert-Hex32 'Provider client private key' ([string]$cfg.provider_client_private_hex)
    Assert-Hex32 'Provider server public key' ([string]$cfg.provider_server_public_hex)
    Assert-Hex32 'Q6EA client private key' ([string]$cfg.anchor_client_private_hex)
    Assert-Hex32 'Q6EA server public key' ([string]$cfg.anchor_server_public_hex)
    foreach ($name in @('provider_receipt_public_hex','anchor_receipt_public_hex')) {
        if ([string]$cfg.$name -notmatch '^(?:[0-9a-fA-F]{2}){1952}$') {
            throw "$name must contain exactly 1952 ML-DSA-65 public-key bytes."
        }
    }

    $nodeBAddress = Get-ConnectedOverlayAddress
    [void](Assert-OverlayIPv4 'Node B Runner address' $nodeBAddress)
    if ($providerEndpoint.Address.ToString() -eq $nodeBAddress -or $anchorEndpoint.Address.ToString() -eq $nodeBAddress -or $callbackEndpoint.Address.ToString() -eq $nodeBAddress) {
        throw 'Node A service and callback endpoints must not point back to the Runner itself.'
    }
    $listenAddress = $nodeBAddress + ':' + $listenerPort

    New-Item -ItemType Directory -Path $tempRoot | Out-Null
    $nodeDirectory = Join-Path $tempRoot 'qfp6-node'
    $floorDirectory = Join-Path $tempRoot 'provider-floor'
    New-Item -ItemType Directory -Path $nodeDirectory,$floorDirectory | Out-Null

    # Private keys are injected only into the child process environment; they are
    # never placed on command lines, written to files, or printed in CI logs.
    $env:QRUN_QFP6_QAP1_LISTEN_ADDR = $listenAddress
    $env:QRUN_QFP6_QAP1_PROVIDER_ADDR = $providerEndpoint.ToString()
    $env:QRUN_QFP6_QAP1_ANCHOR_ADDR = $anchorEndpoint.ToString()
    $env:QRUN_QFP6_QAP1_LISTENER_PRIVATE = [string]$cfg.node_b_listener_private_hex
    $env:QRUN_QFP6_QAP1_PEER_PUBLIC = [string]$cfg.node_a_peer_public_hex
    $env:QRUN_QFP6_QAP1_PROVIDER_CLIENT_PRIVATE = [string]$cfg.provider_client_private_hex
    $env:QRUN_QFP6_QAP1_PROVIDER_SERVER_PUBLIC = [string]$cfg.provider_server_public_hex
    $env:QRUN_QFP6_QAP1_ANCHOR_CLIENT_PRIVATE = [string]$cfg.anchor_client_private_hex
    $env:QRUN_QFP6_QAP1_ANCHOR_SERVER_PUBLIC = [string]$cfg.anchor_server_public_hex
    $env:QRUN_QFP6_QAP1_PROVIDER_RECEIPT_PUBLIC = [string]$cfg.provider_receipt_public_hex
    $env:QRUN_QFP6_QAP1_ANCHOR_RECEIPT_PUBLIC = [string]$cfg.anchor_receipt_public_hex
    $env:QRUN_QFP6_QAP1_NODE_DIR = $nodeDirectory
    $env:QRUN_QFP6_QAP1_FLOOR_DIR = $floorDirectory

    Write-Output 'QFP6_QAP1_RUNNER_OVERLAY_READY=PASS'
    Write-Output 'QFP6_QAP1_CONFIG_SECRET_NOT_LOGGED=PASS'

    $compileOutput = & cargo test --locked --no-run --manifest-path $manifest --lib qrun_v06_node_runtime_candidate::tests::qfp6_qap1_process_worker 2>&1
    $compileCode = $LASTEXITCODE
    $compileOutput | ForEach-Object { Write-Output $_ }
    if ($compileCode -ne 0) { throw "QFP6 worker precompile failed with code $compileCode." }

    # CP-0566C diagnostic: capture Node B ICE/STUN/relay state before the callback.
    # Deliberately omit public keys and all secret-bearing configuration values.
    $netbirdDetail = (& $netbirdExe status -d 2>&1 | Out-String)
    $netbirdDetailExit = $LASTEXITCODE
    Write-Output 'QFP6_QAP1_RUNNER_NETBIRD_DIAGNOSTICS_BEGIN'
    $netbirdDetail -split '\r?\n' | Where-Object {
        $_ -match '^\s*(Management:|Signal:|Relays:|NetBird IP:|Status:|Connection type:|ICE candidate|Relay server address:|Last connection update:|Last WireGuard handshake:|Transfer status|Peers count:)' -or
        $_ -match '^\s*\[(stun:|turn:|turns:|rels://)'
    } | ForEach-Object { Write-Output $_ }
    Write-Output ("QFP6_QAP1_RUNNER_NETBIRD_STATUS_EXIT=" + $netbirdDetailExit)
    try {
        $routeCandidates = Find-NetRoute -RemoteIPAddress $callbackEndpoint.Address -ErrorAction Stop
        foreach ($candidate in $routeCandidates) {
            if ($candidate.PSObject.Properties.Name -contains 'InterfaceAlias') {
                Write-Output ("QFP6_QAP1_CALLBACK_ROUTE_INTERFACE=" + $candidate.InterfaceAlias)
                if ($candidate.PSObject.Properties.Name -contains 'DestinationPrefix') {
                    Write-Output ("QFP6_QAP1_CALLBACK_ROUTE_PREFIX=" + $candidate.DestinationPrefix)
                }
                if ($candidate.PSObject.Properties.Name -contains 'NextHop') {
                    Write-Output ("QFP6_QAP1_CALLBACK_ROUTE_NEXTHOP=" + $candidate.NextHop)
                }
            }
        }
    } catch {
        Write-Output ("QFP6_QAP1_CALLBACK_ROUTE_ERROR=" + $_.Exception.Message)
    }
    Write-Output 'QFP6_QAP1_RUNNER_NETBIRD_DIAGNOSTICS_END'

    $callbackClient = [System.Net.Sockets.TcpClient]::new()
    $callbackClient.Connect($callbackEndpoint.Address, $callbackEndpoint.Port)
    $callbackWriter = [System.IO.StreamWriter]::new($callbackClient.GetStream(), [System.Text.UTF8Encoding]::new($false))
    $callbackWriter.AutoFlush = $true
    $callbackNonce = [string]$cfg.callback_nonce_hex
    $callbackWriter.WriteLine(('READY|' + $callbackNonce + '|' + $listenAddress + '|' + [string]$cfg.node_b_listener_public_hex))
    Write-Output 'QFP6_QAP1_NODE_A_CALLBACK_READY=PASS'

    $firstOutput = Invoke-Qfp6Worker -Role 'server' -ExpectedAnchor 'none' -ExpectedHeight '' -ExpectedGeneration '' -ExpectedStateRoot ''
    Write-Output $firstOutput
    foreach ($marker in @('QFP6_QAP1_PROCESS_SERVER=PASS','QFP6_QAP1_MANIFEST_ANCHOR=','QFP6_QAP1_STATE_ROOT=','QFP6_QAP1_HEIGHT=','QFP6_QAP1_GENERATION=')) {
        if ($firstOutput -notmatch [regex]::Escape($marker)) {
            throw "First QFP6 process omitted required evidence marker: $marker"
        }
    }
    $anchor = [regex]::Match($firstOutput, '(?m)^QFP6_QAP1_MANIFEST_ANCHOR=([0-9a-fA-F]{64})$').Groups[1].Value
    $stateRoot = [regex]::Match($firstOutput, '(?m)^QFP6_QAP1_STATE_ROOT=([0-9a-fA-F]{64})$').Groups[1].Value
    $height = [regex]::Match($firstOutput, '(?m)^QFP6_QAP1_HEIGHT=([0-9]+)$').Groups[1].Value
    $generation = [regex]::Match($firstOutput, '(?m)^QFP6_QAP1_GENERATION=([0-9]+)$').Groups[1].Value
    Assert-Hex32 'Committed QFP6 manifest anchor' $anchor
    Assert-Hex32 'Committed QFP6 state root' $stateRoot
    if ($height -ne '1' -or $generation -ne '1') {
        throw 'The first QFP6 process did not commit exactly one test block and one manifest generation.'
    }

    $restartOutput = Invoke-Qfp6Worker -Role 'restart' -ExpectedAnchor $anchor -ExpectedHeight $height -ExpectedGeneration $generation -ExpectedStateRoot $stateRoot
    Write-Output $restartOutput
    if ($restartOutput -notmatch 'QFP6_QAP1_RESTART_SERVER=PASS') {
        throw 'Second QFP6 process did not confirm exact QAP1 restart continuity.'
    }

    Write-Output "QFP6_QAP1_RESTART_ANCHOR=$anchor"
    Write-Output "QFP6_QAP1_RESTART_STATE_ROOT=$stateRoot"
    Write-Output "QFP6_QAP1_RESTART_HEIGHT=$height"
    Write-Output "QFP6_QAP1_RESTART_GENERATION=$generation"
    Write-Output 'QFP6_QAP1_REMOTE_NODE_ADMISSION_AND_RESTART=PASS'
    $callbackWriter.WriteLine(('DONE|' + $callbackNonce + '|' + $anchor + '|' + $stateRoot + '|' + $height + '|' + $generation + '|PASS'))
    Write-Output 'QFP6_QAP1_NODE_A_RESTART_CALLBACK_SENT=PASS'
}
finally {
    if ($callbackWriter) { $callbackWriter.Dispose() }
    if ($callbackClient) { $callbackClient.Dispose() }
    foreach ($name in $privateEnvironmentNames) {
        Remove-Item -LiteralPath ("Env:" + $name) -ErrorAction SilentlyContinue
    }
    foreach ($name in @(
        'QRUN_QFP6_QAP1_RUNNER_CONFIG_JSON',
        'QRUN_QFP6_QAP1_PROCESS_ROLE',
        'QRUN_QFP6_QAP1_INITIALIZE_FLOOR',
        'QRUN_QFP6_QAP1_LISTENER_TIMEOUT_SECS',
        'QRUN_QFP6_QAP1_TRUSTED_MANIFEST_ANCHOR',
        'QRUN_QFP6_QAP1_EXPECTED_HEIGHT',
        'QRUN_QFP6_QAP1_EXPECTED_GENERATION',
        'QRUN_QFP6_QAP1_EXPECTED_STATE_ROOT',
        'QRUN_QFP6_QAP1_LISTEN_ADDR',
        'QRUN_QFP6_QAP1_PROVIDER_ADDR',
        'QRUN_QFP6_QAP1_ANCHOR_ADDR',
        'QRUN_QFP6_QAP1_NODE_DIR',
        'QRUN_QFP6_QAP1_FLOOR_DIR'
    )) {
        Remove-Item -LiteralPath ("Env:" + $name) -ErrorAction SilentlyContinue
    }
    if (Test-Path -LiteralPath $tempRoot) {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}
