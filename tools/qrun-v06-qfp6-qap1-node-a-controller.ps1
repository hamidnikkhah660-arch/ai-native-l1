[CmdletBinding()]
param(
    [switch]$Dispatch,
    [switch]$AclReviewed,
    [ValidateRange(49664,49664)]
    [int]$RunnerPort = 49664,
    [string]$Repository = 'hamidnikkhah660-arch/ai-native-l1'
)

$ErrorActionPreference = 'Stop'
$workflowFile = 'qfp6-qap1-netbird-cross-host.yml'
$branchExpected = 'feat/qzxb-usdt-trading-gate-20261104'
$configSecretName = 'QRUN_QFP6_QAP1_RUNNER_CONFIG_JSON'
$setupSecretName = 'QRUN_CP0566C_NETBIRD_SETUP_KEY'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$manifest = Join-Path $repoRoot 'src/native/pow_bench/Cargo.toml'
$netbirdExe = 'C:\Program Files\NetBird\netbird.exe'
$driverProcess = $null
$driverTempRoot = $null
$configSecretCreated = $false
$setupSecretCreated = $false
$runId = $null

function Invoke-GhText([string[]]$Arguments) {
    $output = & gh @Arguments 2>&1
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) {
        throw ("gh command failed ({0}): {1}" -f $exitCode, (($output | ForEach-Object { [string]$_ }) -join ' '))
    }
    return ($output | ForEach-Object { [string]$_ }) -join [Environment]::NewLine
}

function Get-LocalNetBirdIPv4 {
    if (-not (Test-Path -LiteralPath $netbirdExe -PathType Leaf)) {
        throw 'NetBird CLI is not installed on the laptop.'
    }
    $status = (& $netbirdExe status 2>&1 | Out-String)
    if ($LASTEXITCODE -ne 0 -or
        $status -notmatch 'Management:\s+Connected' -or
        $status -notmatch 'Signal:\s+Connected') {
        throw 'The laptop NetBird Management and Signal states must both be Connected.'
    }
    $match = [regex]::Match($status, 'NetBird IP:\s+([0-9]{1,3}(?:\.[0-9]{1,3}){3})')
    if (-not $match.Success) { throw 'The laptop NetBird IPv4 address could not be determined.' }
    $ip = [System.Net.IPAddress]::Parse($match.Groups[1].Value)
    $octets = $ip.GetAddressBytes()
    if ($octets[0] -ne 100 -or $octets[1] -lt 64 -or $octets[1] -gt 127) {
        throw 'The laptop NetBird address is outside 100.64.0.0/10.'
    }
    return $ip.ToString()
}

function Assert-RemoteRevisionReady {
    Set-Location $repoRoot
    $localBranch = (git branch --show-current).Trim()
    if ([string]::IsNullOrWhiteSpace($localBranch)) {
        throw 'The local qualification checkout must use a named branch; detached HEAD is not permitted.'
    }
    $localSha = (git rev-parse HEAD).Trim()
    # A dedicated clean worktree may use a local alias branch. The remote branch
    # name/ref below is fixed; exact local HEAD == remote branch SHA is authoritative.
    if ((git status --porcelain) -ne $null -and (git status --porcelain | Measure-Object -Line).Lines -gt 0) {
        throw 'The local worktree is not clean. Review and commit the intended qualification files before dispatch.'
    }
    $remoteBranchJson = Invoke-GhText @('api',"repos/$Repository/branches/$branchExpected")
    $remoteBranch = $remoteBranchJson | ConvertFrom-Json
    if ($remoteBranch.commit.sha -ne $localSha) {
        throw 'The remote qualification branch does not point to the exact local HEAD.'
    }
    $defaultInfo = Invoke-GhText @('repo','view',$Repository,'--json','defaultBranchRef')
    $defaultBranch = ($defaultInfo | ConvertFrom-Json).defaultBranchRef.name
    # GitHub requires the workflow definition on the default branch for
    # workflow_dispatch discovery. The Runner script is executed from the
    # selected feature SHA, so it only needs to exist on that exact branch.
    $workflowPath = ".github/workflows/$workflowFile"
    $null = Invoke-GhText @('api',"repos/$Repository/contents/$workflowPath?ref=$defaultBranch")
    foreach ($path in @(
        $workflowPath,
        'tools/qrun-v06-qfp6-qap1-runner.ps1'
    )) {
        $null = Invoke-GhText @('api',"repos/$Repository/contents/$path?ref=$branchExpected")
    }
    return $localSha
}

function Start-NodeADriver([string]$OverlayIPv4) {
    $script:driverTempRoot = Join-Path $env:TEMP ('qfp6-qap1-node-a-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:driverTempRoot | Out-Null

    # Lock the directory before the Rust driver creates its key-bearing JSON file.
    $userSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl = [System.Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner($userSid)
    $inherit = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    foreach ($sid in @(
        $userSid,
        [System.Security.Principal.SecurityIdentifier]::new('S-1-5-18'),
        [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
    )) {
        $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
            $sid,
            [System.Security.AccessControl.FileSystemRights]::FullControl,
            $inherit,
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow
        )
        $acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $script:driverTempRoot -AclObject $acl
    $script:driverConfigPath = Join-Path $script:driverTempRoot 'runner-config.json'

    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = (Get-Command cargo -ErrorAction Stop).Source
    $psi.Arguments = '--locked --manifest-path "' + $manifest + '" --lib qrun_v06_node_runtime_candidate::tests::qfp6_qap1_node_a_driver -- --exact --nocapture'
    $psi.WorkingDirectory = $repoRoot
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true
    $psi.EnvironmentVariables['QRUN_QFP6_QAP1_NODE_A_ROLE'] = 'driver'
    $psi.EnvironmentVariables['QRUN_QFP6_QAP1_NODE_A_OVERLAY_IP'] = $OverlayIPv4
    $psi.EnvironmentVariables['QRUN_QFP6_QAP1_NODE_A_CONFIG_PATH'] = $script:driverConfigPath

    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $psi
    if (-not $process.Start()) { throw 'Could not start the Node A QFP6/QAP1 driver.' }
    $script:driverProcess = $process
    # Drain both redirected pipes asynchronously so cargo output cannot block the worker.
    $script:driverOutputTask = $process.StandardOutput.ReadToEndAsync()
    $script:driverErrorTask = $process.StandardError.ReadToEndAsync()
    return $process
}

function Read-DriverBootstrap([System.Diagnostics.Process]$Process) {
    $deadline = [datetime]::UtcNow.AddMinutes(10)
    $required = @(
        'node_a_provider_address', 'node_a_anchor_address', 'node_a_callback_address',
        'callback_nonce_hex', 'node_b_listener_port', 'node_b_listener_private_hex',
        'node_b_listener_public_hex', 'node_a_peer_public_hex', 'provider_client_private_hex',
        'provider_server_public_hex', 'anchor_client_private_hex', 'anchor_server_public_hex',
        'provider_receipt_public_hex', 'anchor_receipt_public_hex'
    )
    $configJson = $null
    $cfg = $null
    $lastIssue = 'The configuration file has not been created yet.'

    while ([datetime]::UtcNow -lt $deadline) {
        if (Test-Path -LiteralPath $script:driverConfigPath -PathType Leaf) {
            try {
                $candidateJson = Get-Content -LiteralPath $script:driverConfigPath -Raw
                $candidateCfg = $candidateJson | ConvertFrom-Json -ErrorAction Stop
                $missing = @(
                    foreach ($name in $required) {
                        if (-not $candidateCfg.PSObject.Properties[$name] -or
                            [string]::IsNullOrWhiteSpace([string]$candidateCfg.$name)) { $name }
                    }
                )
                if ($missing.Count -eq 0) {
                    $configJson = $candidateJson
                    $cfg = $candidateCfg
                    break
                }
                $lastIssue = 'Configuration is not complete yet; missing fields: ' + ($missing -join ', ')
            }
            catch {
                $lastIssue = $_.Exception.Message
            }
        }

        if ($Process.HasExited) { break }
        Start-Sleep -Milliseconds 200
    }

    if ($null -eq $configJson) {
        if ($Process.HasExited) {
            $stdout = $script:driverOutputTask.GetAwaiter().GetResult()
            $stderr = $script:driverErrorTask.GetAwaiter().GetResult()
            throw "Node A exited before creating a complete bootstrap file. Exit=$($Process.ExitCode); issue=$lastIssue; stdout=$stdout; stderr=$stderr"
        }
        throw "Timed out waiting for a complete protected Node A Runner configuration file: $lastIssue"
    }
    if ([int]$cfg.node_b_listener_port -ne $RunnerPort) {
        throw 'Node A bootstrap did not retain the canonical QFP6 Runner port.'
    }
    return $configJson
}

function Set-GhSecretFromString([string]$Name, [string]$Value) {
    $Value | & gh secret set $Name --repo $Repository
    if ($LASTEXITCODE -ne 0) { throw "Could not provision temporary Actions secret $Name." }
}

function Get-DispatchRunId([string]$ExpectedSha, [datetime]$StartedUtc) {
    for ($attempt = 0; $attempt -lt 60; $attempt++) {
        $raw = Invoke-GhText @('run','list','--repo',$Repository,'--workflow',$workflowFile,'--branch',$branchExpected,'--limit','8','--json','databaseId,event,headSha,createdAt,status')
        $runs = @($raw | ConvertFrom-Json)
        $match = $runs |
            Where-Object {
                $_.event -eq 'workflow_dispatch' -and
                $_.headSha -eq $ExpectedSha -and
                ([datetime]$_.createdAt).ToUniversalTime() -ge $StartedUtc.AddMinutes(-1)
            } |
            Select-Object -First 1
        if ($match) { return [string]$match.databaseId }
        Start-Sleep -Seconds 2
    }
    throw 'GitHub Actions did not publish the manually dispatched run ID.'
}

function Wait-RunnerEndpoint([string]$RunId) {
    for ($attempt = 0; $attempt -lt 180; $attempt++) {
        $logs = & gh run view $RunId --repo $Repository --log 2>$null
        if ($LASTEXITCODE -eq 0) {
            $joined = ($logs | ForEach-Object { [string]$_ }) -join [Environment]::NewLine
            $match = [regex]::Match($joined, '(?m)QFP6_QAP1_RUNNER_LISTEN_ENDPOINT=(100\.(?:6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.[0-9]{1,3}\.[0-9]{1,3}):([0-9]{1,5})')
            if ($match.Success) {
                if ([int]$match.Groups[2].Value -ne $RunnerPort) {
                    throw 'Runner published an unexpected QFP6 listener port.'
                }
                return $match.Value.Substring('QFP6_QAP1_RUNNER_LISTEN_ENDPOINT='.Length)
            }
        }
        $stateRaw = & gh run view $RunId --repo $Repository --json status,conclusion 2>$null
        if ($LASTEXITCODE -eq 0) {
            $state = $stateRaw | ConvertFrom-Json
            if ($state.status -eq 'completed') {
                throw "GitHub Runner completed before publishing its QFP6 endpoint. Conclusion=$($state.conclusion)."
            }
        }
        Start-Sleep -Seconds 5
    }
    throw 'Timed out waiting for the ephemeral Runner to publish its private overlay endpoint.'
}

try {
    if (-not $Dispatch) {
        Write-Host 'Node A controller is in safe preflight mode. No secrets, workflow runs, or network listeners were created.'
        Write-Host 'Run with -Dispatch -AclReviewed only after the one-off NetBird peer key, tags, peer ACL, and host firewalls are reviewed.'
        return
    }
    if (-not $AclReviewed) {
        throw 'Dispatch is blocked unless -AclReviewed is supplied after reviewing the exact two-peer NetBird ACL and endpoint firewall rules.'
    }

    $localSha = Assert-RemoteRevisionReady
    $overlayIp = Get-LocalNetBirdIPv4
    $existingSecrets = Invoke-GhText @('secret','list','--repo',$Repository,'--json','name')
    $existingNames = @($existingSecrets | ConvertFrom-Json | ForEach-Object { $_.name })
    if ($existingNames -contains $configSecretName -or $existingNames -contains $setupSecretName) {
        throw 'A CP-0566C temporary Actions secret already exists. Refusing to overwrite it.'
    }

    $secureSetupKey = Read-Host 'Enter the NetBird ONE-OFF Setup Key tagged for the QFP6 qualification Runner' -AsSecureString
    if ($secureSetupKey.Length -lt 1 -or $secureSetupKey.Length -gt 256) {
        throw 'The supplied one-off NetBird Setup Key has an invalid length.'
    }

    $process = Start-NodeADriver -OverlayIPv4 $overlayIp
    $configJson = Read-DriverBootstrap -Process $process

    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureSetupKey)
    try {
        $plainSetupKey = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        if ([string]::IsNullOrWhiteSpace($plainSetupKey) -or $plainSetupKey -match '\s' -or $plainSetupKey.Length -gt 256) {
            throw 'The supplied one-off NetBird Setup Key must be a bounded non-whitespace token.'
        }
        Set-GhSecretFromString -Name $setupSecretName -Value $plainSetupKey
        $setupSecretCreated = $true
    }
    finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        $plainSetupKey = $null
    }

    Set-GhSecretFromString -Name $configSecretName -Value $configJson
    $configSecretCreated = $true
    $configJson = $null

    $dispatchStarted = [datetime]::UtcNow
    $null = Invoke-GhText @('workflow','run',$workflowFile,'--repo',$Repository,'--ref',$branchExpected)
    $runId = Get-DispatchRunId -ExpectedSha $localSha -StartedUtc $dispatchStarted
    Write-Host "CP-0566C_RUN_ID=$runId"

    # Node A receives the Runner endpoint only through the authenticated READY callback.
    # The callback nonce and listener identity are validated by the Rust driver.
    while (-not $process.HasExited) {
        $stateRaw = & gh run view $runId --repo $Repository --json status,conclusion 2>$null
        if ($LASTEXITCODE -eq 0) {
            $state = $stateRaw | ConvertFrom-Json
            if ($state.status -eq 'completed' -and $state.conclusion -ne 'success') {
                throw "GitHub Runner ended before Node A completed. Conclusion=$($state.conclusion)."
            }
        }
        Start-Sleep -Seconds 2
    }
    $driverStdOut = $script:driverOutputTask.GetAwaiter().GetResult()
    $driverStdErr = $script:driverErrorTask.GetAwaiter().GetResult()
    if ($process.ExitCode -ne 0) {
        throw "Node A cross-host driver failed with exit code $($process.ExitCode): stdout=$driverStdOut; stderr=$driverStdErr"
    }
    if ($driverStdOut -notmatch 'QFP6_QAP1_NODE_A_CONFIRMED_REMOTE_RESTART=PASS') {
        throw 'Node A did not emit the authenticated remote restart confirmation marker.'
    }

    $null = Invoke-GhText @('run','watch',$runId,'--repo',$Repository,'--exit-status')
    $finalLogs = Invoke-GhText @('run','view',$runId,'--repo',$Repository,'--log')
    if ($finalLogs -notmatch 'QFP6_QAP1_REMOTE_NODE_ADMISSION_AND_RESTART=PASS') {
        throw 'Runner logs did not contain the complete QFP6/QAP1 admission and restart PASS marker.'
    }
    Write-Host 'CP0566C_TWO_HOST_QFP6_QAP1=PASS'
}
finally {
    if ($null -ne $driverProcess -and -not $driverProcess.HasExited) {
        try { $driverProcess.Kill(); $driverProcess.WaitForExit() } catch { }
    }
    if ($null -ne $driverTempRoot -and (Test-Path -LiteralPath $driverTempRoot)) {
        Remove-Item -LiteralPath $driverTempRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
    if ($runId) {
        $stateRaw = & gh run view $runId --repo $Repository --json status 2>$null
        if ($LASTEXITCODE -eq 0 -and ($stateRaw | ConvertFrom-Json).status -ne 'completed') {
            & gh run cancel $runId --repo $Repository 2>$null | Out-Null
        }
    }
    if ($configSecretCreated) {
        & gh secret delete $configSecretName --repo $Repository 2>$null | Out-Null
    }
    if ($setupSecretCreated) {
        & gh secret delete $setupSecretName --repo $Repository 2>$null | Out-Null
    }
    if ($null -ne $secureSetupKey) { $secureSetupKey.Dispose() }
}