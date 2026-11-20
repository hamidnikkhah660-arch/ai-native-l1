$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'qfp6-public-seed-endpoint.psm1') -Force

$script:Passed = 0
function Assert-True([bool]$Condition, [string]$Name) {
    if (-not $Condition) { throw "FAIL: $Name" }
    $script:Passed++
}
function Assert-Fails([scriptblock]$Action, [string]$Name) {
    $failed = $false
    try { & $Action | Out-Null } catch { $failed = $true }
    if (-not $failed) { throw "FAIL: $Name should have been rejected" }
    $script:Passed++
}

$direct = Resolve-Qfp6PublicSeedEndpoint -Value '8.8.8.8:30333'
Assert-True ($direct.Normalized -eq '8.8.8.8:30333' -and -not $direct.Relay) 'direct numeric Seed endpoint'

Assert-Fails { Resolve-Qfp6PublicSeedEndpoint -Value '8.8.8.8:443' } 'relay port without explicit opt-in'
Assert-Fails { Resolve-Qfp6PublicSeedEndpoint -Value '10.0.0.8:30333' } 'private direct Seed endpoint'
Assert-Fails { Resolve-Qfp6PublicSeedEndpoint -Value '198.51.100.8:30333' } 'documentation-range Seed endpoint'

$publicV6Resolver = { param($Name, $Port) return @([System.Net.IPAddress]::Parse('2606:4700:4700::1111')) }
$v6Relay = Resolve-Qfp6PublicSeedEndpoint -Value 'seed6.tailnet.ts.net:443' -AllowPublicTcpRelay -Resolver $publicV6Resolver
Assert-True ($v6Relay.ResolvedAddresses[0].AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) 'public IPv6 relay answer'
$v6AnyResolver = { param($Name, $Port) return @([System.Net.IPAddress]::IPv6Any) }
Assert-Fails { Resolve-Qfp6PublicSeedEndpoint -Value 'seed6.tailnet.ts.net:443' -AllowPublicTcpRelay -Resolver $v6AnyResolver } 'IPv6 unspecified DNS answer'
$v6LocalResolver = { param($Name, $Port) return @([System.Net.IPAddress]::Parse('fd00::1')) }
Assert-Fails { Resolve-Qfp6PublicSeedEndpoint -Value 'seed6.tailnet.ts.net:443' -AllowPublicTcpRelay -Resolver $v6LocalResolver } 'IPv6 unique-local DNS answer'
$v6DocsResolver = { param($Name, $Port) return @([System.Net.IPAddress]::Parse('2001:db8::1')) }
Assert-Fails { Resolve-Qfp6PublicSeedEndpoint -Value 'seed6.tailnet.ts.net:443' -AllowPublicTcpRelay -Resolver $v6DocsResolver } 'IPv6 documentation DNS answer'

$publicResolver = {
    param($Name, $Port)
    if ($Name -ne 'seed.tailnet.ts.net' -or $Port -ne 443) { throw 'unexpected resolver input' }
    return @(
        [System.Net.IPAddress]::Parse('1.1.1.1'),
        [System.Net.IPAddress]::Parse('2606:4700:4700::1111')
    )
}
$relay = Resolve-Qfp6PublicSeedEndpoint -Value 'seed.tailnet.ts.net:443' -AllowPublicTcpRelay -Resolver $publicResolver
Assert-True ($relay.Normalized -eq 'seed.tailnet.ts.net:443' -and $relay.Relay) 'explicit DNS TCP relay'
Assert-True ($relay.ResolvedAddresses.Count -eq 2) 'all public DNS answers retained for alias checks'

Assert-Fails { Resolve-Qfp6PublicSeedEndpoint -Value 'seed.tailnet.ts.net:443' -Resolver $publicResolver } 'DNS endpoint without opt-in'
Assert-Fails { Resolve-Qfp6PublicSeedEndpoint -Value 'seed.tailnet.ts.net:8443' -AllowPublicTcpRelay -Resolver $publicResolver } 'relay port other than 443'
Assert-Fails { Resolve-Qfp6PublicSeedEndpoint -Value 'seed..tailnet.ts.net:443' -AllowPublicTcpRelay -Resolver $publicResolver } 'malformed FQDN'
Assert-Fails { Resolve-Qfp6PublicSeedEndpoint -Value 'localhost:443' -AllowPublicTcpRelay -Resolver $publicResolver } 'localhost relay'

$privateResolver = { param($Name,$Port) return @([System.Net.IPAddress]::Parse('10.0.0.8')) }
Assert-Fails { Resolve-Qfp6PublicSeedEndpoint -Value 'seed.tailnet.ts.net:443' -AllowPublicTcpRelay -Resolver $privateResolver } 'private DNS answer'

$mixedResolver = {
    param($Name,$Port)
    return @(
        [System.Net.IPAddress]::Parse('1.1.1.1'),
        [System.Net.IPAddress]::Parse('192.168.1.8')
    )
}
Assert-Fails { Resolve-Qfp6PublicSeedEndpoint -Value 'seed.tailnet.ts.net:443' -AllowPublicTcpRelay -Resolver $mixedResolver } 'mixed public/private DNS answers'

Write-Output "QFP6 public Seed endpoint tests: $script:Passed passed, 0 failed."
