Set-StrictMode -Version Latest

function Test-Qfp6PublicUnicastAddress {
    param([Parameter(Mandatory=$true)][System.Net.IPAddress]$Address)

    if ([System.Net.IPAddress]::IsLoopback($Address) -or
        $Address.Equals([System.Net.IPAddress]::IPv6Any) -or
        $Address.IsIPv6LinkLocal -or $Address.IsIPv6SiteLocal -or
        $Address.IsIPv6Multicast) {
        return $false
    }
    if ($Address.IsIPv4MappedToIPv6) {
        return (Test-Qfp6PublicUnicastAddress -Address $Address.MapToIPv4())
    }
    if ($Address.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
        $b = $Address.GetAddressBytes()
        if ($b[0] -eq 0 -or $b[0] -eq 10 -or $b[0] -eq 127 -or $b[0] -ge 224) { return $false }
        if ($b[0] -eq 100 -and $b[1] -ge 64 -and $b[1] -le 127) { return $false }
        if ($b[0] -eq 169 -and $b[1] -eq 254) { return $false }
        if ($b[0] -eq 172 -and $b[1] -ge 16 -and $b[1] -le 31) { return $false }
        if ($b[0] -eq 192 -and $b[1] -eq 168) { return $false }
        if ($b[0] -eq 192 -and $b[1] -eq 0 -and $b[2] -eq 0) { return $false }
        if ($b[0] -eq 192 -and $b[1] -eq 2) { return $false }
        if ($b[0] -eq 192 -and $b[1] -eq 88 -and $b[2] -eq 99) { return $false }
        if ($b[0] -eq 198 -and ($b[1] -eq 18 -or $b[1] -eq 19)) { return $false }
        if ($b[0] -eq 198 -and $b[1] -eq 51 -and $b[2] -eq 100) { return $false }
        if ($b[0] -eq 203 -and $b[1] -eq 0 -and $b[2] -eq 113) { return $false }
        if ($b[0] -ge 240) { return $false }
        return $true
    }

    $b = $Address.GetAddressBytes()
    if (($b[0] -band 0xfe) -eq 0xfc -or $b[0] -eq 0xff) { return $false }
    if ($b[0] -eq 0x00 -and $b[1] -eq 0x64 -and $b[2] -eq 0xff -and $b[3] -eq 0x9b -and $b[4] -eq 0x00 -and $b[5] -eq 0x01) { return $false }
    if ($b[0] -eq 0x01 -and $b[1] -eq 0x00 -and $b[2] -eq 0 -and $b[3] -eq 0 -and $b[4] -eq 0 -and $b[5] -eq 0 -and $b[6] -eq 0 -and $b[7] -eq 0) { return $false }
    if ($b[0] -eq 0x20 -and $b[1] -eq 0x01 -and $b[2] -le 1) { return $false }
    if ($b[0] -eq 0x20 -and $b[1] -eq 0x01 -and $b[2] -eq 0x0d -and $b[3] -eq 0xb8) { return $false }
    if ($b[0] -eq 0x20 -and $b[1] -eq 0x02) { return $false }
    if ($b[0] -eq 0x3f -and $b[1] -eq 0xff -and ($b[2] -band 0xf0) -eq 0) { return $false }
    return $true
}

function Resolve-Qfp6PublicSeedEndpoint {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$Value,
        [switch]$AllowPublicTcpRelay,
        [scriptblock]$Resolver
    )

    if ([string]::IsNullOrWhiteSpace($Value)) { throw 'Seed endpoint must not be empty.' }
    $ipText = $null
    $portText = $null
    if ($Value -match '^\[(?<ip>[0-9A-Fa-f:]+)\]:(?<port>[0-9]{1,5})$') {
        $ipText = $Matches.ip
        $portText = $Matches.port
    } elseif ($Value -match '^(?<ip>(?:[0-9]{1,3}\.){3}[0-9]{1,3}):(?<port>[0-9]{1,5})$') {
        $ipText = $Matches.ip
        $portText = $Matches.port
    }

    if ($null -ne $ipText) {
        $port = 0
        if (-not [int]::TryParse($portText, [ref]$port)) { throw 'Seed endpoint port is invalid.' }
        if ($port -ne 30333 -and -not ($AllowPublicTcpRelay -and $port -eq 443)) {
            throw 'Direct Seed endpoints must use TCP 30333; relay endpoints require explicit opt-in and TCP 443.'
        }
        $address = $null
        if (-not [System.Net.IPAddress]::TryParse($ipText, [ref]$address)) { throw 'Seed endpoint contains an invalid IP address.' }
        if (-not (Test-Qfp6PublicUnicastAddress -Address $address)) { throw 'Seed endpoint IP must be globally routable unicast.' }
        $normalizedIp = $address.ToString().ToLowerInvariant()
        if ($address.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) {
            $normalized = '[{0}]:{1}' -f $normalizedIp, $port
        } else {
            $normalized = '{0}:{1}' -f $normalizedIp, $port
        }
        return [pscustomobject]@{
            Address = $address
            ResolvedAddresses = @($address)
            Hostname = $null
            Port = $port
            Relay = ($port -eq 443)
            Normalized = $normalized
        }
    }

    if (-not $AllowPublicTcpRelay) {
        throw 'Seed endpoint must be a numeric IP on TCP 30333. Hostnames require -AllowPublicTcpRelay and TCP 443.'
    }
    if ($Value -notmatch '^(?<host>[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+):(?<port>[0-9]{1,5})$') {
        throw 'Relay endpoint must be a public DNS FQDN:443 without a scheme, path or placeholder.'
    }
    $hostName = $Matches.host.ToLowerInvariant()
    $port = 0
    if (-not [int]::TryParse($Matches.port, [ref]$port) -or $port -ne 443) {
        throw 'Public TCP relay endpoint must use TCP port 443.'
    }
    $reservedSuffixes = @('.localhost','.local','.internal','.test','.invalid','.example')
    $reservedName = $false
    foreach ($suffix in $reservedSuffixes) {
        if ($hostName.EndsWith($suffix, [StringComparison]::OrdinalIgnoreCase)) {
            $reservedName = $true
            break
        }
    }
    if ($hostName -eq 'localhost' -or $reservedName) {
        throw 'Relay hostname must be a public FQDN, not a local or reserved name.'
    }

    if ($null -eq $Resolver) {
        $Resolver = { param($Name, $Port) [System.Net.Dns]::GetHostAddresses($Name) }
    }
    try {
        $addresses = @(& $Resolver $hostName $port)
    } catch {
        throw "Relay hostname DNS resolution failed: $($_.Exception.Message)"
    }
    if ($addresses.Count -lt 1 -or $addresses.Count -gt 16) {
        throw 'Relay hostname must resolve to between 1 and 16 addresses.'
    }
    foreach ($resolved in $addresses) {
        if ($resolved -isnot [System.Net.IPAddress] -or -not (Test-Qfp6PublicUnicastAddress -Address $resolved)) {
            throw 'Every relay DNS answer must be a globally routable unicast IP address.'
        }
    }
    $addresses = @($addresses | Sort-Object { $_.ToString() } -Unique)
    return [pscustomobject]@{
        Address = $null
        ResolvedAddresses = $addresses
        Hostname = $hostName
        Port = $port
        Relay = $true
        Normalized = ('{0}:{1}' -f $hostName, $port)
    }
}

Export-ModuleMember -Function Resolve-Qfp6PublicSeedEndpoint, Test-Qfp6PublicUnicastAddress
