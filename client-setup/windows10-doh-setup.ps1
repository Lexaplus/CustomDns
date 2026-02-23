#Requires -RunAsAdministrator
<#
.SYNOPSIS
    One-click Windows 10 DNS-over-HTTPS setup for the private DNS server at 159.89.25.145.

.DESCRIPTION
    Windows 10 lacks built-in DoH support, so this script installs dnscrypt-proxy
    as a local Windows service that tunnels all DNS traffic over HTTPS.

    1. Installs the server's self-signed TLS cert into Local Machine Trusted Root CA.
    2. Downloads dnscrypt-proxy (latest release) and installs it to C:\dnscrypt-proxy\.
    3. Configures dnscrypt-proxy to forward to https://159.89.25.145:8443/dns-query.
    4. Sets DNS on all active adapters to 127.0.0.1 (the local dnscrypt-proxy).
    5. Verifies end-to-end DNS resolution.

.NOTES
    Run as Administrator. Compatible with Windows 10 (all builds).
    dnscrypt-proxy is installed to C:\dnscrypt-proxy\ and runs as a Windows service.
    To remove everything, run: .\windows10-doh-setup.ps1 -Uninstall

    If CERT_B64 below is empty the script will fetch the cert live from the
    server using a raw TLS connection (requires network access to port 8443).
    To pre-embed the cert:
        openssl s_client -connect 159.89.25.145:8443 </dev/null 2>/dev/null \
            | openssl x509 | base64 -w0
    Paste the single-line base64 output as the value of $CERT_B64.
#>

[CmdletBinding()]
param(
    [string]$ServerAddress = "159.89.25.145",
    [string]$DohPath       = "/dns-query",
    [int]   $DohPort       = 8443,
    [string]$InstallDir    = "C:\dnscrypt-proxy",
    [switch]$Uninstall
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ---------------------------------------------------------------------------
# Embedded certificate (optional — leave empty to fetch live at runtime).
# ---------------------------------------------------------------------------
$CERT_B64 = ""

$ServiceName = "dnscrypt-proxy"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
function Write-Step { param([string]$msg) Write-Host "`n==> $msg" -ForegroundColor Cyan  }
function Write-Ok   { param([string]$msg) Write-Host "    OK  $msg" -ForegroundColor Green }
function Write-Warn { param([string]$msg) Write-Host "    !   $msg" -ForegroundColor Yellow }
function Write-Fail { param([string]$msg) Write-Host "    ERR $msg" -ForegroundColor Red  }

function Get-CertFromServer {
    Write-Step "Fetching certificate live from ${ServerAddress}:${DohPort} ..."
    $cb = [System.Net.Security.RemoteCertificateValidationCallback]{
        param($sender, $cert, $chain, $errors) $true
    }
    $tcp = [System.Net.Sockets.TcpClient]::new($ServerAddress, $DohPort)
    $ssl = [System.Net.Security.SslStream]::new($tcp.GetStream(), $false, $cb)
    try {
        $ssl.AuthenticateAsClient($ServerAddress)
        $rawBytes = $ssl.RemoteCertificate.Export(
            [System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
        return [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($rawBytes)
    } finally {
        $ssl.Dispose()
        $tcp.Dispose()
    }
}

function Import-TrustedRootCert {
    param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert)
    $store = [System.Security.Cryptography.X509Certificates.X509Store]::new("Root", "LocalMachine")
    $store.Open("ReadWrite")
    try {
        $existing = $store.Certificates | Where-Object { $_.Thumbprint -eq $Cert.Thumbprint }
        if ($existing) {
            Write-Ok "Certificate already trusted (thumbprint $($Cert.Thumbprint))"
        } else {
            $store.Add($Cert)
            Write-Ok "Installed cert  Subject=$($Cert.Subject)  Thumbprint=$($Cert.Thumbprint)"
        }
    } finally { $store.Close() }
    return $Cert.Thumbprint
}

# Builds a DNS stamp for a DoH server (https://dnscrypt.info/stamps-specifications)
# Empty hash list = rely on system CA store (we install our cert there in step 1)
function New-DoHStamp {
    param([string]$Addr, [string]$Hostname, [string]$Path)
    $b = [System.Collections.Generic.List[byte]]::new()
    $b.Add(0x02)                              # Protocol: DoH
    1..8 | ForEach-Object { $b.Add(0) }       # Props: 8 zero bytes
    $a = [Text.Encoding]::ASCII.GetBytes($Addr)
    $b.Add([byte]$a.Length); $b.AddRange($a)  # Addr (length-prefixed)
    $b.Add(0)                                  # Hash list: empty terminator = use system CA
    $h = [Text.Encoding]::ASCII.GetBytes($Hostname)
    $b.Add([byte]$h.Length); $b.AddRange($h)  # Hostname (length-prefixed)
    $p = [Text.Encoding]::ASCII.GetBytes($Path)
    $b.Add([byte]$p.Length); $b.AddRange($p)  # Path (length-prefixed)
    $enc = [Convert]::ToBase64String($b.ToArray()) -replace '\+','-' -replace '/','_' -replace '=',''
    return "sdns://$enc"
}

# ---------------------------------------------------------------------------
# Uninstall path
# ---------------------------------------------------------------------------
if ($Uninstall) {
    Write-Step "Uninstalling dnscrypt-proxy and DNS configuration ..."

    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($svc) {
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        & "$InstallDir\dnscrypt-proxy.exe" -service uninstall 2>&1 | Out-Null
        Write-Ok "Service '$ServiceName' removed"
    } else {
        Write-Warn "Service '$ServiceName' not found — skipping"
    }

    Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | ForEach-Object {
        $cfg = Get-DnsClientServerAddress -InterfaceIndex $_.ifIndex -AddressFamily IPv4
        if ($cfg.ServerAddresses -contains "127.0.0.1") {
            Set-DnsClientServerAddress -InterfaceIndex $_.ifIndex -ResetServerAddresses
            Write-Ok "Reset DNS on '$($_.Name)'"
        }
    }

    if (Test-Path $InstallDir) {
        Remove-Item -Path $InstallDir -Recurse -Force
        Write-Ok "Removed $InstallDir"
    }

    Clear-DnsClientCache
    Write-Host "`n--- Uninstall complete ---`n" -ForegroundColor Green
    Write-Warn "Certificate must be removed manually:"
    Write-Warn "  certlm.msc -> Trusted Root CAs -> find CN=$ServerAddress -> Delete"
    exit 0
}

# ---------------------------------------------------------------------------
# STEP 1: Obtain and install certificate
# ---------------------------------------------------------------------------
Write-Step "Step 1 of 4 — Obtaining server certificate ..."

[System.Security.Cryptography.X509Certificates.X509Certificate2]$cert = $null

if ($CERT_B64 -ne "") {
    $b64clean = ($CERT_B64 -replace "-----[^-]+-----","" -replace "\s","")
    $certBytes = [Convert]::FromBase64String($b64clean)
    $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($certBytes)
    Write-Ok "Using embedded certificate (Subject: $($cert.Subject))"
} else {
    $cert = Get-CertFromServer
    Write-Ok "Fetched certificate: Subject=$($cert.Subject)  Expiry=$($cert.NotAfter)"
}

Write-Step "Step 1b — Installing certificate into Trusted Root CA store ..."
$thumbprint = Import-TrustedRootCert -Cert $cert

# ---------------------------------------------------------------------------
# STEP 2: Download and install dnscrypt-proxy
# ---------------------------------------------------------------------------
Write-Step "Step 2 of 4 — Downloading dnscrypt-proxy ..."

Write-Ok "Fetching latest release info from GitHub ..."
$release = Invoke-RestMethod "https://api.github.com/repos/DNSCrypt/dnscrypt-proxy/releases/latest" `
    -UseBasicParsing
$version = $release.tag_name
$asset   = $release.assets | Where-Object { $_.name -like "dnscrypt-proxy-win64-*.zip" } |
    Select-Object -First 1

if (-not $asset) {
    throw "Could not find a Windows 64-bit asset in dnscrypt-proxy release $version"
}

$zipPath = "$env:TEMP\dnscrypt-proxy.zip"
$tmpDir  = "$env:TEMP\dnscrypt-proxy-extract"

Write-Ok "Downloading dnscrypt-proxy $version ..."
Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $zipPath -UseBasicParsing

Write-Ok "Extracting ..."
if (Test-Path $tmpDir) { Remove-Item $tmpDir -Recurse -Force }
Expand-Archive -Path $zipPath -DestinationPath $tmpDir -Force
Remove-Item $zipPath -Force

$srcDir = Get-ChildItem $tmpDir -Directory | Select-Object -First 1
$srcPath = if ($srcDir) { $srcDir.FullName } else { $tmpDir }

if (-not (Test-Path $InstallDir)) {
    New-Item -Path $InstallDir -ItemType Directory | Out-Null
}

Copy-Item "$srcPath\dnscrypt-proxy.exe" "$InstallDir\dnscrypt-proxy.exe" -Force
Remove-Item $tmpDir -Recurse -Force
Write-Ok "dnscrypt-proxy $version installed to $InstallDir"

# ---------------------------------------------------------------------------
# STEP 3: Write config and install service
# ---------------------------------------------------------------------------
Write-Step "Step 3 of 4 — Configuring and starting dnscrypt-proxy service ..."

$stamp = New-DoHStamp `
    -Addr     "${ServerAddress}:${DohPort}" `
    -Hostname $ServerAddress `
    -Path     $DohPath
Write-Ok "DoH stamp: $stamp"

$config = @"
# dnscrypt-proxy configuration — generated by windows10-doh-setup.ps1

listen_addresses    = ['127.0.0.1:53']
server_names        = ['lexdns']

ipv4_servers        = true
ipv6_servers        = false
dnscrypt_servers    = false
doh_servers         = true

require_nolog       = false
require_nofilter    = false
require_dnssec      = false

timeout             = 5000
keepalive           = 30
log_level           = 2
use_syslog          = false

# Bootstrap resolvers are used only if the server address is a hostname.
# Our server uses a literal IP so these are a fallback safety net only.
ignore_system_dns   = true
fallback_resolvers  = ['1.1.1.1:53', '8.8.8.8:53']
netprobe_timeout    = 60
netprobe_address    = '8.8.8.8:53'

[static]
  [static.'lexdns']
  stamp = '$stamp'
"@

$configPath = "$InstallDir\dnscrypt-proxy.toml"
Set-Content -Path $configPath -Value $config -Encoding UTF8
Write-Ok "Config written to $configPath"

# Remove stale service if present
$svcExisting = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($svcExisting) {
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    $null = & "$InstallDir\dnscrypt-proxy.exe" -config $configPath -service uninstall 2>&1
}

# Install the service (dnscrypt-proxy may return non-zero even on success; capture and ignore)
$null = & "$InstallDir\dnscrypt-proxy.exe" -config $configPath -service install 2>&1

# Start via PowerShell cmdlet — avoids NativeCommandError from -service start flag
Start-Service -Name $ServiceName -ErrorAction Stop
Write-Ok "Service '$ServiceName' installed and started"

Start-Sleep -Seconds 2  # give the service a moment to bind port 53

# ---------------------------------------------------------------------------
# STEP 4: Point DNS to the local proxy
# ---------------------------------------------------------------------------
Write-Step "Step 4 of 4 — Setting DNS to 127.0.0.1 on all active adapters ..."

$adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
if (-not $adapters) { Write-Warn "No active adapters found — DNS not set" }

foreach ($adapter in $adapters) {
    Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ServerAddress "127.0.0.1"
    Write-Ok "  [$($adapter.Name)] -> 127.0.0.1 (dnscrypt-proxy)"
}

Clear-DnsClientCache
Write-Ok "DNS cache flushed"

# ---------------------------------------------------------------------------
# Verify
# ---------------------------------------------------------------------------
Write-Step "Verifying DNS-over-HTTPS resolution ..."
Start-Sleep -Seconds 1

$resolved  = $false
$resolvedIP = ""

try {
    $result = Resolve-DnsName "google.com" -Type A -ErrorAction Stop |
        Where-Object { $_.QueryType -eq "A" } | Select-Object -First 1
    if ($result -and $result.IPAddress -notmatch "^198\.18\.") {
        $resolved   = $true
        $resolvedIP = $result.IPAddress
    }
} catch {
    try {
        $ns = & nslookup google.com 127.0.0.1 2>&1 | Out-String
        if ($ns -match "Address:\s+((?!127\.0\.0\.1)\d+\.\d+\.\d+\.\d+)") {
            $ip = $Matches[1]
            if ($ip -notmatch "^198\.18\.") { $resolved = $true; $resolvedIP = $ip }
        }
    } catch {}
}

Write-Host ""
if ($resolved) {
    Write-Host "  +--------------------------------------------------+" -ForegroundColor Green
    Write-Host "  |  OK  DNS-over-HTTPS configured and working!      |" -ForegroundColor Green
    Write-Host "  |  google.com -> $($resolvedIP.PadRight(33))|" -ForegroundColor Green
    Write-Host "  +--------------------------------------------------+" -ForegroundColor Green
    Write-Host ""
    Write-Host "  DoH endpoint : https://${ServerAddress}:${DohPort}${DohPath}" -ForegroundColor Cyan
    Write-Host "  Local proxy  : 127.0.0.1:53 (dnscrypt-proxy $version)" -ForegroundColor Cyan
    Write-Host "  Cert         : $thumbprint" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  To revert, run:  .\windows10-doh-setup.ps1 -Uninstall" -ForegroundColor DarkGray
} else {
    Write-Fail "Could not resolve google.com via dnscrypt-proxy."
    Write-Fail "Possible causes:"
    Write-Fail "  - Your IP is not on the server allowlist"
    Write-Fail "  - dnscrypt-proxy failed to start  (check: Get-Service dnscrypt-proxy)"
    Write-Fail "  - Server $ServerAddress is unreachable on port $DohPort"
    Write-Host ""
    Write-Host "  Diagnose: & '$InstallDir\dnscrypt-proxy.exe' -config '$configPath' -check" -ForegroundColor Yellow
    Write-Host "  Service log:   Get-EventLog -LogName Application -Source dnscrypt-proxy -Newest 20" -ForegroundColor Yellow
}
