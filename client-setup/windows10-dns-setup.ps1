#Requires -RunAsAdministrator
<#
.SYNOPSIS
    One-click Windows 10 DNS setup for the private DNS server at 159.89.25.145.

.DESCRIPTION
    Windows 10 does not support built-in DNS-over-HTTPS (DoH).
    This script configures plain DNS (port 53) which works on all Windows versions.

    1. Installs the server's self-signed TLS cert into Local Machine Trusted Root CA.
    2. Sets DNS to 159.89.25.145 on every active adapter.
    3. Verifies resolution.

.NOTES
    Run as Administrator. Compatible with Windows 10 (all builds).
    For encrypted DoH on Windows 10, upgrade to Windows 11 and use windows-doh-setup.ps1.

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
    [int]   $CertPort      = 8443,
    [switch]$Uninstall
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ---------------------------------------------------------------------------
# Embedded certificate (optional — leave empty to fetch live at runtime).
# ---------------------------------------------------------------------------
$CERT_B64 = ""

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
function Write-Step { param([string]$msg) Write-Host "`n==> $msg" -ForegroundColor Cyan  }
function Write-Ok   { param([string]$msg) Write-Host "    OK  $msg" -ForegroundColor Green }
function Write-Warn { param([string]$msg) Write-Host "    !   $msg" -ForegroundColor Yellow }
function Write-Fail { param([string]$msg) Write-Host "    ERR $msg" -ForegroundColor Red  }

function Get-CertFromServer {
    Write-Step "Fetching certificate live from ${ServerAddress}:${CertPort} ..."
    $cb = [System.Net.Security.RemoteCertificateValidationCallback]{
        param($sender, $cert, $chain, $errors) $true
    }
    $tcp = [System.Net.Sockets.TcpClient]::new($ServerAddress, $CertPort)
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

# ---------------------------------------------------------------------------
# Uninstall path
# ---------------------------------------------------------------------------
if ($Uninstall) {
    Write-Step "Uninstalling private DNS configuration ..."
    Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | ForEach-Object {
        $cfg = Get-DnsClientServerAddress -InterfaceIndex $_.ifIndex -AddressFamily IPv4
        if ($cfg.ServerAddresses -contains $ServerAddress) {
            Set-DnsClientServerAddress -InterfaceIndex $_.ifIndex -ResetServerAddresses
            Write-Ok "Reset DNS on '$($_.Name)'"
        }
    }
    Clear-DnsClientCache
    Write-Host "`n--- Uninstall complete ---`n" -ForegroundColor Green
    Write-Warn "Certificate must be removed manually:"
    Write-Warn "  certlm.msc -> Trusted Root CAs -> find CN=$ServerAddress -> Delete"
    exit 0
}

# ---------------------------------------------------------------------------
# STEP 1: Obtain certificate
# ---------------------------------------------------------------------------
Write-Step "Step 1 of 3 — Obtaining server certificate ..."

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

# ---------------------------------------------------------------------------
# STEP 2: Install certificate
# ---------------------------------------------------------------------------
Write-Step "Step 2 of 3 — Installing certificate into Trusted Root CA store ..."
$thumbprint = Import-TrustedRootCert -Cert $cert

# ---------------------------------------------------------------------------
# STEP 3: Set DNS on all active adapters
# ---------------------------------------------------------------------------
Write-Step "Step 3 of 3 — Setting DNS server on all active adapters ..."

$adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
if (-not $adapters) { Write-Warn "No active adapters found — DNS not set" }

foreach ($adapter in $adapters) {
    Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ServerAddress $ServerAddress
    Write-Ok "  [$($adapter.Name)] -> $ServerAddress"
}

Clear-DnsClientCache
Write-Ok "DNS cache flushed"

# ---------------------------------------------------------------------------
# Verify
# ---------------------------------------------------------------------------
Write-Step "Verifying DNS resolution ..."

$resolved = $false
$resolvedIP = ""

try {
    $result = Resolve-DnsName "google.com" -Server $ServerAddress -Type A -ErrorAction Stop |
        Where-Object { $_.QueryType -eq "A" } | Select-Object -First 1
    if ($result -and $result.IPAddress -notmatch "^198\.18\.") {
        $resolved = $true
        $resolvedIP = $result.IPAddress
    }
} catch {
    # Fall back to nslookup (works on all Windows 10 builds)
    try {
        $ns = & nslookup google.com $ServerAddress 2>&1 | Out-String
        if ($ns -match "Address:\s+((?!$ServerAddress)\d+\.\d+\.\d+\.\d+)") {
            $ip = $Matches[1]
            if ($ip -notmatch "^198\.18\.") {
                $resolved = $true
                $resolvedIP = $ip
            }
        }
    } catch {}
}

Write-Host ""
if ($resolved) {
    Write-Host "  +-----------------------------------------------+" -ForegroundColor Green
    Write-Host "  |  OK  DNS configured and working!              |" -ForegroundColor Green
    Write-Host "  |  google.com -> $($resolvedIP.PadRight(30))|" -ForegroundColor Green
    Write-Host "  +-----------------------------------------------+" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Server : $ServerAddress (plain DNS, port 53)" -ForegroundColor Cyan
    Write-Host "  Cert   : $thumbprint" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Note: Windows 10 uses plain DNS (port 53), not encrypted DoH." -ForegroundColor Yellow
    Write-Host "        Upgrade to Windows 11 for DNS-over-HTTPS support." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  To revert, run:  .\windows10-dns-setup.ps1 -Uninstall" -ForegroundColor DarkGray
} else {
    Write-Fail "Could not resolve google.com."
    Write-Fail "Possible causes:"
    Write-Fail "  - Server $ServerAddress is unreachable"
    Write-Fail "  - Your IP is not on the server allowlist"
    Write-Fail "  - Certificate validation failed (try Step 2 manually in certlm.msc)"
}
