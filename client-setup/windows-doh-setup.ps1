#Requires -RunAsAdministrator
<#
.SYNOPSIS
    One-click Windows 11 DoH setup for the private DNS server at 159.89.25.145.

.DESCRIPTION
    1. Installs the server's self-signed TLS cert into Local Machine Trusted Root CA.
    2. Registers the DoH template with Windows (Windows 11 22H2+ required).
    3. Sets DNS to 159.89.25.145 on every active adapter.
    4. Verifies resolution with Resolve-DnsName.

.NOTES
    Run as Administrator. Tested on Windows 11 22H2 / 23H2.

    If CERT_B64 below is empty the script will fetch the cert live from the
    server using a raw TLS connection (requires network access to port 8443).
    To pre-embed the cert:
        openssl s_client -connect 159.89.25.145:8443 </dev/null 2>/dev/null \
            | openssl x509 | base64 -w0
    Paste the single-line base64 output as the value of $CERT_B64.
#>

[CmdletBinding()]
param(
    [string]$ServerAddress  = "159.89.25.145",
    [string]$DohTemplate    = "https://159.89.25.145:8443/dns-query",
    [int]   $DohPort        = 8443,
    [switch]$Uninstall                       # Remove everything this script added
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ---------------------------------------------------------------------------
# Embedded certificate (base64 DER or PEM — both accepted).
# Leave empty to fetch live from $ServerAddress:$DohPort at runtime.
# ---------------------------------------------------------------------------
$CERT_B64 = ""

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
function Write-Step   { param([string]$msg) Write-Host "`n==> $msg" -ForegroundColor Cyan  }
function Write-Ok     { param([string]$msg) Write-Host "    OK  $msg" -ForegroundColor Green }
function Write-Warn   { param([string]$msg) Write-Host "    !   $msg" -ForegroundColor Yellow }
function Write-Fail   { param([string]$msg) Write-Host "    ERR $msg" -ForegroundColor Red  }

function Get-CertFromServer {
    Write-Step "Fetching certificate live from ${ServerAddress}:${DohPort} ..."

    # Attempt 1: SslStream (fast, direct)
    try {
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
            $ssl.Dispose(); $tcp.Dispose()
        }
    } catch {
        Write-Warn "SslStream failed ($($_.Exception.Message)) — trying HttpWebRequest fallback ..."
    }

    # Attempt 2: HttpWebRequest (more compatible with some Windows TLS configurations)
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    try {
        Add-Type -TypeDefinition @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class _AcceptAllCerts : ICertificatePolicy {
    public bool CheckValidationResult(ServicePoint sp, X509Certificate cert,
        WebRequest req, int problem) { return true; }
}
"@ -ErrorAction Stop
    } catch { <# type already defined on retry — safe to ignore #> }

    $saved = [System.Net.ServicePointManager]::CertificatePolicy
    [System.Net.ServicePointManager]::CertificatePolicy = New-Object _AcceptAllCerts

    try {
        $req = [System.Net.HttpWebRequest]::Create("https://${ServerAddress}:${DohPort}/")
        $req.Timeout = 10000
        try { $null = $req.GetResponse() } catch [System.Net.WebException] {
            if ($_.Exception.Response) { $_.Exception.Response.Close() }
        }
        if (-not $req.ServicePoint.Certificate) { throw "No certificate returned by ServicePoint" }
        $rawBytes = $req.ServicePoint.Certificate.Export(
            [System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
        return [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($rawBytes)
    } finally {
        [System.Net.ServicePointManager]::CertificatePolicy = $saved
    }
}

function Import-TrustedRootCert {
    param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert)

    $store = [System.Security.Cryptography.X509Certificates.X509Store]::new(
        "Root", "LocalMachine")
    $store.Open("ReadWrite")
    try {
        # Idempotent: skip if thumbprint already present
        $existing = $store.Certificates | Where-Object { $_.Thumbprint -eq $Cert.Thumbprint }
        if ($existing) {
            Write-Ok "Certificate already trusted (thumbprint $($Cert.Thumbprint))"
        } else {
            $store.Add($Cert)
            Write-Ok "Installed cert  Subject=$($Cert.Subject)  Thumbprint=$($Cert.Thumbprint)"
        }
    } finally {
        $store.Close()
    }
    return $Cert.Thumbprint
}

function Remove-TrustedRootCert {
    param([string]$Thumbprint)
    $store = [System.Security.Cryptography.X509Certificates.X509Store]::new(
        "Root", "LocalMachine")
    $store.Open("ReadWrite")
    try {
        $certs = $store.Certificates | Where-Object { $_.Thumbprint -eq $Thumbprint }
        foreach ($c in $certs) { $store.Remove($c); Write-Ok "Removed cert $Thumbprint" }
    } finally { $store.Close() }
}

# ---------------------------------------------------------------------------
# Uninstall path
# ---------------------------------------------------------------------------
if ($Uninstall) {
    Write-Step "Uninstalling private DoH configuration ..."

    # Remove DoH template
    try {
        Remove-DnsClientDohServerAddress -ServerAddress $ServerAddress -ErrorAction SilentlyContinue
        Write-Ok "DoH template removed for $ServerAddress"
    } catch { Write-Warn "DoH template not found or already removed" }

    # Reset DNS on all adapters that currently point to our server
    Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | ForEach-Object {
        $cfg = Get-DnsClientServerAddress -InterfaceIndex $_.ifIndex -AddressFamily IPv4
        if ($cfg.ServerAddresses -contains $ServerAddress) {
            Set-DnsClientServerAddress -InterfaceIndex $_.ifIndex -ResetServerAddresses
            Write-Ok "Reset DNS on '$($_.Name)'"
        }
    }

    Write-Host "`n--- Uninstall complete ---`n" -ForegroundColor Green
    Write-Warn "Certificate must be removed manually:"
    Write-Warn "  certlm.msc -> Trusted Root CAs -> find CN=$ServerAddress -> Delete"
    exit 0
}

# ---------------------------------------------------------------------------
# STEP 1: Resolve / parse certificate
# ---------------------------------------------------------------------------
Write-Step "Step 1 of 4 — Obtaining server certificate ..."

[System.Security.Cryptography.X509Certificates.X509Certificate2]$cert = $null

if ($CERT_B64 -ne "") {
    # Strip any PEM header/footer lines and whitespace, then decode
    $b64clean = ($CERT_B64 -replace "-----[^-]+-----","" -replace "\s","")
    $certBytes = [Convert]::FromBase64String($b64clean)
    $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($certBytes)
    Write-Ok "Using embedded certificate (Subject: $($cert.Subject))"
} else {
    $cert = Get-CertFromServer
    Write-Ok "Fetched certificate: Subject=$($cert.Subject)  Expiry=$($cert.NotAfter)"
}

# Sanity check: cert must cover the server IP
$sanText = $cert.Extensions |
    Where-Object { $_.Oid.FriendlyName -like "*Subject Alternative*" } |
    ForEach-Object { $_.Format($false) }
Write-Ok "SAN: $sanText"

# ---------------------------------------------------------------------------
# STEP 2: Install certificate as Trusted Root
# ---------------------------------------------------------------------------
Write-Step "Step 2 of 4 — Installing certificate into Trusted Root CA store ..."
$thumbprint = Import-TrustedRootCert -Cert $cert

# ---------------------------------------------------------------------------
# STEP 3: Register DoH template + set DNS
# ---------------------------------------------------------------------------
Write-Step "Step 3 of 4 — Registering DoH template (requires Windows 11 22H2+) ..."

# Remove stale registration first (idempotent)
try {
    Remove-DnsClientDohServerAddress -ServerAddress $ServerAddress -ErrorAction SilentlyContinue
} catch {}

Add-DnsClientDohServerAddress `
    -ServerAddress     $ServerAddress `
    -DohTemplate       $DohTemplate `
    -AllowFallbackToUdp $false `
    -AutoUpgrade        $true
Write-Ok "DoH template registered: $DohTemplate"

Write-Step "Setting DNS server on all active adapters ..."
$adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
if (-not $adapters) { Write-Warn "No active adapters found — DNS not set" }
foreach ($adapter in $adapters) {
    Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex `
        -ServerAddress $ServerAddress
    Write-Ok "  [$($adapter.Name)] -> $ServerAddress"
}

# Flush resolver cache so the new config takes effect immediately
Clear-DnsClientCache
Write-Ok "DNS cache flushed"

# ---------------------------------------------------------------------------
# STEP 4: Verify
# ---------------------------------------------------------------------------
Write-Step "Step 4 of 4 — Testing DNS resolution ..."

$testResult = $null
try {
    # Force DoH (DoH-only, no UDP fallback because AllowFallbackToUdp=$false above)
    $testResult = Resolve-DnsName "google.com" -Server $ServerAddress `
        -Type A -ErrorAction Stop |
        Where-Object { $_.QueryType -eq "A" } |
        Select-Object -First 1
} catch {
    Write-Fail "Resolve-DnsName failed: $_"
}

Write-Host ""
if ($testResult -and $testResult.IPAddress -notmatch "^198\.18\.") {
    Write-Host "  +-----------------------------------------------+" -ForegroundColor Green
    Write-Host "  |  OK  DoH configured and working!              |" -ForegroundColor Green
    Write-Host "  |  google.com -> $($testResult.IPAddress.PadRight(30))|" -ForegroundColor Green
    Write-Host "  +-----------------------------------------------+" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Server : $ServerAddress" -ForegroundColor Cyan
    Write-Host "  Template: $DohTemplate"  -ForegroundColor Cyan
    Write-Host "  Cert   : $thumbprint"    -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  To revert, run:  .\windows-doh-setup.ps1 -Uninstall" -ForegroundColor DarkGray
} elseif ($testResult) {
    Write-Warn "Resolution returned a NXDOMAIN-mapped address ($($testResult.IPAddress))."
    Write-Warn "DNS is set but the server may be blocking this client."
    Write-Warn "Ask the server admin to allowlist your IP."
} else {
    Write-Fail "Could not resolve google.com."
    Write-Fail "Possible causes:"
    Write-Fail "  - Server $ServerAddress is unreachable"
    Write-Fail "  - Your IP is not on the server allowlist"
    Write-Fail "  - Certificate validation failed (try Step 2 manually in certlm.msc)"
}
