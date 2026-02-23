#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Verifies that the private DoH DNS setup is working correctly on Windows 11.

.DESCRIPTION
    Runs 6 checks and prints a pass/fail summary:
      1. DNS server set to 159.89.25.145 on at least one active adapter
      2. Self-signed cert present in Trusted Root CA store
      3. DoH template registered in Windows DNS client
      4. DoH endpoint reachable over HTTPS (port 8443)
      5. DNS resolves via the private server (returns a real IP)
      6. Non-allowlisted behavior check (optional, informational)

.NOTES
    Run as Administrator. No parameters needed.
#>

[CmdletBinding()]
param(
    [string]$ServerAddress = "159.89.25.145",
    [string]$DohTemplate   = "https://159.89.25.145:8443/dns-query"
)

$PASS = 0
$FAIL = 0
$WARN = 0

function Write-Pass { param([string]$msg) Write-Host "  [PASS] $msg" -ForegroundColor Green;  $script:PASS++ }
function Write-Fail { param([string]$msg) Write-Host "  [FAIL] $msg" -ForegroundColor Red;    $script:FAIL++ }
function Write-Warn { param([string]$msg) Write-Host "  [WARN] $msg" -ForegroundColor Yellow; $script:WARN++ }
function Write-Step { param([string]$msg) Write-Host "`n--- $msg" -ForegroundColor Cyan }

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  Private DoH DNS — Verification Script" -ForegroundColor Cyan
Write-Host "  Server : $ServerAddress" -ForegroundColor Cyan
Write-Host "  Template: $DohTemplate" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

# ── Check 1: DNS server set on active adapter ────────────────
Write-Step "1. DNS server address on active adapters"
$adaptersWithOurDns = Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | ForEach-Object {
    $cfg = Get-DnsClientServerAddress -InterfaceIndex $_.ifIndex -AddressFamily IPv4
    if ($cfg.ServerAddresses -contains $ServerAddress) { $_.Name }
}

if ($adaptersWithOurDns) {
    Write-Pass "DNS set to $ServerAddress on: $($adaptersWithOurDns -join ', ')"
} else {
    Write-Fail "No active adapter has DNS set to $ServerAddress"
    Write-Host "         Fix: Run windows-doh-setup.ps1 as Administrator" -ForegroundColor DarkGray
}

# ── Check 2: Certificate in Trusted Root CA store ────────────
Write-Step "2. Self-signed certificate in Trusted Root CA store"
$cert = Get-ChildItem Cert:\LocalMachine\Root |
    Where-Object { $_.Subject -like "*$ServerAddress*" -or $_.Issuer -like "*$ServerAddress*" } |
    Select-Object -First 1

if ($cert) {
    $daysLeft = ($cert.NotAfter - (Get-Date)).Days
    Write-Pass "Cert found  Subject=$($cert.Subject)  Expires=$($cert.NotAfter.ToString('yyyy-MM-dd')) (${daysLeft}d)"
} else {
    Write-Fail "No cert for $ServerAddress found in LocalMachine\Root"
    Write-Host "         Fix: Run windows-doh-setup.ps1 as Administrator" -ForegroundColor DarkGray
}

# ── Check 3: DoH template registered ─────────────────────────
Write-Step "3. DoH template registered in Windows DNS client"
try {
    $dohEntry = Get-DnsClientDohServerAddress -ErrorAction Stop |
        Where-Object { $_.ServerAddress -eq $ServerAddress }
    if ($dohEntry) {
        Write-Pass "DoH template registered: $($dohEntry.DohTemplate)  AutoUpgrade=$($dohEntry.AutoUpgrade)  FallbackToUdp=$($dohEntry.AllowFallbackToUdp)"
    } else {
        Write-Fail "No DoH template registered for $ServerAddress"
        Write-Host "         Fix: Run windows-doh-setup.ps1 as Administrator" -ForegroundColor DarkGray
    }
} catch {
    Write-Warn "Get-DnsClientDohServerAddress not available — requires Windows 11 22H2+"
}

# ── Check 4: DoH endpoint reachable ──────────────────────────
Write-Step "4. DoH endpoint reachable (HTTPS port 8443)"
try {
    $cb = [System.Net.Security.RemoteCertificateValidationCallback]{ $true }
    $tcp = [System.Net.Sockets.TcpClient]::new($ServerAddress, 8443)
    $ssl = [System.Net.Security.SslStream]::new($tcp.GetStream(), $false, $cb)
    try {
        $ssl.AuthenticateAsClient($ServerAddress)
        $remoteCert = $ssl.RemoteCertificate
        Write-Pass "Port 8443 open and TLS handshake successful  CN=$($remoteCert.Subject)"
    } finally {
        $ssl.Dispose(); $tcp.Dispose()
    }
} catch {
    Write-Fail "Cannot reach ${ServerAddress}:8443 — $_"
    Write-Host "         Possible causes: server down, IP not allowlisted, firewall blocking 8443" -ForegroundColor DarkGray
}

# ── Check 5: DNS resolution returns a real IP ─────────────────
Write-Step "5. DNS resolution via private server"
try {
    $result = Resolve-DnsName "google.com" -Server $ServerAddress -Type A -ErrorAction Stop |
        Where-Object { $_.QueryType -eq "A" } |
        Select-Object -First 1

    if ($result -and $result.IPAddress -notmatch "^198\.18\.") {
        Write-Pass "google.com resolved to $($result.IPAddress) via $ServerAddress"
    } elseif ($result) {
        Write-Fail "Resolved to NXDOMAIN-mapped address $($result.IPAddress) — your IP is likely not allowlisted"
        Write-Host "         Fix: ask the admin to add your IP, or use the Telegram bot: /addip YOUR_IP" -ForegroundColor DarkGray
    } else {
        Write-Fail "No A record returned"
    }
} catch {
    Write-Fail "Resolve-DnsName failed: $_"
    Write-Host "         Your IP may not be on the server allowlist" -ForegroundColor DarkGray
}

# ── Check 6: What's my public IP (informational) ─────────────
Write-Step "6. Your current public IP (must be allowlisted)"
try {
    $myIp = (Resolve-DnsName "myip.opendns.com" -Server "resolver1.opendns.com" -Type A -ErrorAction Stop |
        Where-Object { $_.QueryType -eq "A" } | Select-Object -First 1).IPAddress
    if ($myIp) {
        Write-Warn "Your public IP is $myIp — make sure this is in the server allowlist"
        Write-Host "         Add it: curl -X POST http://${ServerAddress}:8080/allowed-ips -H 'x-admin-token: TOKEN' -H 'Content-Type: application/json' -d '{`"ip`":`"$myIp`",`"label`":`"my-windows-pc`"}'" -ForegroundColor DarkGray
    }
} catch {
    Write-Warn "Could not determine public IP (no internet via fallback DNS?)"
}

# ── Summary ───────────────────────────────────────────────────
Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
if ($FAIL -eq 0) {
    Write-Host "  ALL CHECKS PASSED ($PASS passed, $WARN warnings)" -ForegroundColor Green
    Write-Host "  Your machine is using the private DoH DNS server." -ForegroundColor Green
} else {
    Write-Host "  $FAIL check(s) FAILED  |  $PASS passed  |  $WARN warnings" -ForegroundColor Red
    Write-Host "  Run windows-doh-setup.ps1 as Administrator to fix setup issues." -ForegroundColor Yellow
}
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

exit $FAIL
