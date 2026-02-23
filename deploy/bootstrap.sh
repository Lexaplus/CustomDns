#!/usr/bin/env bash
# deploy/bootstrap.sh
# Full VPS bootstrap for private-dns-demo.
# Run as root on a fresh Ubuntu 22.04 / 24.04 droplet.
#
# Usage: bash bootstrap.sh

set -euo pipefail

REPO_URL="https://github.com/Lexaplus/CustomDns.git"
REPO_DIR="/opt/private-dns-demo"
INFRA_DIR="${REPO_DIR}/infra"
DEPLOY_DIR="${REPO_DIR}/deploy"

log()  { echo -e "\033[1;34m[bootstrap]\033[0m $*"; }
ok()   { echo -e "\033[1;32m[  OK  ]\033[0m $*"; }
warn() { echo -e "\033[1;33m[ WARN ]\033[0m $*" >&2; }
die()  { echo -e "\033[1;31m[ERROR ]\033[0m $*" >&2; exit 1; }

[[ $EUID -ne 0 ]] && die "Run as root: sudo bash bootstrap.sh"

# ── 1. System packages ────────────────────────────────────────
log "Updating apt and installing base packages..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq \
  curl git ufw apache2-utils ca-certificates \
  gnupg lsb-release net-tools dnsutils openssl
ok "Base packages installed"

# ── 2. Install Docker ─────────────────────────────────────────
if ! command -v docker &>/dev/null; then
  log "Installing Docker..."
  curl -fsSL https://get.docker.com | sh
  systemctl enable --now docker
  ok "Docker installed"
else
  ok "Docker already installed: $(docker --version)"
fi

# ── 3. Disable systemd-resolved (conflicts with port 53) ─────
log "Disabling systemd-resolved to free port 53..."
systemctl stop systemd-resolved 2>/dev/null || true
systemctl disable systemd-resolved 2>/dev/null || true

# Remove the symlink and write a real resolv.conf
rm -f /etc/resolv.conf
cat > /etc/resolv.conf <<'EOF'
nameserver 1.1.1.1
nameserver 8.8.8.8
EOF
ok "systemd-resolved disabled, resolv.conf set to 1.1.1.1"

# ── 4. Kernel parameters ──────────────────────────────────────
log "Setting sysctls..."
cat > /etc/sysctl.d/99-dns-demo.conf <<'EOF'
net.ipv4.ip_forward = 1
net.core.rmem_max = 4194304
net.core.wmem_max = 4194304
net.ipv4.udp_rmem_min = 8192
net.ipv4.udp_wmem_min = 8192
EOF
sysctl --system -q
ok "Sysctls applied"

# ── 5. Clone / update repo ────────────────────────────────────
if [[ -d "${REPO_DIR}/.git" ]]; then
  log "Repo already exists — pulling latest..."
  git -C "$REPO_DIR" pull --ff-only
else
  log "Cloning repo to ${REPO_DIR}..."
  git clone "$REPO_URL" "$REPO_DIR"
fi
ok "Repo ready at ${REPO_DIR}"

# Make deploy scripts executable
chmod +x "${DEPLOY_DIR}"/*.sh

# ── 6. Set up .env ───────────────────────────────────────────
ENV_FILE="${INFRA_DIR}/.env"
if [[ ! -f "$ENV_FILE" ]]; then
  cp "${INFRA_DIR}/.env.example" "$ENV_FILE"
  warn ".env created from .env.example — you MUST edit it now!"
  warn "Open ${ENV_FILE} in your editor and set:"
  warn "  ADMIN_IPS, POSTGRES_PASSWORD, ADMIN_API_TOKEN,"
  warn "  TELEGRAM_BOT_TOKEN, ADMIN_IDS, GF_ADMIN_PASSWORD"
  echo ""
  read -r -p "Press ENTER after editing .env to continue..." _
else
  ok ".env already exists — skipping"
fi

# Quick validation
# shellcheck disable=SC1090
source "$ENV_FILE"
[[ -z "${ADMIN_IPS:-}" ]] && die "ADMIN_IPS is not set in .env"
[[ "${POSTGRES_PASSWORD:-}" == "changeme_strong_password" ]] && \
  warn "POSTGRES_PASSWORD is still the default — change it!"
[[ "${ADMIN_API_TOKEN:-}" == "changeme_admin_api_token" ]] && \
  warn "ADMIN_API_TOKEN is still the default — change it!"

# ── 7. Generate AdGuard bcrypt password hash ──────────────────
log "Configuring AdGuard Home password..."
ADGUARD_YAML="${INFRA_DIR}/adguard/conf/AdGuardHome.yaml"

read -r -s -p "Enter AdGuard admin password (will be bcrypt-hashed): " AG_PASS
echo ""
[[ -z "$AG_PASS" ]] && die "Password cannot be empty"

# Use htpasswd -B to generate bcrypt hash (output: user:hash, take the hash part)
HASH=$(htpasswd -nbB admin "$AG_PASS" | cut -d: -f2)

# Escape for sed (AdGuard uses $2y$ prefix; escape $ signs)
HASH_ESCAPED=$(printf '%s\n' "$HASH" | sed 's/[&/\]/\\&/g')

sed -i "s|password:.*placeholder_replace_via_bootstrap.*|password: \"${HASH_ESCAPED}\"|g" "$ADGUARD_YAML"

# Also update ADGUARD_ADMIN_PASSWORD_HASH in .env for reference
sed -i "s|^ADGUARD_ADMIN_PASSWORD_HASH=.*|ADGUARD_ADMIN_PASSWORD_HASH=${HASH_ESCAPED}|" "$ENV_FILE"

ok "AdGuard password hash configured"

# ── 7.5. Generate self-signed TLS cert for AdGuard DoH ───────
CERT_DIR="${INFRA_DIR}/adguard/certs"
CERT_FILE="${CERT_DIR}/agh.crt"
KEY_FILE="${CERT_DIR}/agh.key"
SERVER_IP=$(hostname -I | awk '{print $1}')

mkdir -p "$CERT_DIR"

if [[ ! -f "$CERT_FILE" ]]; then
  log "Generating self-signed TLS cert (valid 10 years, SAN=IP:${SERVER_IP})..."
  openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$KEY_FILE" \
    -out    "$CERT_FILE" \
    -days   3650 \
    -subj   "/CN=${SERVER_IP}" \
    -addext "subjectAltName=IP:${SERVER_IP}" \
    2>/dev/null
  chmod 644 "$CERT_FILE"
  chmod 600 "$KEY_FILE"
  # Copy to /tmp for easy retrieval (base64 for Windows client-setup script)
  cp "$CERT_FILE" /tmp/agh.crt
  ok "TLS cert generated at ${CERT_FILE}"
  log "SHA-256 fingerprint: $(openssl x509 -in "$CERT_FILE" -noout -fingerprint -sha256 | cut -d= -f2)"
  echo ""
  log "--- WINDOWS CLIENT SETUP ---"
  log "Run client-setup/windows-doh-setup.ps1 on Windows 11 as Administrator."
  log "The script auto-fetches the cert, or you can pre-embed it:"
  log "  Base64 cert (copy into \$CERT_B64 in the .ps1):"
  base64 -w0 "$CERT_FILE"
  echo ""
else
  ok "TLS cert already exists at ${CERT_FILE} — skipping"
fi

# ── 8. Apply firewall (bootstrap mode) ───────────────────────
log "Applying UFW firewall rules..."
bash "${DEPLOY_DIR}/firewall_apply.sh" bootstrap
ok "Firewall configured"

# ── 9. Pull images and start stack ───────────────────────────
log "Starting Docker Compose stack..."
cd "$INFRA_DIR"
docker compose pull --quiet
docker compose up -d --remove-orphans

ok "Stack started"

# ── 10. Health check ─────────────────────────────────────────
log "Waiting for admin-api to become healthy (up to 60s)..."
for i in $(seq 1 12); do
  if curl -sf "http://127.0.0.1:8080/health" > /dev/null 2>&1; then
    ok "admin-api is up!"
    break
  fi
  sleep 5
  [[ $i -eq 12 ]] && warn "admin-api not responding after 60s — check 'docker compose logs admin-api'"
done

echo ""
echo "============================================================"
echo "  private-dns-demo is running!"
echo "------------------------------------------------------------"
echo "  AdGuard UI:    http://$(hostname -I | awk '{print $1}'):3000"
echo "  Admin API:     http://$(hostname -I | awk '{print $1}'):8080/health"
echo "  Grafana:       http://$(hostname -I | awk '{print $1}'):3001"
echo "  Prometheus:    http://127.0.0.1:9090 (localhost only)"
echo "============================================================"
echo ""
echo "Next steps:"
echo "  1. Add your IP: curl -X POST http://SERVER_IP:8080/allowed-ips \\"
echo "       -H 'x-admin-token: YOUR_TOKEN' \\"
echo "       -H 'Content-Type: application/json' \\"
echo "       -d '{\"ip\":\"YOUR_IP\",\"label\":\"My laptop\"}'"
echo "  2. Set your laptop DNS to $(hostname -I | awk '{print $1}')"
echo "  3. Run smoke tests: bash ${DEPLOY_DIR}/smoke_test.sh $(hostname -I | awk '{print $1}') YOUR_TOKEN"
echo ""
