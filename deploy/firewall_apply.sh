#!/usr/bin/env bash
# deploy/firewall_apply.sh
# Applies UFW firewall rules for the private-dns-demo stack.
#
# Usage:
#   firewall_apply.sh bootstrap   — full reset: SSH, admin UIs, then DNS rules
#   firewall_apply.sh update      — only refresh DNS/port-53 rules
#
# Environment (read from /opt/private-dns-demo/infra/.env):
#   ADMIN_IPS   — comma-separated IPs always allowed for SSH + admin UIs
#
# Locking: uses /deploy/firewall.lock (flock) so only one instance runs at a time.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ALLOWLIST="${SCRIPT_DIR}/allowlist.txt"
ENV_FILE="${SCRIPT_DIR}/../infra/.env"
LOCK_FILE="${SCRIPT_DIR}/firewall.lock"

MODE="${1:-update}"

# ── Helpers ──────────────────────────────────────────────────
log() { echo "[$(date -u +%H:%M:%S)] firewall_apply.sh: $*"; }
die() { echo "[ERROR] $*" >&2; exit 1; }

# ── Load ADMIN_IPS from .env ─────────────────────────────────
load_admin_ips() {
  if [[ -f "$ENV_FILE" ]]; then
    # shellcheck disable=SC1090
    ADMIN_IPS_RAW=$(grep -E '^ADMIN_IPS=' "$ENV_FILE" | cut -d= -f2- | tr -d '"' | tr -d "'" || true)
  fi
  ADMIN_IPS="${ADMIN_IPS_RAW:-${ADMIN_IPS:-}}"

  if [[ -z "$ADMIN_IPS" ]]; then
    die "ADMIN_IPS is not set. Set it in infra/.env or as an environment variable to prevent SSH lockout."
  fi
}

# ── Strip all existing port-53 rules (by number, in reverse) ─
strip_port53_rules() {
  log "Stripping existing port-53 rules..."
  # Collect rule numbers in reverse order to avoid index shifting
  mapfile -t RULE_NUMS < <(
    ufw status numbered 2>/dev/null \
      | grep -E '53/' \
      | awk -F'[][]' '{print $2}' \
      | sort -rn
  )

  for num in "${RULE_NUMS[@]}"; do
    log "  Deleting rule #${num}"
    ufw --force delete "$num" 2>/dev/null || true
  done
}

# ── Add DNS rules from allowlist.txt ─────────────────────────
add_dns_rules() {
  if [[ ! -f "$ALLOWLIST" ]]; then
    log "No allowlist.txt found at ${ALLOWLIST} — skipping DNS rules"
    return
  fi

  local count=0
  while IFS= read -r ip; do
    ip="${ip// /}"
    [[ -z "$ip" || "$ip" == \#* ]] && continue
    log "  Allowing 53/tcp+udp from ${ip}"
    ufw allow from "$ip" to any port 53 proto tcp comment "dns-allowlist"
    ufw allow from "$ip" to any port 53 proto udp comment "dns-allowlist"
    (( count++ )) || true
  done < "$ALLOWLIST"

  log "Added DNS rules for ${count} IPs"
}

# ── Bootstrap: full UFW setup ────────────────────────────────
do_bootstrap() {
  log "Bootstrap mode: resetting UFW and configuring all rules"
  load_admin_ips

  ufw --force reset
  ufw default deny incoming
  ufw default allow outgoing

  # SSH + admin UI from ADMIN_IPS only
  IFS=',' read -ra ADMINS <<< "$ADMIN_IPS"
  for ip in "${ADMINS[@]}"; do
    ip="${ip// /}"
    [[ -z "$ip" ]] && continue
    log "  Allowing SSH + admin from ${ip}"
    ufw allow from "$ip" to any port 22   proto tcp comment "admin-ssh"
    ufw allow from "$ip" to any port 8080 proto tcp comment "admin-api"
    ufw allow from "$ip" to any port 3000 proto tcp comment "adguard-ui"
    ufw allow from "$ip" to any port 3001 proto tcp comment "grafana"
    ufw allow from "$ip" to any port 9090 proto tcp comment "prometheus"
  done

  add_dns_rules

  ufw --force enable
  log "UFW bootstrap complete"
  ufw status verbose
}

# ── Update: refresh port-53 rules only ───────────────────────
do_update() {
  log "Update mode: refreshing port-53 rules only"
  strip_port53_rules
  add_dns_rules
  log "UFW update complete"
}

# ── Main (with flock) ────────────────────────────────────────
main() {
  case "$MODE" in
    bootstrap) do_bootstrap ;;
    update)    do_update ;;
    *) die "Unknown mode '${MODE}'. Use 'bootstrap' or 'update'." ;;
  esac
}

# Acquire exclusive lock and run
(
  flock -x -w 30 200 || die "Could not acquire firewall lock after 30s"
  main
) 200>"$LOCK_FILE"
