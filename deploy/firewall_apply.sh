#!/usr/bin/env bash
# deploy/firewall_apply.sh
# Applies firewall rules for the private-dns-demo stack.
#
# Usage:
#   firewall_apply.sh bootstrap   — full reset: SSH, admin UIs, then DNS rules
#   firewall_apply.sh update      — only refresh DNS/port-53 rules
#
# Port 53 is controlled via the iptables DOCKER-USER chain (not UFW) because
# Docker publishes ports by inserting iptables rules that bypass UFW's INPUT chain.
# DOCKER-USER is the correct chain for filtering Docker-forwarded traffic.
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
    ADMIN_IPS_RAW=$(grep -E '^ADMIN_IPS=' "$ENV_FILE" | cut -d= -f2- | tr -d '"' | tr -d "'" || true)
  fi
  ADMIN_IPS="${ADMIN_IPS_RAW:-${ADMIN_IPS:-}}"

  if [[ -z "$ADMIN_IPS" ]]; then
    die "ADMIN_IPS is not set. Set it in infra/.env to prevent SSH lockout."
  fi
}

# ── DOCKER-USER chain: flush all port-53 and port-8443 rules ─
flush_docker_dns_rules() {
  log "Flushing DOCKER-USER port-53 / port-8443 rules..."
  # Ensure chain exists (Docker creates it on first run)
  iptables -N DOCKER-USER 2>/dev/null || true

  for PORT in 53 8443; do
    # TCP
    while iptables -L DOCKER-USER --line-numbers -n 2>/dev/null | grep -qE "tcp.*dpt:${PORT}"; do
      LINENUM=$(iptables -L DOCKER-USER --line-numbers -n 2>/dev/null \
        | grep -E "tcp.*dpt:${PORT}" | head -1 | awk '{print $1}')
      [[ -z "$LINENUM" ]] && break
      iptables -D DOCKER-USER "$LINENUM" 2>/dev/null || break
    done
    # UDP (port 53 only)
    if [[ "$PORT" == "53" ]]; then
      while iptables -L DOCKER-USER --line-numbers -n 2>/dev/null | grep -qE "udp.*dpt:53"; do
        LINENUM=$(iptables -L DOCKER-USER --line-numbers -n 2>/dev/null \
          | grep -E "udp.*dpt:53" | head -1 | awk '{print $1}')
        [[ -z "$LINENUM" ]] && break
        iptables -D DOCKER-USER "$LINENUM" 2>/dev/null || break
      done
    fi
  done

  log "DOCKER-USER port-53 / port-8443 rules cleared"
}

# ── DOCKER-USER chain: add allowlist + default DROP for 53+8443
apply_docker_dns_rules() {
  log "Applying DOCKER-USER port-53 / port-8443 rules..."

  # Default DROP rules at the END (ALLOWs are inserted before them)
  iptables -A DOCKER-USER -p tcp --dport 53   -j DROP
  iptables -A DOCKER-USER -p udp --dport 53   -j DROP
  iptables -A DOCKER-USER -p tcp --dport 8443 -j DROP
  log "  Default DROP for ports 53 and 8443 added"

  if [[ ! -f "$ALLOWLIST" ]]; then
    log "No allowlist.txt — ports 53 and 8443 blocked for all IPs"
    return
  fi

  local count=0
  while IFS= read -r ip; do
    ip="${ip// /}"
    [[ -z "$ip" || "$ip" == \#* ]] && continue
    log "  Allowing 53/tcp+udp and 8443/tcp from ${ip}"
    # Insert RETURN rules BEFORE the DROP rules (at position 1)
    iptables -I DOCKER-USER 1 -p udp --dport 53   -s "$ip" -j RETURN
    iptables -I DOCKER-USER 1 -p tcp --dport 53   -s "$ip" -j RETURN
    iptables -I DOCKER-USER 1 -p tcp --dport 8443 -s "$ip" -j RETURN
    (( count++ )) || true
  done < "$ALLOWLIST"

  log "Added ALLOW rules for ${count} IPs on ports 53 + 8443"
}

# ── Bootstrap: full UFW setup ────────────────────────────────
do_bootstrap() {
  log "Bootstrap mode: resetting UFW and configuring all rules"
  load_admin_ips

  ufw --force reset
  ufw default deny incoming
  ufw default allow outgoing

  # SSH + admin UIs from ADMIN_IPS only (UFW handles non-Docker ports fine)
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

  ufw --force enable
  log "UFW bootstrap complete"
  ufw status verbose

  # Apply DOCKER-USER port-53 rules
  flush_docker_dns_rules
  apply_docker_dns_rules
}

# ── Update: refresh port-53 rules only ───────────────────────
do_update() {
  log "Update mode: refreshing port-53 rules only (DOCKER-USER chain)"
  flush_docker_dns_rules
  apply_docker_dns_rules
  log "Update complete"
}

# ── Main (with flock) ────────────────────────────────────────
main() {
  case "$MODE" in
    bootstrap) do_bootstrap ;;
    update)    do_update ;;
    *) die "Unknown mode '${MODE}'. Use 'bootstrap' or 'update'." ;;
  esac
}

(
  flock -x -w 30 200 || die "Could not acquire firewall lock after 30s"
  main
) 200>"$LOCK_FILE"
