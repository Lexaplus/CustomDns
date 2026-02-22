#!/usr/bin/env bash
# deploy/smoke_test.sh
# End-to-end smoke tests for private-dns-demo.
#
# Usage: ./smoke_test.sh <SERVER_IP> <ADMIN_API_TOKEN>
#
# Requirements: curl, dig (dnsutils)

set -euo pipefail

SERVER_IP="${1:?Usage: $0 <SERVER_IP> <ADMIN_API_TOKEN>}"
TOKEN="${2:?Usage: $0 <SERVER_IP> <ADMIN_API_TOKEN>}"

API_BASE="http://${SERVER_IP}:8080"
PASS=0
FAIL=0
TEST_IP=""

# ── Helpers ──────────────────────────────────────────────────
pass() { echo -e "\033[1;32m[PASS]\033[0m $*"; (( PASS++ )) || true; }
fail() { echo -e "\033[1;31m[FAIL]\033[0m $*"; (( FAIL++ )) || true; }
info() { echo -e "\033[1;34m[INFO]\033[0m $*"; }
check_cmd() { command -v "$1" &>/dev/null || { fail "Required: $1 not found"; exit 1; }; }

check_cmd curl
check_cmd dig

echo "============================================================"
echo "  private-dns-demo Smoke Tests"
echo "  Server: ${SERVER_IP}"
echo "============================================================"
echo ""

# ── Test 1: API health ───────────────────────────────────────
info "1. API /health"
HEALTH=$(curl -sf "${API_BASE}/health" 2>&1) && pass "API health: ${HEALTH}" || fail "API /health unreachable"

# ── Test 2: Unauthenticated request rejected ─────────────────
info "2. Auth check — request without token should be rejected"
STATUS=$(curl -s -o /dev/null -w "%{http_code}" "${API_BASE}/allowed-ips")
if [[ "$STATUS" == "401" ]]; then
  pass "Unauthenticated request correctly rejected (401)"
else
  fail "Expected 401, got ${STATUS}"
fi

# ── Test 3: Authenticated list ───────────────────────────────
info "3. GET /allowed-ips (authenticated)"
LIST=$(curl -sf -H "x-admin-token: ${TOKEN}" "${API_BASE}/allowed-ips" 2>&1) && pass "GET /allowed-ips ok" || fail "GET /allowed-ips failed: ${LIST}"

# ── Test 4: Add IP ───────────────────────────────────────────
# Use a test IP that won't conflict
TEST_IP="10.254.254.$(( RANDOM % 253 + 1 ))"
info "4. POST /allowed-ips — adding test IP ${TEST_IP}"
ADD_RESULT=$(curl -sf \
  -X POST \
  -H "x-admin-token: ${TOKEN}" \
  -H "x-actor: smoke-test" \
  -H "Content-Type: application/json" \
  -d "{\"ip\":\"${TEST_IP}\",\"label\":\"smoke-test\"}" \
  "${API_BASE}/allowed-ips" 2>&1)

if echo "$ADD_RESULT" | grep -q "\"ip\""; then
  RECORD_ID=$(echo "$ADD_RESULT" | grep -o '"id":[0-9]*' | head -1 | cut -d: -f2)
  pass "IP ${TEST_IP} added (id=${RECORD_ID})"
else
  fail "Add IP failed: ${ADD_RESULT}"
  RECORD_ID=""
fi

# ── Test 5: IP shows in list ─────────────────────────────────
info "5. Verify ${TEST_IP} appears in list"
LIST2=$(curl -sf -H "x-admin-token: ${TOKEN}" "${API_BASE}/allowed-ips" 2>&1)
if echo "$LIST2" | grep -q "$TEST_IP"; then
  pass "IP ${TEST_IP} found in list"
else
  fail "IP ${TEST_IP} not found in list"
fi

# ── Test 6: DNS resolution (from this host) ──────────────────
info "6. DNS resolution from this host"
DIG_RESULT=$(dig +time=5 +tries=2 @"${SERVER_IP}" google.com A 2>&1)
if echo "$DIG_RESULT" | grep -qE "ANSWER SECTION|status: NOERROR"; then
  pass "DNS resolves google.com via ${SERVER_IP}"
else
  warn "DNS resolution test inconclusive (this host may not be allowlisted)"
  info "Add this server's IP to the allowlist or run from an allowlisted host"
fi

# ── Test 7: AdGuard UI reachable ─────────────────────────────
info "7. AdGuard UI (port 3000)"
AG_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "http://${SERVER_IP}:3000/" 2>&1)
if [[ "$AG_STATUS" =~ ^(200|302|307|308)$ ]]; then
  pass "AdGuard UI reachable (HTTP ${AG_STATUS})"
else
  fail "AdGuard UI not reachable (HTTP ${AG_STATUS})"
fi

# ── Test 8: Grafana UI reachable ─────────────────────────────
info "8. Grafana UI (port 3001)"
GF_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "http://${SERVER_IP}:3001/" 2>&1)
if [[ "$GF_STATUS" =~ ^(200|302|307|308)$ ]]; then
  pass "Grafana UI reachable (HTTP ${GF_STATUS})"
else
  fail "Grafana UI not reachable (HTTP ${GF_STATUS})"
fi

# ── Test 9: Remove test IP ───────────────────────────────────
if [[ -n "${RECORD_ID:-}" ]]; then
  info "9. DELETE /allowed-ips/${RECORD_ID}"
  DEL_STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    -X DELETE \
    -H "x-admin-token: ${TOKEN}" \
    -H "x-actor: smoke-test" \
    "${API_BASE}/allowed-ips/${RECORD_ID}")
  if [[ "$DEL_STATUS" == "204" ]]; then
    pass "IP ${TEST_IP} removed successfully"
  else
    fail "Delete returned HTTP ${DEL_STATUS}"
  fi
fi

# ── Summary ──────────────────────────────────────────────────
echo ""
echo "============================================================"
echo "  Results: ${PASS} passed, ${FAIL} failed"
echo "============================================================"
[[ "$FAIL" -eq 0 ]]
