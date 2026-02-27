#!/usr/bin/env bash
# =============================================================================
# cctv-diag.sh — Camera Box On-Demand Diagnostic & Support Bundle Generator
# Version: 1.0.0
# Safe/read-only by default. No changes made to the system.
# =============================================================================
set -uo pipefail
IFS=$'\n\t'

# ---------------------------------------------------------------------------
# VERSION & METADATA
# ---------------------------------------------------------------------------
SCRIPT_VERSION="1.0.0"
SCRIPT_NAME="cctv-diag"
STARTED_AT="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
STARTED_EPOCH="$(date +%s)"

# ---------------------------------------------------------------------------
# COLOUR CODES (auto-disable when not a tty)
# ---------------------------------------------------------------------------
if [[ -t 1 ]] && [[ "${TERM:-dumb}" != "dumb" ]] && tput colors &>/dev/null 2>&1; then
  C_RED=$'\e[0;31m';   C_AMBER=$'\e[0;33m'; C_GREEN=$'\e[0;32m'
  C_CYAN=$'\e[0;36m';  C_BOLD=$'\e[1m';      C_DIM=$'\e[2m'
  C_RESET=$'\e[0m'
else
  C_RED=''; C_AMBER=''; C_GREEN=''; C_CYAN=''; C_BOLD=''; C_DIM=''; C_RESET=''
fi

# ---------------------------------------------------------------------------
# DEFAULTS & THRESHOLDS (overridable via /etc/cctv-diag.conf)
# ---------------------------------------------------------------------------
CONF_FILE="/etc/cctv-diag.conf"
DISK_AMBER=85          # %
DISK_RED=95            # %
INODE_AMBER=80         # %
INODE_RED=90           # %
SNAP_AMBER_DAYS=14
SNAP_RED_DAYS=30
NX_PORTS="7001,7002,7004"        # expected listening ports (comma-sep)
NX_SERVICE_PATTERNS=("networkoptix-mediaserver" "nx-mediaserver" "mediaserver" "networkoptix")
NX_LOG_PATHS=(
  "/opt/networkoptix/mediaserver/var/log"
  "/opt/networkoptix-mediaserver/var/log"
  "/opt/networkoptix/var/log"
  "/opt/nx_witness/var/log"
  "/var/log/networkoptix"
  "/home/networkoptix/.config/nx_ini"
)
CMD_TIMEOUT=10         # seconds, default per external command
PING_COUNT=4
PING_TIMEOUT=5         # seconds per ping
MODE="normal"          # quick | normal | full
SINCE="24h"
OUTPUT_DIR="/tmp"
DO_BUNDLE=true
BOX_ID=""
EXPECTED_HOSTNAME=""
EXPECTED_IP=""
EXPECTED_UFW_STATE=""
REQUIRE_TAILSCALE=false
IS_ROOT=false
[[ $EUID -eq 0 ]] && IS_ROOT=true

# Load optional conf file (sourced safely)
[[ -f "$CONF_FILE" ]] && source "$CONF_FILE" 2>/dev/null || true

# ---------------------------------------------------------------------------
# STATE / COUNTERS
# ---------------------------------------------------------------------------
COUNT_RED=0
COUNT_AMBER=0
COUNT_GREEN=0
declare -a ACTIONS_RED=()
declare -a ACTIONS_AMBER=()

# Temp workspace for bundle
WORK_DIR="$(mktemp -d /tmp/cctv-diag.XXXXXX)"
trap 'rm -rf "$WORK_DIR"' EXIT

REPORT_FILE="$WORK_DIR/report.txt"
JSON_FILE="$WORK_DIR/report.json"
CMDS_DIR="$WORK_DIR/commands"
LOGS_DIR="$WORK_DIR/logs"
mkdir -p "$CMDS_DIR" "$LOGS_DIR"

# JSON accumulator (array of objects)
JSON_SECTIONS="[]"   # we'll build as a bash string

# Redirect console output *and* tee to report file
exec > >(tee -a "$REPORT_FILE") 2>&1

# ---------------------------------------------------------------------------
# ARGUMENT PARSING
# ---------------------------------------------------------------------------
usage() {
  cat <<EOF
Usage: $0 [OPTIONS]

Options:
  --quick                   Fast mode: minimal log extraction
  --full                    Full mode: extended checks, more logs, latency tests
  --since "24h"|"YYYY-MM-DD"  Log window (default: 24h)
  --output-dir PATH         Where to save bundle (default: /tmp)
  --bundle / --no-bundle    Create .tar.gz bundle (default: yes)
  --box-id N                Camera box ID 1-250 (auto-detect if omitted)
  --expected-hostname NAME  Assert hostname should match NAME
  --expected-ip IPV4        Assert server IP should match this
  --expected-ufw-state enabled|disabled
  --expected-nx-ports "7001,7002,..."
  --require-tailscale       Treat Tailscale offline as RED
  -h, --help                Show this help
EOF
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --quick)                  MODE="quick" ;;
      --full)                   MODE="full" ;;
      --since)                  SINCE="$2"; shift ;;
      --output-dir)             OUTPUT_DIR="$2"; shift ;;
      --bundle)                 DO_BUNDLE=true ;;
      --no-bundle)              DO_BUNDLE=false ;;
      --box-id)                 BOX_ID="$2"; shift ;;
      --expected-hostname)      EXPECTED_HOSTNAME="$2"; shift ;;
      --expected-ip)            EXPECTED_IP="$2"; shift ;;
      --expected-ufw-state)     EXPECTED_UFW_STATE="$2"; shift ;;
      --expected-nx-ports)      NX_PORTS="$2"; shift ;;
      --require-tailscale)      REQUIRE_TAILSCALE=true ;;
      -h|--help)                usage; exit 0 ;;
      *) echo "Unknown argument: $1"; usage; exit 1 ;;
    esac
    shift
  done
}

parse_args "$@"

# ---------------------------------------------------------------------------
# HELPER: Run a command with timeout, capture output, never fail the script
# ---------------------------------------------------------------------------
run_cmd() {
  # run_cmd <label> <timeout_sec> <cmd...>
  local label="$1"; local timeout_sec="$2"; shift 2
  local out rc
  out=$(timeout "$timeout_sec" "$@" 2>&1) && rc=$? || rc=$?
  # Save to commands dir
  local safe_label
  safe_label="$(echo "$label" | tr ' /()' '____')"
  echo "$out" > "$CMDS_DIR/${safe_label}.txt"
  echo "$out"
  return $rc
}

# Same but silently (no stdout echo), returns output in RUN_OUT, rc in RUN_RC
run_silent() {
  local label="$1"; local timeout_sec="$2"; shift 2
  RUN_OUT=$(timeout "$timeout_sec" "$@" 2>&1) && RUN_RC=0 || RUN_RC=$?
  local safe_label
  safe_label="$(echo "$label" | tr ' /()' '____')"
  echo "$RUN_OUT" > "$CMDS_DIR/${safe_label}.txt"
}

# ---------------------------------------------------------------------------
# HELPER: Section header
# ---------------------------------------------------------------------------
section() {
  local title="$1"
  echo ""
  echo -e "${C_CYAN}${C_BOLD}══════════════════════════════════════════════════════"
  echo -e "  $title"
  echo -e "══════════════════════════════════════════════════════${C_RESET}"
}

# ---------------------------------------------------------------------------
# HELPER: Status line  (component, severity, message)
# ---------------------------------------------------------------------------
status_line() {
  local component="$1" severity="$2" message="$3"
  local colour icon
  case "$severity" in
    RED)   colour="$C_RED";   icon="[RED  ]"; COUNT_RED=$(( COUNT_RED + 1 )) ;;
    AMBER) colour="$C_AMBER"; icon="[AMBER]"; COUNT_AMBER=$(( COUNT_AMBER + 1 )) ;;
    GREEN) colour="$C_GREEN"; icon="[GREEN]"; COUNT_GREEN=$(( COUNT_GREEN + 1 )) ;;
    INFO)  colour="$C_DIM";   icon="[INFO ]" ;;
    *)     colour="$C_DIM";   icon="[INFO ]" ;;
  esac
  echo -e "${colour}${icon}${C_RESET} ${C_BOLD}${component}${C_RESET}: ${message}"
  # Track actions for summary
  if [[ "$severity" == "RED" ]]; then
    ACTIONS_RED+=("$component: $message")
  elif [[ "$severity" == "AMBER" ]]; then
    ACTIONS_AMBER+=("$component: $message")
  fi
}

# ---------------------------------------------------------------------------
# HELPER: Log scanner — grep patterns from files within time window
# ---------------------------------------------------------------------------
log_scan() {
  # log_scan <dest_label> <since_epoch> <pattern1> [pattern2 ...] -- <file1> [file2 ...]
  # Simpler: we pass an array of files and an array of patterns
  local dest_label="$1"; local since_epoch="$2"; shift 2
  local -a patterns=(); local -a files=()
  local in_files=false
  for arg in "$@"; do
    if [[ "$arg" == "--" ]]; then in_files=true; continue; fi
    if $in_files; then files+=("$arg"); else patterns+=("$arg"); fi
  done
  local grep_args=(); for p in "${patterns[@]}"; do grep_args+=(-e "$p"); done
  local out=""
  for f in "${files[@]}"; do
    [[ -f "$f" ]] || continue
    # Try to filter by time if journalctl; for plain files grep and hope
    local matches
    matches=$(grep -iE "${grep_args[@]}" "$f" 2>/dev/null | tail -200) || true
    [[ -n "$matches" ]] && out+=$'\n'"=== $f ===\n$matches"
  done
  if [[ -n "$out" ]]; then
    echo "$out" > "$LOGS_DIR/${dest_label}.txt"
    echo "$out"
  fi
}

# ---------------------------------------------------------------------------
# HELPER: Convert SINCE to epoch
# ---------------------------------------------------------------------------
since_epoch() {
  local s="$SINCE"
  if [[ "$s" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]]; then
    date -d "$s" +%s 2>/dev/null || echo "0"
  elif [[ "$s" =~ ^([0-9]+)h$ ]]; then
    echo $(( STARTED_EPOCH - ${BASH_REMATCH[1]} * 3600 ))
  elif [[ "$s" =~ ^([0-9]+)d$ ]]; then
    echo $(( STARTED_EPOCH - ${BASH_REMATCH[1]} * 86400 ))
  else
    echo $(( STARTED_EPOCH - 86400 ))
  fi
}
SINCE_EPOCH="$(since_epoch)"

# ---------------------------------------------------------------------------
# JSON helpers — accumulate findings
# ---------------------------------------------------------------------------
JSON_ITEMS=""   # newline-separated JSON objects, joined later

add_json() {
  # add_json <section> <component> <severity> <message> [key=value ...]
  local section="$1" component="$2" severity="$3" message="$4"; shift 4
  local extras=""; for kv in "$@"; do extras+=",\"${kv%%=*}\":\"${kv#*=}\""; done
  JSON_ITEMS+="$(printf '{"section":"%s","component":"%s","severity":"%s","message":"%s"%s}' \
    "$section" "$component" "$severity" "$(echo "$message" | sed 's/"/\\"/g')" "$extras")"$'\n'
}

# ---------------------------------------------------------------------------
# SECTION: BOX_ID detection
# ---------------------------------------------------------------------------
detect_box_id() {
  section "BOX ID & SUBNET DETECTION"

  if [[ -n "$BOX_ID" ]]; then
    if ! [[ "$BOX_ID" =~ ^[1-9][0-9]*$ ]] || [[ $BOX_ID -lt 1 ]] || [[ $BOX_ID -gt 250 ]]; then
      status_line "BOX_ID" "RED" "Provided --box-id $BOX_ID is out of range 1-250"
      BOX_ID=""
    else
      status_line "BOX_ID" "INFO" "Using provided BOX_ID=$BOX_ID"
    fi
  fi

  if [[ -z "$BOX_ID" ]]; then
    # Auto-detect: find 192.168.x.y addresses
    local -a candidates=()
    while IFS= read -r line; do
      if [[ "$line" =~ 192\.168\.([0-9]+)\.[0-9]+ ]]; then
        candidates+=("${BASH_REMATCH[1]}")
      fi
    done < <(ip -4 addr show 2>/dev/null | grep 'inet ' || true)

    # Deduplicate
    local -a unique_candidates=()
    for c in "${candidates[@]}"; do
      local found=false
      for u in "${unique_candidates[@]:-dummy_not_found}"; do [[ "$u" == "$c" ]] && found=true; done
      $found || unique_candidates+=("$c")
    done

    if [[ ${#unique_candidates[@]} -eq 0 ]]; then
      status_line "BOX_ID" "AMBER" "No 192.168.x.y address found; BOX_ID unknown"
      BOX_ID=""
    elif [[ ${#unique_candidates[@]} -eq 1 ]]; then
      BOX_ID="${unique_candidates[0]}"
      if [[ $BOX_ID -lt 1 ]] || [[ $BOX_ID -gt 250 ]]; then
        status_line "BOX_ID" "AMBER" "Detected 192.168.$BOX_ID subnet but $BOX_ID outside 1-250 range"
      else
        status_line "BOX_ID" "GREEN" "Auto-detected BOX_ID=$BOX_ID (subnet 192.168.$BOX_ID.0/24)"
      fi
    else
      # Multiple candidates — prefer the one on default-route interface
      local def_iface def_subnet=""
      def_iface=$(ip route show default 2>/dev/null | awk '/default/{print $5; exit}') || true
      if [[ -n "$def_iface" ]]; then
        local def_ip
        def_ip=$(ip -4 addr show dev "$def_iface" 2>/dev/null | grep 'inet ' | awk '{print $2}' | cut -d/ -f1 | head -1)
        if [[ "$def_ip" =~ 192\.168\.([0-9]+)\.[0-9]+ ]]; then
          def_subnet="${BASH_REMATCH[1]}"
        fi
      fi
      BOX_ID="${def_subnet:-${unique_candidates[0]}}"
      status_line "BOX_ID" "AMBER" "Multiple 192.168.x subnets detected: [${unique_candidates[*]}] — using $BOX_ID (on default-route interface). Verify manually."
      add_json "box_id" "BOX_ID" "AMBER" "Multiple candidates: ${unique_candidates[*]}" "chosen=$BOX_ID"
    fi
  fi

  if [[ -n "$BOX_ID" ]]; then
    ROUTER_IP="192.168.${BOX_ID}.1"
    SERVER_SUBNET="192.168.${BOX_ID}.0/24"
    echo -e "${C_DIM}  BOX_ID=$BOX_ID  |  Subnet=$SERVER_SUBNET  |  Router=$ROUTER_IP${C_RESET}"
    add_json "box_id" "BOX_ID" "GREEN" "BOX_ID=$BOX_ID subnet=$SERVER_SUBNET router=$ROUTER_IP"
  else
    ROUTER_IP=""
    SERVER_SUBNET=""
  fi
}

# ---------------------------------------------------------------------------
# SECTION: Identity & DNS
# ---------------------------------------------------------------------------
check_identity() {
  section "IDENTITY & DNS"

  local hn fqdn
  hn=$(hostname -s 2>/dev/null || echo "UNKNOWN")
  fqdn=$(hostname -f 2>/dev/null || echo "UNKNOWN")
  status_line "Hostname" "INFO" "Short=$hn  FQDN=$fqdn"

  if [[ -n "$EXPECTED_HOSTNAME" ]]; then
    if [[ "$hn" == "$EXPECTED_HOSTNAME" ]] || [[ "$fqdn" == "$EXPECTED_HOSTNAME" ]]; then
      status_line "Hostname-match" "GREEN" "Matches expected '$EXPECTED_HOSTNAME'"
      add_json "identity" "Hostname" "GREEN" "Matches expected"
    else
      status_line "Hostname-match" "RED" "Expected '$EXPECTED_HOSTNAME', got short='$hn' fqdn='$fqdn'"
      add_json "identity" "Hostname" "RED" "Mismatch: expected=$EXPECTED_HOSTNAME actual=$hn"
    fi
  fi

  # /etc/hosts sanity — look for duplicate entries for this hostname
  local hosts_dups
  hosts_dups=$(grep -v '^#' /etc/hosts 2>/dev/null | grep -cw "$hn" 2>/dev/null) || true
  hosts_dups="${hosts_dups//[[:space:]]/}"
  hosts_dups="${hosts_dups:-0}"
  if [[ $hosts_dups -gt 1 ]]; then
    status_line "/etc/hosts" "AMBER" "Hostname '$hn' appears $hosts_dups times in /etc/hosts"
    add_json "identity" "hosts" "AMBER" "Duplicate hostname entries"
  else
    status_line "/etc/hosts" "GREEN" "No duplicate entries for '$hn'"
  fi

  # DNS resolution
  if command -v getent &>/dev/null; then
    local resolved
    resolved=$(timeout $CMD_TIMEOUT getent hosts "$hn" 2>/dev/null | awk '{print $1}' | head -1 || true)
    if [[ -n "$resolved" ]]; then
      status_line "DNS-resolve" "GREEN" "$hn → $resolved"
      if [[ -n "$EXPECTED_IP" ]] && [[ "$resolved" != "$EXPECTED_IP" ]]; then
        status_line "DNS-IP-match" "AMBER" "Resolved $resolved but expected $EXPECTED_IP"
        add_json "identity" "DNS" "AMBER" "resolved=$resolved expected=$EXPECTED_IP"
      fi
    else
      status_line "DNS-resolve" "AMBER" "'$hn' does not resolve to any IP"
      add_json "identity" "DNS" "AMBER" "Hostname does not resolve"
    fi
  fi

  # DNS resolvers
  echo -e "${C_DIM}  DNS resolvers:${C_RESET}"
  if [[ -f /etc/resolv.conf ]]; then
    grep '^nameserver' /etc/resolv.conf 2>/dev/null | head -5 | while read -r _ ip; do
      echo "    nameserver $ip"
    done
  fi
  # systemd-resolved stub
  if command -v resolvectl &>/dev/null; then
    run_silent "resolvectl-status" $CMD_TIMEOUT resolvectl status
    echo "$RUN_OUT" | grep -E 'DNS Servers|DNS Domain|Current Scopes' | head -10 || true
  fi
}

# ---------------------------------------------------------------------------
# SECTION: Networking
# ---------------------------------------------------------------------------
check_networking() {
  section "NETWORKING"

  # Interfaces
  echo -e "${C_DIM}── Interfaces & addresses ──${C_RESET}"
  run_cmd "ip-addr" $CMD_TIMEOUT ip -4 addr show | head -60 || true
  echo ""

  # Check server is in expected subnet
  if [[ -n "$BOX_ID" ]]; then
    local server_ip_in_subnet=false
    while IFS= read -r line; do
      if [[ "$line" =~ inet[[:space:]]+(192\.168\.${BOX_ID}\.[0-9]+) ]]; then
        server_ip_in_subnet=true
        status_line "Subnet-check" "GREEN" "Server has IP ${BASH_REMATCH[1]} in 192.168.${BOX_ID}.0/24"
        add_json "networking" "Subnet" "GREEN" "IP in correct subnet"
        break
      fi
    done < <(ip -4 addr show 2>/dev/null || true)
    if ! $server_ip_in_subnet; then
      status_line "Subnet-check" "RED" "No address found in 192.168.${BOX_ID}.0/24 — BOX_ID mismatch or misconfiguration"
      add_json "networking" "Subnet" "RED" "Not in expected subnet 192.168.${BOX_ID}.0/24"
    fi
  fi

  # Default route
  echo -e "${C_DIM}── Routes ──${C_RESET}"
  run_cmd "ip-route" $CMD_TIMEOUT ip route show | head -30 || true

  local def_gw
  def_gw=$(ip route show default 2>/dev/null | awk '/default/{print $3; exit}') || true
  if [[ -z "$def_gw" ]]; then
    status_line "Default-route" "RED" "No default route found"
    add_json "networking" "DefaultRoute" "RED" "No default route"
  else
    status_line "Default-route" "GREEN" "Default gateway: $def_gw"
    add_json "networking" "DefaultRoute" "GREEN" "gw=$def_gw"
    if [[ -n "$ROUTER_IP" ]] && [[ "$def_gw" != "$ROUTER_IP" ]]; then
      status_line "Gateway-match" "AMBER" "Default GW is $def_gw but expected ROUTER_IP=$ROUTER_IP"
      add_json "networking" "Gateway" "AMBER" "gw=$def_gw expected=$ROUTER_IP"
    elif [[ -n "$ROUTER_IP" ]]; then
      status_line "Gateway-match" "GREEN" "Default GW matches ROUTER_IP=$ROUTER_IP"
    fi
  fi

  # Link state
  echo -e "${C_DIM}── Link states ──${C_RESET}"
  ip link show 2>/dev/null | grep -E 'state (UP|DOWN|UNKNOWN)' | while read -r line; do
    local iface state
    iface=$(echo "$line" | awk -F': ' '{print $2}' | cut -d@ -f1)
    state=$(echo "$line" | grep -oP 'state \K\S+')
    case "$state" in
      UP)   status_line "Link[$iface]" "GREEN" "UP" ;;
      DOWN) status_line "Link[$iface]" "AMBER" "DOWN" ;;
      *)    status_line "Link[$iface]" "INFO"  "$state" ;;
    esac
  done
}

# ---------------------------------------------------------------------------
# SECTION: Router & WAN checks
# ---------------------------------------------------------------------------
check_router_wan() {
  section "ROUTER / WAN HEALTH"

  if [[ -z "$ROUTER_IP" ]]; then
    status_line "Router" "AMBER" "ROUTER_IP unknown (BOX_ID not determined) — skipping"
    return
  fi

  # Ping router
  local ping_out ping_rc
  ping_out=$(timeout $(( PING_TIMEOUT * PING_COUNT + 5 )) ping -c $PING_COUNT -W $PING_TIMEOUT "$ROUTER_IP" 2>&1) && ping_rc=0 || ping_rc=1
  echo "$ping_out" > "$CMDS_DIR/ping_router.txt"
  if [[ $ping_rc -eq 0 ]]; then
    local rtt
    rtt=$(echo "$ping_out" | grep -oP 'rtt.*?= \K[\d.]+(?=/)' || echo "?")
    status_line "Router-ping" "GREEN" "$ROUTER_IP reachable (avg ${rtt}ms)"
    add_json "router_wan" "RouterPing" "GREEN" "rtt_ms=$rtt"
  else
    status_line "Router-ping" "RED" "$ROUTER_IP unreachable (ping failed)"
    add_json "router_wan" "RouterPing" "RED" "Router ping failed"
  fi

  # ARP/neighbour entry for router
  local neigh
  neigh=$(timeout $CMD_TIMEOUT ip neigh show "$ROUTER_IP" 2>/dev/null || true)
  if [[ -n "$neigh" ]]; then
    status_line "Router-ARP" "GREEN" "ARP entry: $neigh"
  else
    status_line "Router-ARP" "AMBER" "No ARP/neighbour entry for $ROUTER_IP"
    add_json "router_wan" "RouterARP" "AMBER" "No neighbour entry"
  fi

  # WAN checks (DNS + HTTP HEAD to stable endpoints)
  local WAN_ENDPOINTS=("8.8.8.8" "1.1.1.1")
  local HTTP_ENDPOINTS=("http://detectportal.firefox.com/success.txt" "http://connectivitycheck.gstatic.com/generate_204")
  local DNS_TEST_HOST="google.com"

  echo -e "${C_DIM}── WAN DNS check ──${C_RESET}"
  local dns_ok=false
  if timeout $CMD_TIMEOUT getent hosts "$DNS_TEST_HOST" &>/dev/null; then
    status_line "WAN-DNS" "GREEN" "$DNS_TEST_HOST resolves OK"
    dns_ok=true
    add_json "router_wan" "WAN_DNS" "GREEN" "DNS resolution working"
  else
    status_line "WAN-DNS" "AMBER" "$DNS_TEST_HOST failed to resolve — WAN DNS may be down"
    add_json "router_wan" "WAN_DNS" "AMBER" "DNS test failed"
  fi

  echo -e "${C_DIM}── WAN ping checks ──${C_RESET}"
  for ep in "${WAN_ENDPOINTS[@]}"; do
    local p_out p_rc
    p_out=$(timeout $(( PING_TIMEOUT * 3 + 3 )) ping -c 3 -W $PING_TIMEOUT "$ep" 2>&1) && p_rc=0 || p_rc=1
    echo "$p_out" > "$CMDS_DIR/ping_wan_${ep//./_}.txt"
    if [[ $p_rc -eq 0 ]]; then
      local rtt2; rtt2=$(echo "$p_out" | grep -oP 'rtt.*?= \K[\d.]+(?=/)' || echo "?")
      status_line "WAN-ping[$ep]" "GREEN" "Reachable (avg ${rtt2}ms)"
    else
      status_line "WAN-ping[$ep]" "AMBER" "$ep unreachable"
      add_json "router_wan" "WAN_ping" "AMBER" "endpoint=$ep unreachable"
    fi
  done

  echo -e "${C_DIM}── WAN HTTP checks ──${C_RESET}"
  if command -v curl &>/dev/null; then
    for url in "${HTTP_ENDPOINTS[@]}"; do
      local http_rc
      http_rc=$(timeout $CMD_TIMEOUT curl -o /dev/null -s -w "%{http_code}" --head "$url" 2>/dev/null) || true
      if [[ "$http_rc" =~ ^(200|204)$ ]]; then
        status_line "WAN-HTTP" "GREEN" "$url → HTTP $http_rc"
      else
        status_line "WAN-HTTP" "AMBER" "$url → HTTP ${http_rc:-timeout/error}"
        add_json "router_wan" "WAN_HTTP" "AMBER" "url=$url code=$http_rc"
      fi
    done
  else
    status_line "WAN-HTTP" "INFO" "curl not available — skipping HTTP checks"
  fi

  # Extended latency/loss tests in full mode
  if [[ "$MODE" == "full" ]]; then
    echo -e "${C_DIM}── Extended latency test (30s) ──${C_RESET}"
    local ext_out ext_rc
    ext_out=$(timeout 40 ping -c 30 -i 1 -W 3 "8.8.8.8" 2>&1) && ext_rc=0 || ext_rc=1
    echo "$ext_out" > "$CMDS_DIR/ping_extended.txt"
    local loss rtt_avg
    loss=$(echo "$ext_out" | grep -oP '[\d.]+(?=% packet loss)' || echo "100")
    rtt_avg=$(echo "$ext_out" | grep -oP 'rtt.*?= [\d.]+/\K[\d.]+' || echo "?")
    if [[ "${loss%.*}" -lt 5 ]]; then
      status_line "WAN-latency-ext" "GREEN" "Loss=${loss}% avg_rtt=${rtt_avg}ms"
    elif [[ "${loss%.*}" -lt 20 ]]; then
      status_line "WAN-latency-ext" "AMBER" "Loss=${loss}% avg_rtt=${rtt_avg}ms — intermittent"
      add_json "router_wan" "ExtLatency" "AMBER" "loss=$loss rtt=$rtt_avg"
    else
      status_line "WAN-latency-ext" "RED" "Loss=${loss}% — severe WAN issues"
      add_json "router_wan" "ExtLatency" "RED" "loss=$loss"
    fi
  fi
}

# ---------------------------------------------------------------------------
# SECTION: Time / NTP
# ---------------------------------------------------------------------------
check_time() {
  section "TIME / NTP"

  run_silent "timedatectl" $CMD_TIMEOUT timedatectl status
  echo "$RUN_OUT"

  local ntp_synced tz rtc_utc
  ntp_synced=$(echo "$RUN_OUT" | grep -i 'NTP synchronized' | grep -c 'yes' || echo 0)
  tz=$(echo "$RUN_OUT" | grep 'Time zone' | awk '{print $3}')

  if [[ "$ntp_synced" -ge 1 ]]; then
    status_line "NTP-sync" "GREEN" "NTP synchronised (TZ: $tz)"
    add_json "time" "NTP" "GREEN" "synced tz=$tz"
  else
    # Check if time is at least close (within 5 min)
    local sys_epoch hw_epoch
    sys_epoch=$(date +%s)
    hw_epoch=$(hwclock --utc 2>/dev/null | date -f - +%s 2>/dev/null || echo "$sys_epoch")
    local drift=$(( sys_epoch - hw_epoch ))
    drift=${drift#-}  # abs
    if [[ $drift -gt 300 ]]; then
      status_line "NTP-sync" "RED" "NTP NOT synced and clock drift >5min ($drift seconds)"
      add_json "time" "NTP" "RED" "unsynced drift_sec=$drift"
    else
      status_line "NTP-sync" "AMBER" "NTP NOT synced but drift within acceptable range ($drift sec)"
      add_json "time" "NTP" "AMBER" "unsynced drift_sec=$drift"
    fi
  fi

  # Check NTP service
  for svc in systemd-timesyncd chronyd ntpd; do
    if systemctl is-active "$svc" &>/dev/null 2>&1; then
      status_line "NTP-service" "GREEN" "$svc is active"
      break
    fi
  done
}

# ---------------------------------------------------------------------------
# SECTION: Storage
# ---------------------------------------------------------------------------
check_storage() {
  section "STORAGE"

  # Disk usage
  echo -e "${C_DIM}── Disk usage ──${C_RESET}"
  run_cmd "df" $CMD_TIMEOUT df -hT | head -40 || true
  echo ""

  while IFS= read -r line; do
    local pct mp fs
    pct=$(echo "$line" | awk '{print $6}' | tr -d '%')
    mp=$(echo "$line" | awk '{print $7}')
    fs=$(echo "$line" | awk '{print $2}')
    [[ "$pct" =~ ^[0-9]+$ ]] || continue
    [[ "$mp" == "Filesystem" ]] && continue
    if [[ $pct -ge $DISK_RED ]]; then
      status_line "Disk[$mp]" "RED" "${pct}% used (>=$DISK_RED% threshold) — CCTV recording at risk"
      add_json "storage" "Disk" "RED" "mount=$mp pct=$pct"
    elif [[ $pct -ge $DISK_AMBER ]]; then
      status_line "Disk[$mp]" "AMBER" "${pct}% used (>=$DISK_AMBER% threshold)"
      add_json "storage" "Disk" "AMBER" "mount=$mp pct=$pct"
    fi
  done < <(df -P 2>/dev/null | tail -n +2 || true)

  # Inode usage
  echo -e "${C_DIM}── Inode usage ──${C_RESET}"
  run_cmd "df-inodes" $CMD_TIMEOUT df -i | head -30 || true
  while IFS= read -r line; do
    local pct mp
    pct=$(echo "$line" | awk '{print $5}' | tr -d '%')
    mp=$(echo "$line" | awk '{print $6}')
    [[ "$pct" =~ ^[0-9]+$ ]] || continue
    if [[ $pct -ge $INODE_RED ]]; then
      status_line "Inodes[$mp]" "RED" "${pct}% inodes used"
      add_json "storage" "Inodes" "RED" "mount=$mp pct=$pct"
    elif [[ $pct -ge $INODE_AMBER ]]; then
      status_line "Inodes[$mp]" "AMBER" "${pct}% inodes used"
      add_json "storage" "Inodes" "AMBER" "mount=$mp pct=$pct"
    fi
  done < <(df -Pi 2>/dev/null | tail -n +2 || true)

  # Mount check for NX storage paths
  echo -e "${C_DIM}── NX storage mount check ──${C_RESET}"
  local nx_storage_paths=("/mnt/nx" "/opt/networkoptix-mediaserver/var" "/var/nx" "/mnt/cctv" "/storage")
  for p in "${nx_storage_paths[@]}"; do
    [[ -d "$p" ]] || continue
    # Check it's actually mounted (not just a directory)
    if mountpoint -q "$p" 2>/dev/null; then
      # Writability check
      if $IS_ROOT; then
        if touch "$p/.cctv_diag_test_$$" 2>/dev/null; then
          rm -f "$p/.cctv_diag_test_$$"
          status_line "NX-storage[$p]" "GREEN" "Mounted and writable"
          add_json "storage" "NXStorage" "GREEN" "path=$p"
        else
          status_line "NX-storage[$p]" "RED" "Mounted but NOT writable — recording will fail"
          add_json "storage" "NXStorage" "RED" "path=$p not_writable"
        fi
      else
        status_line "NX-storage[$p]" "INFO" "Mounted (writable check skipped — not root)"
      fi
    else
      status_line "NX-storage[$p]" "AMBER" "Directory exists but is NOT a mountpoint"
      add_json "storage" "NXStorage" "AMBER" "path=$p not_mounted"
    fi
  done

  # Stale mounts (fuser / findmnt hung check)
  echo -e "${C_DIM}── Mount health ──${C_RESET}"
  run_cmd "findmnt" $CMD_TIMEOUT findmnt --real --output TARGET,SOURCE,FSTYPE,OPTIONS | head -40 || true

  # Filesystem errors from dmesg/journal
  echo -e "${C_DIM}── Filesystem error patterns (dmesg/journal) ──${C_RESET}"
  local fs_errors=("I/O error" "EXT4-fs error" "XFS.*error" "Buffer I/O error" "SCSI error" "ata.*error"
                   "hard resetting link" "disk quota exceeded" "filesystem corruption"
                   "Remounting filesystem read-only" "journal commit I/O error")
  local err_found=false
  for pattern in "${fs_errors[@]}"; do
    local hits
    hits=$(timeout $CMD_TIMEOUT dmesg 2>/dev/null | grep -iE "$pattern" | tail -5 || true)
    if [[ -n "$hits" ]]; then
      err_found=true
      echo -e "${C_RED}[dmesg] Pattern '$pattern':${C_RESET}"
      echo "$hits" | head -3
      status_line "FS-errors" "RED" "dmesg shows '$pattern'"
      add_json "storage" "FSErrors" "RED" "pattern=$pattern"
    fi
  done
  $err_found || status_line "FS-errors" "GREEN" "No filesystem error patterns in dmesg"

  # Journal FS errors
  if command -v journalctl &>/dev/null && $IS_ROOT; then
    local j_err
    j_err=$(timeout $CMD_TIMEOUT journalctl --since "24h ago" -q --no-pager 2>/dev/null \
      | grep -iE "I/O error|EXT4-fs error|XFS.*error|filesystem.*corrupt" | tail -20 || true)
    [[ -n "$j_err" ]] && echo "$j_err" > "$LOGS_DIR/journal_fs_errors.txt"
  fi

  # SMART health (best effort)
  echo -e "${C_DIM}── SMART health (best effort) ──${C_RESET}"
  if command -v smartctl &>/dev/null && $IS_ROOT; then
    for dev in /dev/sd? /dev/nvme?; do
      [[ -b "$dev" ]] || continue
      local smart_out smart_rc
      smart_out=$(timeout $CMD_TIMEOUT smartctl -H "$dev" 2>&1) && smart_rc=0 || smart_rc=$?
      echo "$smart_out" > "$CMDS_DIR/smart_${dev//\//_}.txt"
      if echo "$smart_out" | grep -q 'PASSED'; then
        status_line "SMART[$dev]" "GREEN" "SMART self-test PASSED"
      elif echo "$smart_out" | grep -q 'FAILED'; then
        status_line "SMART[$dev]" "RED" "SMART reports FAILURE on $dev — drive may be failing"
        add_json "storage" "SMART" "RED" "device=$dev"
      else
        status_line "SMART[$dev]" "AMBER" "SMART status unclear: $smart_out"
      fi
    done
  else
    status_line "SMART" "INFO" "smartctl not available or not root — skipping"
  fi
}

# ---------------------------------------------------------------------------
# SECTION: System Resources
# ---------------------------------------------------------------------------
check_resources() {
  section "SYSTEM RESOURCES"

  # Uptime & load
  echo -e "${C_DIM}── Uptime & Load ──${C_RESET}"
  run_cmd "uptime" $CMD_TIMEOUT uptime || true

  local load1
  load1=$(cut -d' ' -f1 /proc/loadavg 2>/dev/null || echo 0)
  local ncpu
  ncpu=$(nproc 2>/dev/null || echo 1)
  local load_norm
  load_norm=$(awk "BEGIN{printf \"%.2f\", $load1 / $ncpu}")
  if awk "BEGIN{exit ($load_norm < 2.0) ? 0 : 1}"; then
    status_line "CPU-load" "GREEN" "Load avg (1m): $load1 (${load_norm}x per-core)"
  elif awk "BEGIN{exit ($load_norm < 5.0) ? 0 : 1}"; then
    status_line "CPU-load" "AMBER" "Load avg (1m): $load1 (${load_norm}x per-core) — elevated"
    add_json "resources" "CPU" "AMBER" "load1=$load1 norm=$load_norm"
  else
    status_line "CPU-load" "RED" "Load avg (1m): $load1 (${load_norm}x per-core) — critical"
    add_json "resources" "CPU" "RED" "load1=$load1 norm=$load_norm"
  fi

  # Memory
  echo -e "${C_DIM}── Memory ──${C_RESET}"
  run_cmd "free" $CMD_TIMEOUT free -h || true
  local mem_total mem_avail mem_pct
  mem_total=$(grep MemTotal /proc/meminfo | awk '{print $2}')
  mem_avail=$(grep MemAvailable /proc/meminfo | awk '{print $2}')
  if [[ -n "$mem_total" ]] && [[ -n "$mem_avail" ]] && [[ $mem_total -gt 0 ]]; then
    mem_pct=$(( (mem_total - mem_avail) * 100 / mem_total ))
    if [[ $mem_pct -ge 95 ]]; then
      status_line "Memory" "RED" "${mem_pct}% used — critical"
      add_json "resources" "Memory" "RED" "pct=$mem_pct"
    elif [[ $mem_pct -ge 85 ]]; then
      status_line "Memory" "AMBER" "${mem_pct}% used"
      add_json "resources" "Memory" "AMBER" "pct=$mem_pct"
    else
      status_line "Memory" "GREEN" "${mem_pct}% used"
    fi
  fi

  # Swap
  local swap_total swap_used
  swap_total=$(grep SwapTotal /proc/meminfo | awk '{print $2}')
  swap_used=$(grep SwapFree /proc/meminfo | awk '{print $2}')
  if [[ "$swap_total" -gt 0 ]] 2>/dev/null; then
    local swap_pct=$(( (swap_total - swap_used) * 100 / swap_total ))
    [[ $swap_pct -ge 80 ]] && status_line "Swap" "AMBER" "${swap_pct}% swap used" \
      && add_json "resources" "Swap" "AMBER" "pct=$swap_pct"
  fi

  # OOM killer evidence
  echo -e "${C_DIM}── OOM killer evidence ──${C_RESET}"
  local oom_hits
  oom_hits=$(timeout $CMD_TIMEOUT dmesg 2>/dev/null | grep -c 'Out of memory\|oom-kill' || echo 0)
  if [[ $oom_hits -gt 0 ]]; then
    status_line "OOM-killer" "RED" "$oom_hits OOM kill event(s) in dmesg"
    add_json "resources" "OOM" "RED" "events=$oom_hits"
    timeout $CMD_TIMEOUT dmesg 2>/dev/null | grep -E 'Out of memory|oom-kill' | tail -10 > "$LOGS_DIR/oom.txt"
  else
    status_line "OOM-killer" "GREEN" "No OOM kill events in dmesg"
  fi

  # Uptime & reboot history
  echo -e "${C_DIM}── Reboot history ──${C_RESET}"
  run_cmd "last-reboot" $CMD_TIMEOUT last reboot -n 5 2>/dev/null || true
  local uptime_secs
  uptime_secs=$(awk '{print int($1)}' /proc/uptime 2>/dev/null || echo 0)
  if [[ $uptime_secs -lt 300 ]]; then
    status_line "Recent-reboot" "AMBER" "System rebooted less than 5 minutes ago (uptime: ${uptime_secs}s)"
    add_json "resources" "Reboot" "AMBER" "uptime_sec=$uptime_secs"
  else
    local uptime_h=$(( uptime_secs / 3600 ))
    status_line "Uptime" "GREEN" "${uptime_h}h (${uptime_secs}s)"
  fi
}

# ---------------------------------------------------------------------------
# SECTION: Services
# ---------------------------------------------------------------------------
check_services() {
  section "SERVICES"

  # Key services to check
  local -a KEY_SERVICES=()
  # NX Witness — detect
  for pattern in "${NX_SERVICE_PATTERNS[@]}"; do
    local found_svc
    found_svc=$(systemctl list-units --type=service --all 2>/dev/null \
      | grep -iE "$pattern" | awk '{print $1}' | head -1 || true)
    [[ -n "$found_svc" ]] && KEY_SERVICES+=("$found_svc") && break
  done
  KEY_SERVICES+=("tailscaled" "ufw" "timeshift")

  # Add timer if exists
  if systemctl list-timers --all 2>/dev/null | grep -q timeshift; then
    KEY_SERVICES+=("timeshift.timer")
  fi

  for svc in "${KEY_SERVICES[@]}"; do
    run_silent "svc-$svc" $CMD_TIMEOUT systemctl status "$svc" --no-pager -l
    local active_state sub_state
    active_state=$(echo "$RUN_OUT" | grep 'Active:' | awk '{print $2}' | head -1)
    sub_state=$(echo "$RUN_OUT" | grep 'Active:' | grep -oP '\(\K[^)]+' | head -1)
    case "$active_state" in
      active)
        status_line "Service[$svc]" "GREEN" "active ($sub_state)"
        add_json "services" "$svc" "GREEN" "active"
        ;;
      failed|error)
        status_line "Service[$svc]" "RED" "FAILED — $sub_state"
        add_json "services" "$svc" "RED" "failed sub=$sub_state"
        ;;
      inactive|dead)
        status_line "Service[$svc]" "AMBER" "inactive/dead"
        add_json "services" "$svc" "AMBER" "inactive"
        ;;
      *)
        status_line "Service[$svc]" "INFO" "${active_state:-unknown}"
        ;;
    esac
  done
}

# ---------------------------------------------------------------------------
# SECTION: Witness NX (Network Optix / Nx Witness)
# ---------------------------------------------------------------------------
check_witness_nx() {
  section "WITNESS NX (NETWORK OPTIX)"

  # Detect NX package
  local nx_pkg=""
  for pkg_name in "networkoptix-mediaserver" "nx-witness" "nxwitness"; do
    if dpkg -l "$pkg_name" 2>/dev/null | grep -q '^ii'; then
      nx_pkg="$pkg_name"
      local nx_ver; nx_ver=$(dpkg -l "$pkg_name" 2>/dev/null | awk '/^ii/{print $3}')
      status_line "NX-package" "GREEN" "Installed: $pkg_name v$nx_ver"
      add_json "nx" "NXPackage" "GREEN" "pkg=$pkg_name version=$nx_ver"
      break
    fi
  done
  [[ -z "$nx_pkg" ]] && status_line "NX-package" "AMBER" "No NX package detected (dpkg); may be installed differently"

  # Service detection
  local nx_svc=""
  for pattern in "${NX_SERVICE_PATTERNS[@]}"; do
    nx_svc=$(systemctl list-units --type=service --all 2>/dev/null \
      | grep -iE "$pattern" | awk '{print $1}' | head -1 || true)
    [[ -n "$nx_svc" ]] && break
  done

  if [[ -n "$nx_svc" ]]; then
    run_silent "nx-service-status" $CMD_TIMEOUT systemctl status "$nx_svc" --no-pager -l
    if echo "$RUN_OUT" | grep -q 'active (running)'; then
      status_line "NX-service" "GREEN" "$nx_svc is running"
      add_json "nx" "NXService" "GREEN" "service=$nx_svc"
    else
      status_line "NX-service" "RED" "$nx_svc is NOT running"
      add_json "nx" "NXService" "RED" "service=$nx_svc not_running"
    fi
    echo "$RUN_OUT" | tail -20
  else
    status_line "NX-service" "AMBER" "No NX media server service found via systemctl"
    add_json "nx" "NXService" "AMBER" "no_service_found"
  fi

  # Port check
  echo -e "${C_DIM}── NX port listening ──${C_RESET}"
  IFS=',' read -ra NX_PORT_LIST <<< "$NX_PORTS"
  for port in "${NX_PORT_LIST[@]}"; do
    port=$(echo "$port" | tr -d ' ')
    local port_open=false
    if command -v ss &>/dev/null; then
      ss -tlnp "sport = :$port" 2>/dev/null | grep -q ":$port" && port_open=true
    elif command -v netstat &>/dev/null; then
      netstat -tlnp 2>/dev/null | grep -q ":$port " && port_open=true
    fi
    if $port_open; then
      status_line "NX-port[$port]" "GREEN" "Listening"
    else
      status_line "NX-port[$port]" "AMBER" "NOT listening on port $port"
      add_json "nx" "NXPort" "AMBER" "port=$port not_listening"
    fi
  done

  # NX process
  echo -e "${C_DIM}── NX process ──${C_RESET}"
  local nx_proc
  nx_proc=$(pgrep -a -f 'mediaserver\|nx_witness\|nxwitness' 2>/dev/null | head -5 || true)
  if [[ -n "$nx_proc" ]]; then
    echo "$nx_proc"
    status_line "NX-process" "GREEN" "Process found"
  else
    status_line "NX-process" "AMBER" "No mediaserver process found"
    add_json "nx" "NXProcess" "AMBER" "no_process"
  fi

  # NX logs — discover and scan
  echo -e "${C_DIM}── NX log scan ──${C_RESET}"
  local -a critical_patterns=(
    "crash" "segfault" "sigsegv" "SIGSEGV" "fatal" "FATAL"
    "database corruption" "corrupt" "storage offline" "recorder offline"
    "license" "permission denied" "EACCES" "EPERM"
    "stream.*offline" "camera.*offline" "device.*offline"
    "recording.*fail" "write.*fail" "no space"
  )
  local nx_logs_found=false
  for log_dir in "${NX_LOG_PATHS[@]}"; do
    [[ -d "$log_dir" ]] || continue
    nx_logs_found=true
    local log_files
    readarray -t log_files < <(find "$log_dir" -maxdepth 2 -name "*.log" 2>/dev/null | head -20 || true)
    for lf in "${log_files[@]:-}"; do
      [[ -f "$lf" ]] || continue
      local hits
      for pat in "${critical_patterns[@]}"; do
        hits=$(grep -iE "$pat" "$lf" 2>/dev/null | tail -10 || true)
        if [[ -n "$hits" ]]; then
          echo -e "${C_AMBER}[NX-log] Pattern '$pat' in $lf:${C_RESET}"
          echo "$hits" | head -5
          echo "$hits" >> "$LOGS_DIR/nx_critical.txt"
          status_line "NX-log[$pat]" "AMBER" "Found in $(basename "$lf")"
          add_json "nx" "NXLog" "AMBER" "pattern=$pat file=$(basename "$lf")"
        fi
      done
      # Collect recent log excerpt
      local log_label
      log_label="nx_$(basename "$lf")_recent.txt"
      if [[ "$MODE" != "quick" ]]; then
        tail -200 "$lf" > "$LOGS_DIR/$log_label" 2>/dev/null || true
      fi
    done
  done
  $nx_logs_found || status_line "NX-logs" "AMBER" "No NX log directories found at standard paths"

  # NX storage permission check
  echo -e "${C_DIM}── NX storage permissions ──${C_RESET}"
  local nx_data_dirs=("/opt/networkoptix/mediaserver/var" "/opt/networkoptix-mediaserver/var" "/var/lib/networkoptix" "/home/networkoptix" "/mnt/nx")
  for d in "${nx_data_dirs[@]}"; do
    [[ -d "$d" ]] || continue
    local owner perms
    owner=$(stat -c '%U:%G' "$d" 2>/dev/null || echo "?")
    perms=$(stat -c '%a' "$d" 2>/dev/null || echo "?")
    status_line "NX-dir[$d]" "INFO" "owner=$owner perms=$perms"
    # Verify readable
    if [[ -r "$d" ]]; then
      status_line "NX-dir-read[$d]" "GREEN" "Readable"
    else
      status_line "NX-dir-read[$d]" "AMBER" "Not readable by current user"
      add_json "nx" "NXDirPerm" "AMBER" "dir=$d not_readable"
    fi
  done
}

# ---------------------------------------------------------------------------
# SECTION: Timeshift
# ---------------------------------------------------------------------------
check_timeshift() {
  section "TIMESHIFT"

  if ! command -v timeshift &>/dev/null; then
    status_line "Timeshift" "AMBER" "timeshift not installed or not in PATH"
    add_json "timeshift" "Timeshift" "AMBER" "not_installed"
    return
  fi

  # List snapshots
  local ts_out ts_rc
  ts_out=$(timeout 30 timeshift --list 2>&1) && ts_rc=0 || ts_rc=$?
  echo "$ts_out" | head -50
  echo "$ts_out" > "$CMDS_DIR/timeshift_list.txt"

  if [[ $ts_rc -ne 0 ]]; then
    status_line "Timeshift-list" "AMBER" "timeshift --list failed (rc=$ts_rc)"
    add_json "timeshift" "TimeshiftList" "AMBER" "rc=$ts_rc"
    return
  fi

  # Parse last snapshot date
  local last_snap_line last_snap_date last_snap_epoch now_epoch days_ago
  last_snap_line=$(echo "$ts_out" | grep -E '^\s*[0-9]+\s+>' | tail -1 || \
                   echo "$ts_out" | grep -E '[0-9]{4}-[0-9]{2}-[0-9]{2}' | tail -1 || true)

  local snap_date
  snap_date=$(echo "$last_snap_line" | grep -oP '\d{4}-\d{2}-\d{2}' | head -1 || true)

  if [[ -z "$snap_date" ]]; then
    status_line "Timeshift-snaps" "AMBER" "No snapshots found (or could not parse list)"
    add_json "timeshift" "TimeshiftSnaps" "AMBER" "no_snapshots"
    return
  fi

  last_snap_epoch=$(date -d "$snap_date" +%s 2>/dev/null || echo 0)
  now_epoch=$(date +%s)
  days_ago=$(( (now_epoch - last_snap_epoch) / 86400 ))

  if [[ $days_ago -ge $SNAP_RED_DAYS ]]; then
    status_line "Timeshift-age" "RED" "Last snapshot: $snap_date (${days_ago} days ago — >${SNAP_RED_DAYS}d threshold)"
    add_json "timeshift" "TimeshiftAge" "RED" "last=$snap_date days_ago=$days_ago"
  elif [[ $days_ago -ge $SNAP_AMBER_DAYS ]]; then
    status_line "Timeshift-age" "AMBER" "Last snapshot: $snap_date (${days_ago} days ago — >${SNAP_AMBER_DAYS}d threshold)"
    add_json "timeshift" "TimeshiftAge" "AMBER" "last=$snap_date days_ago=$days_ago"
  else
    status_line "Timeshift-age" "GREEN" "Last snapshot: $snap_date (${days_ago} days ago)"
    add_json "timeshift" "TimeshiftAge" "GREEN" "last=$snap_date days_ago=$days_ago"
  fi

  # Count snapshots
  local snap_count
  snap_count=$(echo "$ts_out" | grep -cE '^\s*[0-9]+\s+>' || echo 0)
  status_line "Timeshift-count" "INFO" "$snap_count snapshot(s) found"

  # Snapshot destination space
  local snap_dest
  snap_dest=$(timeshift --list 2>/dev/null | grep 'Snapshot Device' | awk '{print $NF}' || true)
  if [[ -n "$snap_dest" ]]; then
    local snap_pct
    snap_pct=$(df -P "$snap_dest" 2>/dev/null | awk 'NR==2{print $5}' | tr -d '%' || echo 0)
    if [[ $snap_pct -ge $DISK_RED ]]; then
      status_line "Timeshift-space" "RED" "Snapshot device $snap_dest is ${snap_pct}% full"
      add_json "timeshift" "TimeshiftSpace" "RED" "pct=$snap_pct device=$snap_dest"
    elif [[ $snap_pct -ge $DISK_AMBER ]]; then
      status_line "Timeshift-space" "AMBER" "Snapshot device $snap_dest is ${snap_pct}% full"
    else
      status_line "Timeshift-space" "GREEN" "Snapshot device $snap_dest: ${snap_pct}% used"
    fi
  fi

  # Timeshift log errors
  local ts_log="/var/log/timeshift.log"
  if [[ -f "$ts_log" ]]; then
    local ts_err
    ts_err=$(grep -iE 'error|fail|warn' "$ts_log" 2>/dev/null | tail -20 || true)
    [[ -n "$ts_err" ]] && echo "$ts_err" > "$LOGS_DIR/timeshift_errors.txt"
    local err_count; err_count=$(echo -n "$ts_err" | wc -l)
    [[ $err_count -gt 0 ]] && status_line "Timeshift-log" "AMBER" "$err_count error/warn lines in $ts_log" \
      && add_json "timeshift" "TimeshiftLog" "AMBER" "err_lines=$err_count"
  fi
}

# ---------------------------------------------------------------------------
# SECTION: UFW
# ---------------------------------------------------------------------------
check_ufw() {
  section "UFW FIREWALL"

  if ! command -v ufw &>/dev/null; then
    status_line "UFW" "AMBER" "ufw not installed"
    add_json "ufw" "UFW" "AMBER" "not_installed"
    return
  fi

  run_silent "ufw-status" $CMD_TIMEOUT ufw status verbose
  echo "$RUN_OUT"

  local ufw_state
  ufw_state=$(echo "$RUN_OUT" | grep '^Status:' | awk '{print $2}')

  # State check
  if [[ -n "$EXPECTED_UFW_STATE" ]]; then
    if [[ "$ufw_state" == "$EXPECTED_UFW_STATE" ]]; then
      status_line "UFW-state" "GREEN" "UFW is $ufw_state (as expected)"
      add_json "ufw" "UFWState" "GREEN" "state=$ufw_state"
    else
      status_line "UFW-state" "RED" "UFW is $ufw_state but expected $EXPECTED_UFW_STATE"
      add_json "ufw" "UFWState" "RED" "state=$ufw_state expected=$EXPECTED_UFW_STATE"
    fi
  else
    status_line "UFW-state" "INFO" "UFW status: $ufw_state"
  fi

  # Check UFW is NOT blocking NX ports
  if [[ "$ufw_state" == "active" ]]; then
    IFS=',' read -ra NX_PORT_LIST <<< "$NX_PORTS"
    for port in "${NX_PORT_LIST[@]}"; do
      port=$(echo "$port" | tr -d ' ')
      # Check if port is explicitly denied or not explicitly allowed
      local rule
      rule=$(echo "$RUN_OUT" | grep -E "^$port\s|^$port/")
      if echo "$rule" | grep -qi 'DENY\|REJECT'; then
        status_line "UFW-NX[$port]" "RED" "UFW DENIES NX port $port — recording/API will fail"
        add_json "ufw" "UFWNXPort" "RED" "port=$port blocked"
      elif echo "$rule" | grep -qi 'ALLOW'; then
        status_line "UFW-NX[$port]" "GREEN" "UFW ALLOWS port $port"
      else
        status_line "UFW-NX[$port]" "AMBER" "Port $port has no explicit UFW rule (check default policy)"
        add_json "ufw" "UFWNXPort" "AMBER" "port=$port no_rule"
      fi
    done

    # Check Tailscale interface
    local ts_iface
    ts_iface=$(ip link show 2>/dev/null | grep tailscale | awk -F': ' '{print $2}' | head -1 || true)
    if [[ -n "$ts_iface" ]]; then
      if echo "$RUN_OUT" | grep -qiE "Allow IN on $ts_iface|$ts_iface.*ALLOW"; then
        status_line "UFW-Tailscale" "GREEN" "Tailscale interface $ts_iface allowed"
      else
        status_line "UFW-Tailscale" "AMBER" "No explicit UFW rule for Tailscale interface $ts_iface"
        add_json "ufw" "UFWTailscale" "AMBER" "no_tailscale_rule iface=$ts_iface"
      fi
    fi

    # UFW logging state
    local ufw_log_state
    ufw_log_state=$(echo "$RUN_OUT" | grep 'Logging:' | awk '{print $2}')
    if [[ "$ufw_log_state" == "off" ]] || [[ -z "$ufw_log_state" ]]; then
      status_line "UFW-logging" "AMBER" "UFW logging is off — blocked connections won't be logged"
      add_json "ufw" "UFWLogging" "AMBER" "logging=off"
    else
      status_line "UFW-logging" "GREEN" "UFW logging: $ufw_log_state"
    fi

    # Recent UFW denies
    local ufw_log="/var/log/ufw.log"
    if [[ -f "$ufw_log" ]]; then
      local recent_blocks
      recent_blocks=$(grep 'BLOCK\|DPT=7001\|DPT=7002\|DPT=7004' "$ufw_log" 2>/dev/null \
        | tail -50 || true)
      local block_count; block_count=$(echo -n "$recent_blocks" | grep -c 'BLOCK' || echo 0)
      [[ $block_count -gt 0 ]] && echo "$recent_blocks" > "$LOGS_DIR/ufw_blocks.txt"
      status_line "UFW-recent-blocks" "INFO" "$block_count recent BLOCK entries in $ufw_log"
      # Highlight if NX ports blocked
      local nx_blocks
      nx_blocks=$(echo "$recent_blocks" | grep -E 'DPT=(7001|7002|7004)' || true)
      if [[ -n "$nx_blocks" ]]; then
        status_line "UFW-NX-blocks" "RED" "UFW is actively blocking NX port traffic — check rules"
        add_json "ufw" "UFWNXBlocks" "RED" "NX ports being blocked"
      fi
    fi
  fi
}

# ---------------------------------------------------------------------------
# SECTION: Tailscale
# ---------------------------------------------------------------------------
check_tailscale() {
  section "TAILSCALE VPN"

  if ! command -v tailscale &>/dev/null; then
    if $REQUIRE_TAILSCALE; then
      status_line "Tailscale" "RED" "tailscale not installed (required)"
      add_json "tailscale" "Tailscale" "RED" "not_installed required=true"
    else
      status_line "Tailscale" "AMBER" "tailscale not installed"
      add_json "tailscale" "Tailscale" "AMBER" "not_installed"
    fi
    return
  fi

  # Daemon status
  local ts_daemon_active
  ts_daemon_active=$(systemctl is-active tailscaled 2>/dev/null || echo "inactive")
  if [[ "$ts_daemon_active" != "active" ]]; then
    if $REQUIRE_TAILSCALE; then
      status_line "Tailscale-daemon" "RED" "tailscaled is not running (required)"
      add_json "tailscale" "TailscaleDaemon" "RED" "daemon=inactive required=true"
    else
      status_line "Tailscale-daemon" "AMBER" "tailscaled is not running"
      add_json "tailscale" "TailscaleDaemon" "AMBER" "daemon=inactive"
    fi
    return
  fi
  status_line "Tailscale-daemon" "GREEN" "tailscaled active"

  # Tailscale status
  run_silent "tailscale-status" $CMD_TIMEOUT tailscale status
  local ts_status_out="$RUN_OUT"
  echo "$ts_status_out" | head -40
  echo "$ts_status_out" > "$CMDS_DIR/tailscale_status.txt"

  local ts_auth
  ts_auth=$(echo "$ts_status_out" | grep -c 'Logged in' || echo 0)
  local ts_backend
  ts_backend=$(echo "$ts_status_out" | head -1)

  if echo "$ts_status_out" | grep -qiE 'logged out|needs login|unauthorized|not logged in'; then
    if $REQUIRE_TAILSCALE; then
      status_line "Tailscale-auth" "RED" "Not authenticated to Tailscale"
      add_json "tailscale" "TailscaleAuth" "RED" "not_authenticated"
    else
      status_line "Tailscale-auth" "AMBER" "Not authenticated to Tailscale"
      add_json "tailscale" "TailscaleAuth" "AMBER" "not_authenticated"
    fi
    return
  fi

  status_line "Tailscale-auth" "GREEN" "Authenticated"

  # IPs
  run_silent "tailscale-ip4" $CMD_TIMEOUT tailscale ip -4
  local ts_ipv4="$RUN_OUT"
  run_silent "tailscale-ip6" $CMD_TIMEOUT tailscale ip -6
  local ts_ipv6="$RUN_OUT"
  status_line "Tailscale-IP" "GREEN" "IPv4=$ts_ipv4 IPv6=$ts_ipv6"
  add_json "tailscale" "TailscaleIP" "GREEN" "ipv4=$ts_ipv4 ipv6=$ts_ipv6"

  # Peer count
  local peer_count
  peer_count=$(echo "$ts_status_out" | grep -c 'active\|idle' 2>/dev/null || echo "?")
  status_line "Tailscale-peers" "INFO" "Peers visible: $peer_count"

  # Netcheck (if available in full mode)
  if [[ "$MODE" == "full" ]] || [[ "$MODE" == "normal" ]]; then
    if tailscale netcheck --help &>/dev/null 2>&1; then
      run_silent "tailscale-netcheck" 20 tailscale netcheck
      echo "$RUN_OUT" | head -30
      echo "$RUN_OUT" > "$CMDS_DIR/tailscale_netcheck.txt"
      if echo "$RUN_OUT" | grep -qi 'error\|fail'; then
        status_line "Tailscale-netcheck" "AMBER" "netcheck reports issues"
        add_json "tailscale" "TailscaleNetcheck" "AMBER" "netcheck_issues"
      else
        status_line "Tailscale-netcheck" "GREEN" "netcheck completed OK"
      fi
    fi
  fi
}

# ---------------------------------------------------------------------------
# SECTION: Log highlights (journal + syslog)
# ---------------------------------------------------------------------------
check_logs() {
  section "LOG HIGHLIGHTS (last $SINCE)"

  [[ "$MODE" == "quick" ]] && { status_line "Logs" "INFO" "Skipped in --quick mode"; return; }

  # Journal
  if command -v journalctl &>/dev/null; then
    echo -e "${C_DIM}── systemd journal errors/warnings ──${C_RESET}"
    local since_journal
    case "$SINCE" in
      *h) since_journal="${SINCE%h} hour ago" ;;
      *d) since_journal="${SINCE%d} day ago" ;;
      [0-9][0-9][0-9][0-9]-*) since_journal="$SINCE" ;;
      *) since_journal="24 hour ago" ;;
    esac
    local j_out
    j_out=$(timeout 15 journalctl --since "$since_journal" -p err -q --no-pager \
      --output=short-iso 2>/dev/null | head -100 || true)
    [[ -n "$j_out" ]] && echo "$j_out" | head -50 && echo "$j_out" > "$LOGS_DIR/journal_errors.txt"
    local err_cnt; err_cnt=$(echo -n "$j_out" | wc -l)
    if [[ $err_cnt -gt 50 ]]; then
      status_line "Journal-errors" "AMBER" "$err_cnt error-level journal entries in $SINCE"
      add_json "logs" "Journal" "AMBER" "count=$err_cnt"
    else
      status_line "Journal-errors" "GREEN" "$err_cnt error-level journal entries in $SINCE"
    fi
  fi

  # syslog
  if [[ -f /var/log/syslog ]]; then
    grep -iE 'error|fail|crit|alert|emerg' /var/log/syslog 2>/dev/null | tail -50 > "$LOGS_DIR/syslog_errors.txt" || true
  fi
  [[ -f /var/log/kern.log ]] && tail -200 /var/log/kern.log > "$LOGS_DIR/kern.log" 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# SUMMARY
# ---------------------------------------------------------------------------
print_summary() {
  section "DIAGNOSTIC SUMMARY"

  echo -e "${C_BOLD}  Timestamp : $STARTED_AT${C_RESET}"
  echo -e "${C_BOLD}  Hostname  : $(hostname -s 2>/dev/null || echo '?')${C_RESET}"
  echo -e "${C_BOLD}  BOX_ID    : ${BOX_ID:-UNKNOWN}${C_RESET}"
  echo -e "${C_BOLD}  Router IP : ${ROUTER_IP:-UNKNOWN}${C_RESET}"
  echo -e "${C_BOLD}  Mode      : $MODE${C_RESET}"
  echo ""
  echo -e "  ${C_RED}RED  : $COUNT_RED${C_RESET}   ${C_AMBER}AMBER: $COUNT_AMBER${C_RESET}   ${C_GREEN}GREEN: $COUNT_GREEN${C_RESET}"
  echo ""

  if [[ ${#ACTIONS_RED[@]} -gt 0 ]] || [[ ${#ACTIONS_AMBER[@]} -gt 0 ]]; then
    echo -e "${C_BOLD}  TOP ACTIONS RECOMMENDED:${C_RESET}"
    local i=1
    for a in "${ACTIONS_RED[@]}"; do
      echo -e "    ${C_RED}$i. [RED]${C_RESET} $a"
      (( i++ )) || true
      [[ $i -gt 5 ]] && break
    done
    for a in "${ACTIONS_AMBER[@]}"; do
      [[ $i -gt 5 ]] && break
      echo -e "    ${C_AMBER}$i. [AMBER]${C_RESET} $a"
      (( i++ )) || true
    done
    [[ $i -eq 1 ]] && echo -e "    ${C_GREEN}No action items — system appears healthy${C_RESET}"
  else
    echo -e "    ${C_GREEN}✓ All checks passed — system appears healthy${C_RESET}"
  fi
  echo ""
}

# ---------------------------------------------------------------------------
# JSON OUTPUT
# ---------------------------------------------------------------------------
write_json() {
  local meta
  meta=$(printf '{"timestamp":"%s","hostname":"%s","box_id":"%s","router_ip":"%s","mode":"%s","script_version":"%s","counts":{"red":%d,"amber":%d,"green":%d}}' \
    "$STARTED_AT" "$(hostname -s 2>/dev/null || echo '?')" "${BOX_ID:-unknown}" "${ROUTER_IP:-unknown}" "$MODE" \
    "$SCRIPT_VERSION" "$COUNT_RED" "$COUNT_AMBER" "$COUNT_GREEN")

  # Build JSON array from items
  local items_json="["
  local first=true
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    $first || items_json+=","
    items_json+="$line"
    first=false
  done <<< "$JSON_ITEMS"
  items_json+="]"

  printf '{"meta":%s,"findings":%s}\n' "$meta" "$items_json" > "$JSON_FILE"
}

# ---------------------------------------------------------------------------
# BUNDLE
# ---------------------------------------------------------------------------
create_bundle() {
  [[ "$DO_BUNDLE" != "true" ]] && return

  # Manifest
  {
    echo "CCTV Diagnostic Bundle"
    echo "Generated: $STARTED_AT"
    echo "BOX_ID: ${BOX_ID:-unknown}"
    echo ""
    echo "Files collected:"
    find "$WORK_DIR" -type f | sort | while read -r f; do
      echo "  ${f#$WORK_DIR/} ($(wc -c < "$f" 2>/dev/null || echo 0) bytes)"
    done
  } > "$WORK_DIR/MANIFEST.txt"

  local ts
  ts=$(date -u '+%Y%m%dT%H%M%SZ')
  local bundle_name="${SCRIPT_NAME}_box${BOX_ID:-unknown}_${ts}.tar.gz"
  local bundle_path="$OUTPUT_DIR/$bundle_name"

  mkdir -p "$OUTPUT_DIR"
  tar -czf "$bundle_path" -C "$(dirname "$WORK_DIR")" "$(basename "$WORK_DIR")" 2>/dev/null
  echo ""
  echo -e "${C_BOLD}📦 Support bundle: $bundle_path${C_RESET}"
  echo "   ($(du -sh "$bundle_path" 2>/dev/null | cut -f1) compressed)"
}

# ---------------------------------------------------------------------------
# PRINT HEADER
# ---------------------------------------------------------------------------
print_header() {
  echo -e "${C_CYAN}${C_BOLD}"
  echo "╔══════════════════════════════════════════════════════╗"
  echo "║       CCTV Camera Box Diagnostic Tool v$SCRIPT_VERSION        ║"
  echo "╚══════════════════════════════════════════════════════╝${C_RESET}"
  echo -e "${C_DIM}  Started: $STARTED_AT"
  echo -e "  Running as: $(id -un) (root: $IS_ROOT)"
  echo -e "  Mode: $MODE  |  Since: $SINCE${C_RESET}"
  echo ""
}

# ---------------------------------------------------------------------------
# COLLECT EXTRA SYSTEM INFO FOR BUNDLE
# ---------------------------------------------------------------------------
collect_system_info() {
  run_silent "uname"      $CMD_TIMEOUT uname -a
  run_silent "os-release" $CMD_TIMEOUT cat /etc/os-release
  run_silent "dmidecode"  $CMD_TIMEOUT dmidecode -t system 2>/dev/null || true
  run_silent "lshw"       $CMD_TIMEOUT lshw -short 2>/dev/null || true
  run_silent "lsblk"      $CMD_TIMEOUT lsblk -o NAME,SIZE,TYPE,MOUNTPOINT,FSTYPE
  run_silent "mount"      $CMD_TIMEOUT mount | grep -v 'proc\|sys\|devtmpfs\|cgroup' | head -40
  run_silent "ss"         $CMD_TIMEOUT ss -tlnp
  run_silent "dmesg-tail" $CMD_TIMEOUT dmesg | tail -100
  run_silent "ps-aux"     $CMD_TIMEOUT ps aux --sort=-%mem | head -30
  run_silent "journalctl-boot" $CMD_TIMEOUT journalctl -b -q --no-pager -n 100 2>/dev/null || true
  # Copy /var/log/ufw.log excerpt (bounded)
  [[ -f /var/log/ufw.log ]] && tail -500 /var/log/ufw.log > "$LOGS_DIR/ufw.log.tail" 2>/dev/null || true
  # Sanitise: ensure no private keys in bundle
  find "$CMDS_DIR" "$LOGS_DIR" -type f -exec \
    sed -i -E 's/(PRIVATE KEY|AUTH_KEY|SECRET|PASSWORD|TOKEN)[^a-zA-Z0-9][^\n]*/\1 *** REDACTED ***/gi' {} + 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------
main() {
  print_header
  detect_box_id
  check_identity
  check_networking
  check_router_wan
  check_time
  check_storage
  check_resources
  check_services
  check_witness_nx
  check_timeshift
  check_ufw
  check_tailscale
  check_logs
  collect_system_info
  write_json
  print_summary
  create_bundle
}

main
