#!/usr/bin/env bash

# Run forever. Every INTERVAL seconds, attempt TCP connections to SERVER_IP on a list of ports.
# Errors are logged but ignored.
#
# Usage:
#   ./tests/sbc_traffic_forever.sh [server_ip] [interval_seconds]
#
# Environment overrides:
#   PORTS="22 23 80 443 8080 9090 3000 21"  (must be 8 ports if you want 8 connections)
#   LOG_FILE=/tmp/pepctl_sbc_traffic.log

set -u

SERVER_IP="${1:-192.168.3.28}"
INTERVAL_SECONDS="${2:-10}"

ALLOW_PORT="${ALLOW_PORT:-50080}"
LOG_ONLY_PORT="${LOG_ONLY_PORT:-50081}"
BLOCK_PORT="${BLOCK_PORT:-50082}"
RATE_LIMIT_PORT="${RATE_LIMIT_PORT:-50083}"

PORTS_STR="${PORTS:-"${ALLOW_PORT} ${ALLOW_PORT} ${LOG_ONLY_PORT} ${LOG_ONLY_PORT} ${BLOCK_PORT} ${BLOCK_PORT} ${RATE_LIMIT_PORT} ${RATE_LIMIT_PORT}"}"
LOG_FILE="${LOG_FILE:-""}"

log_line() {
    local line="$1"
    if [[ -n "$LOG_FILE" ]]; then
        printf '%s\n' "$line" >> "$LOG_FILE" 2>/dev/null || true
    fi
    printf '%s\n' "$line"
}

try_tcp_connect() {
    local ip="$1"
    local port="$2"

    if command -v timeout >/dev/null 2>&1; then
        timeout 2 bash -c "echo -n 'x' > /dev/tcp/${ip}/${port}" >/dev/null 2>&1
    else
        bash -c "echo -n 'x' > /dev/tcp/${ip}/${port}" >/dev/null 2>&1
    fi
}

IFS=' ' read -r -a PORTS <<< "$PORTS_STR"

if [[ ${#PORTS[@]} -lt 1 ]]; then
    log_line "[$(date '+%F %T')] ERROR: no ports configured"
    exit 1
fi

if [[ ${#PORTS[@]} -ne 8 ]]; then
    log_line "[$(date '+%F %T')] ERROR: expected exactly 8 ports (2 per category); got ${#PORTS[@]}"
    log_line "[$(date '+%F %T')] Hint: set PORTS or ALLOW_PORT/LOG_ONLY_PORT/BLOCK_PORT/RATE_LIMIT_PORT"
    exit 1
fi

log_line "[$(date '+%F %T')] Starting SBC traffic generator: server=${SERVER_IP} interval=${INTERVAL_SECONDS}s ports=${PORTS_STR}"
if [[ -n "$LOG_FILE" ]]; then
    log_line "[$(date '+%F %T')] Logging to: ${LOG_FILE}"
fi

while true; do
    loop_start="$(date '+%F %T')"
    log_line "[${loop_start}] Burst start"

    for idx in "${!PORTS[@]}"; do
        port="${PORTS[$idx]}"
        (
            ts="$(date '+%F %T')"
            if try_tcp_connect "$SERVER_IP" "$port"; then
                log_line "[${ts}] OK   tcp://${SERVER_IP}:${port}"
            else
                log_line "[${ts}] FAIL tcp://${SERVER_IP}:${port}"
            fi
        ) &
    done

    wait || true
    log_line "[$(date '+%F %T')] Burst done; sleeping ${INTERVAL_SECONDS}s"
    sleep "$INTERVAL_SECONDS" || true
done
