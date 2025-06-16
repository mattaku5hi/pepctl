#!/bin/bash

# PEPCTL Startup Script
# Usage: ./scripts/start_pepctl.sh [production|development|testing|loopback]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
CONFIG_DIR="$PROJECT_ROOT/configs"

# Default to development if no argument provided
ENVIRONMENT="${1:-development}"

# Validate environment
case "$ENVIRONMENT" in
production|development|testing|loopback)
;;
*)
echo " Invalid environment: $ENVIRONMENT"
echo "Usage: $0 [production|development|testing|loopback]"
exit 1
;;
esac

CONFIG_FILE="$CONFIG_DIR/$ENVIRONMENT.json"

# Check if config file exists
if [[ ! -f "$CONFIG_FILE" ]]; then
echo " Configuration file not found: $CONFIG_FILE"
exit 1
fi

# Check if pepctl binary exists
PEPCTL_BINARY="$PROJECT_ROOT/build/src/pepctl"
if [[ ! -f "$PEPCTL_BINARY" ]]; then
echo " PEPCTL binary not found: $PEPCTL_BINARY"
echo "Please build the project first: make -C build"
exit 1
fi

# Stop any existing pepctl instances
echo " Stopping any existing pepctl instances..."
sudo pkill -f pepctl || true

# Clean up old eBPF maps if needed
if [[ "$ENVIRONMENT" == "testing" ]]; then
echo " Cleaning up old eBPF maps for testing..."
sudo rm -f /sys/fs/bpf/stats_map /sys/fs/bpf/policy_map /sys/fs/bpf/packet_events
fi

# Start pepctl
echo " Starting PEPCTL in $ENVIRONMENT mode..."
echo " Config: $CONFIG_FILE"

sudo "$PEPCTL_BINARY" --config "$CONFIG_FILE" --daemon

echo " PEPCTL started successfully!"
echo " Metrics: http://localhost:9090/metrics"
echo " Admin API: http://localhost:8080/"

# Show log location
if [[ "$ENVIRONMENT" == "production" ]]; then
echo " Logs: /var/log/pepctl.log"
else
echo " Logs: /tmp/pepctl.log"
fi 