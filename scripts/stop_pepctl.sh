#!/bin/bash

# PEPCTL Stop Script
# Stops pepctl daemon and optionally cleans up eBPF resources

set -e

CLEAN_EBPF="${1:-false}"

echo " Stopping PEPCTL..."

# Stop pepctl processes
if pgrep -f pepctl > /dev/null; then
sudo pkill -f pepctl
echo " PEPCTL processes stopped"
else
echo " No PEPCTL processes found"
fi

# Clean up eBPF resources if requested
if [[ "$CLEAN_EBPF" == "clean" ]]; then
echo " Cleaning up eBPF resources..."

# Remove XDP programs
for iface in enx00e099002775 lo; do
if ip link show $iface 2>/dev/null | grep -q "prog/xdp"; then
sudo ip link set dev $iface xdp off 2>/dev/null || true
echo " Removed XDP from $iface"
fi
done

# Remove TC programs
for iface in enx00e099002775 lo; do
if tc qdisc show dev $iface 2>/dev/null | grep -q clsact; then
sudo tc qdisc del dev $iface clsact 2>/dev/null || true
echo " Removed TC from $iface"
fi
done

# Remove pinned maps
sudo rm -f /sys/fs/bpf/stats_map /sys/fs/bpf/policy_map /sys/fs/bpf/packet_events 2>/dev/null || true
sudo rm -rf /sys/fs/bpf/xdp/ 2>/dev/null || true
echo " Removed pinned eBPF maps"

echo " eBPF cleanup completed"
fi

echo " PEPCTL shutdown complete"

# Usage information
if [[ "$CLEAN_EBPF" != "clean" ]]; then
echo ""
echo " To also clean up eBPF resources, run:"
echo " $0 clean"
fi 