#!/bin/bash

# PEPCTL Traffic Generator
# Usage: ./scripts/generate_real_traffic.sh [interface] [ip_address]
# Example: ./scripts/generate_real_traffic.sh enx00e099002775 192.168.3.66
# Example: ./scripts/generate_real_traffic.sh lo 127.0.0.1

set -e

# Default values
DEFAULT_INTERFACE="enx00e099002775"
DEFAULT_IP="192.168.3.66"

# Parse command line arguments
INTERFACE="${1:-$DEFAULT_INTERFACE}"
IP_ADDRESS="${2:-$DEFAULT_IP}"

# Validate interface exists
if ! ip link show "$INTERFACE" > /dev/null 2>&1; then
echo " Interface '$INTERFACE' not found!"
echo "Available interfaces:"
ip link show | grep -E '^[0-9]+:' | awk -F': ' '{print " " $2}' | sed 's/@.*//'
exit 1
fi

# Get network info
NETWORK_PREFIX=$(echo "$IP_ADDRESS" | cut -d. -f1-3)
GATEWAY="${NETWORK_PREFIX}.1"

echo " Generating Targeted Traffic for ALL PEPCTL Policy Categories"
echo "Interface: $INTERFACE ($IP_ADDRESS)"
echo "Network: ${NETWORK_PREFIX}.x"
echo "Gateway: $GATEWAY"
echo "=============================================================="
echo " Target: Generate ALLOW, BLOCK, LOG_ONLY, RATE_LIMIT packets"
echo " NOTE: Some traffic requires external sources or different approach"
echo

# Function to generate ALLOW traffic (ICMP pings)
generate_allow_traffic() {
echo " Generating ALLOW traffic (ICMP to $IP_ADDRESS)..."
echo " Policy: allow_ping_responses"

if [[ "$INTERFACE" == "lo" ]]; then
echo " Loopback interface - generating local pings"
ping -c 5 127.0.0.1 > /dev/null 2>&1 &
ping -c 3 localhost > /dev/null 2>&1 &
else
echo " Network interface - pinging gateway to generate ICMP traffic"
ping -c 5 "$GATEWAY" > /dev/null 2>&1 &
ping -c 3 "$GATEWAY" > /dev/null 2>&1 &
fi

sleep 0.5
echo " Generated ICMP packets"
}

# Function to generate BLOCK traffic (TCP to port 23)
generate_block_traffic() {
echo " Generating BLOCK traffic (TCP to $IP_ADDRESS:23)..."
echo " Policy: block_suspicious_port_scan"

if [[ "$INTERFACE" == "lo" ]]; then
echo " Loopback interface - attempting local connections"
timeout 1 telnet 127.0.0.1 23 > /dev/null 2>&1 &
timeout 1 nc -w 1 127.0.0.1 23 > /dev/null 2>&1 &
else
echo " Network interface - attempting connections to local network"
timeout 1 telnet "$GATEWAY" 23 > /dev/null 2>&1 &
timeout 1 nc -w 1 "$GATEWAY" 23 > /dev/null 2>&1 &

# Try scanning other IPs in the subnet
for i in {2..5}; do
local target_ip="${NETWORK_PREFIX}.${i}"
timeout 1 nc -w 1 "$target_ip" 23 > /dev/null 2>&1 &
sleep 0.1
done
fi

echo " Generated TCP connection attempts to port 23"
}

# Function to generate LOG_ONLY traffic (HTTP, HTTPS, DNS)
generate_log_only_traffic() {
echo " Generating LOG_ONLY traffic..."

# HTTP traffic (port 80)
echo " HTTP traffic (port 80)..."
curl -s --connect-timeout 2 --max-time 3 http://httpbin.org/get > /dev/null 2>&1 &
curl -s --connect-timeout 2 --max-time 3 http://example.com > /dev/null 2>&1 &
curl -s --connect-timeout 2 --max-time 3 http://google.com > /dev/null 2>&1 &

sleep 1

# HTTPS traffic (port 443)
echo " HTTPS traffic (port 443)..."
curl -s --connect-timeout 2 --max-time 3 https://httpbin.org/get > /dev/null 2>&1 &
curl -s --connect-timeout 2 --max-time 3 https://example.com > /dev/null 2>&1 &
curl -s --connect-timeout 2 --max-time 3 https://github.com > /dev/null 2>&1 &

sleep 1

# DNS queries (port 53)
echo " DNS queries (port 53)..."
nslookup google.com > /dev/null 2>&1 &
nslookup github.com > /dev/null 2>&1 &
nslookup stackoverflow.com > /dev/null 2>&1 &
dig @8.8.8.8 example.com > /dev/null 2>&1 &
dig @1.1.1.1 cloudflare.com > /dev/null 2>&1 &

echo " Generated HTTP, HTTPS, and DNS traffic"
}

# Function to generate RATE_LIMIT traffic (SSH attempts)
generate_rate_limit_traffic() {
echo " Generating RATE_LIMIT traffic (SSH to $IP_ADDRESS:22)..."
echo " Policy: rate_limit_ssh_attempts"

if [[ "$INTERFACE" == "lo" ]]; then
echo " Loopback interface - rapid SSH attempts to localhost"
for i in {1..5}; do
timeout 1 telnet 127.0.0.1 22 > /dev/null 2>&1 &
timeout 1 nc -w 1 127.0.0.1 22 > /dev/null 2>&1 &
sleep 0.1
done
else
echo " Network interface - rapid SSH attempts to local network"
for i in {1..5}; do
local target_ip="${NETWORK_PREFIX}.${i}"
timeout 1 telnet "$target_ip" 22 > /dev/null 2>&1 &
timeout 1 nc -w 1 "$target_ip" 22 > /dev/null 2>&1 &
sleep 0.1
done
fi

echo " Generated rapid SSH attempts"
}

# Function to generate local network traffic
generate_local_network_traffic() {
echo " Generating local network traffic..."
echo " Policy: log_local_network_traffic"

if [[ "$INTERFACE" == "lo" ]]; then
echo " Loopback interface - local TCP traffic"
for port in 80 443 8080; do
timeout 2 telnet 127.0.0.1 $port > /dev/null 2>&1 &
timeout 2 nc -w 1 127.0.0.1 $port > /dev/null 2>&1 &
sleep 0.2
done
else
echo " Network interface - TCP traffic within ${NETWORK_PREFIX}.x network"
for i in {1..5}; do
local target_ip="${NETWORK_PREFIX}.${i}"
for port in 80 443 8080; do
timeout 2 telnet "$target_ip" $port > /dev/null 2>&1 &
timeout 2 nc -w 1 "$target_ip" $port > /dev/null 2>&1 &
sleep 0.2
done
done
fi

echo " Generated local TCP traffic"
}

# Function to show current stats before traffic generation
show_before_stats() {
echo " BEFORE Traffic Generation:"
echo "=============================="
local stats_url="http://${IP_ADDRESS}:9090/stats"
curl -s "$stats_url" | jq -r '
" eBPF Packets: " + (.ebpf.packets_processed | tostring) + 
"\n Daemon Packets: " + (.daemon.packets_processed | tostring) +
"\n Allowed: " + (.daemon.packets_allowed | tostring) +
"\n Blocked: " + (.daemon.packets_blocked | tostring) + 
"\n Logged: " + (.daemon.packets_logged | tostring) +
"\n Rate Limited: " + (.daemon.packets_rate_limited | tostring)
' 2>/dev/null || echo "Could not fetch stats from $stats_url"
echo
}

# Function to show stats after traffic generation
show_after_stats() {
echo
echo " AFTER Traffic Generation:"
echo "============================="
local stats_url="http://${IP_ADDRESS}:9090/stats"
curl -s "$stats_url" | jq -r '
" eBPF Packets: " + (.ebpf.packets_processed | tostring) + 
"\n Daemon Packets: " + (.daemon.packets_processed | tostring) +
"\n Allowed: " + (.daemon.packets_allowed | tostring) +
"\n Blocked: " + (.daemon.packets_blocked | tostring) + 
"\n Logged: " + (.daemon.packets_logged | tostring) +
"\n Rate Limited: " + (.daemon.packets_rate_limited | tostring)
' 2>/dev/null || echo "Could not fetch stats from $stats_url"
echo
}

# Function to show policy-specific analysis
show_policy_analysis() {
echo
echo " POLICY ANALYSIS:"
echo "==================="
echo "Current policies and their matching criteria:"
echo "• allow_ping_responses: ICMP to $IP_ADDRESS (needs external ping TO us)"
echo "• block_suspicious_port_scan: TCP to $IP_ADDRESS:23 (needs external connection TO us)" 
echo "• log_all_http_traffic: TCP to any:80 (outbound HTTP should match)"
echo "• log_all_https_traffic: TCP to any:443 (outbound HTTPS should match)"
echo "• log_dns_queries: UDP to any:53 (outbound DNS should match)"
echo "• rate_limit_ssh_attempts: TCP to $IP_ADDRESS:22 (needs external SSH TO us)"
echo "• log_local_network_traffic: TCP from ${NETWORK_PREFIX}.x to $IP_ADDRESS (needs external local traffic TO us)"
echo
if [[ "$INTERFACE" != "lo" ]]; then
echo " LIMITATION: Many policies require INBOUND traffic TO $IP_ADDRESS"
echo " Self-generated traffic from $IP_ADDRESS won't match these policies!"
echo " For full testing, you need external machines to send traffic TO this host."
else
echo " LOOPBACK MODE: Traffic patterns may differ on loopback interface"
echo " Some XDP features may not work on loopback interface"
fi
echo
}

# Main execution
echo " Starting traffic generation for interface: $INTERFACE"
echo

show_before_stats
show_policy_analysis

echo " Starting targeted traffic generation..."
echo

# Generate traffic for each category with delays
generate_allow_traffic
sleep 2

generate_block_traffic 
sleep 2

generate_log_only_traffic
sleep 3

generate_rate_limit_traffic
sleep 2

generate_local_network_traffic
sleep 3

echo
echo "⏳ Waiting for all background processes to complete..."
wait

show_after_stats

echo " Traffic generation completed!"
echo
echo " Check detailed policy hits:"
echo " ./scripts/manage_policies.sh list"
echo " Check comprehensive stats:"
echo " ./scripts/manage_policies.sh stats"
echo
echo " USAGE EXAMPLES:"
echo " ./scripts/generate_real_traffic.sh enx00e099002775 192.168.3.66"
echo " ./scripts/generate_real_traffic.sh lo 127.0.0.1"
echo " ./scripts/generate_real_traffic.sh eth0 10.0.0.100" 