#!/bin/bash

# PEPCTL Traffic Generator and Test Script
# Generates various types of network traffic to test eBPF packet processing

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
PEPCTL_STATS_URL="http://127.0.0.1:9090/stats"
PEPCTL_METRICS_URL="http://127.0.0.1:9090/metrics"
PROMETHEUS_URL="http://127.0.0.1:9091"
GRAFANA_URL="http://127.0.0.1:3000"
TEST_DURATION=60 # seconds
TRAFFIC_INTERVAL=10 # seconds between traffic bursts

echo -e "${BLUE} PEPCTL Traffic Generator and Monitoring Test${NC}"
echo -e "${BLUE}================================================${NC}"

# Function to print colored output
print_status() {
echo -e "${GREEN}[$(date '+%H:%M:%S')] $1${NC}"
}

print_warning() {
echo -e "${YELLOW}[$(date '+%H:%M:%S')] WARNING: $1${NC}"
}

print_error() {
echo -e "${RED}[$(date '+%H:%M:%S')] ERROR: $1${NC}"
}

# Function to check if services are running
check_services() {
print_status "Checking PEPCTL services..."

# Check PEPCTL daemon
if curl -s "$PEPCTL_STATS_URL" > /dev/null; then
print_status " PEPCTL daemon is running"
else
print_error " PEPCTL daemon is not accessible"
exit 1
fi

# Check Prometheus
if curl -s "$PROMETHEUS_URL" > /dev/null; then
print_status " Prometheus is running"
else
print_warning "️ Prometheus is not accessible"
fi

# Check Grafana
if curl -s "$GRAFANA_URL/api/health" > /dev/null; then
print_status " Grafana is running"
else
print_warning "️ Grafana is not accessible"
fi
}

# Function to get current packet statistics
get_stats() {
local stats=$(curl -s "$PEPCTL_STATS_URL" | jq -r '.ebpf.packets_processed // 0')
echo "$stats"
}

# Function to generate ICMP traffic (ping)
generate_icmp_traffic() {
print_status " Generating ICMP traffic (ping)..."
for i in {1..10}; do
ping -c 3 -i 0.2 127.0.0.1 > /dev/null 2>&1 &
done
wait
}

# Function to generate TCP traffic
generate_tcp_traffic() {
print_status " Generating TCP traffic..."
for port in 8080 9090 3000; do
for i in {1..5}; do
curl -s --connect-timeout 1 "http://127.0.0.1:$port" > /dev/null 2>&1 &
done
done
wait
}

# Function to generate UDP traffic
generate_udp_traffic() {
print_status " Generating UDP traffic..."
for i in {1..10}; do
echo "test packet $i" | nc -u -w1 127.0.0.1 53 > /dev/null 2>&1 &
done
wait
}

# Function to generate mixed traffic burst
generate_traffic_burst() {
local burst_id=$1
print_status " Traffic Burst #$burst_id"

# Get initial stats
local initial_packets=$(get_stats)

# Generate different types of traffic
generate_icmp_traffic &
generate_tcp_traffic &
generate_udp_traffic &

# Wait for all traffic to complete
wait

# Get final stats
sleep 2 # Allow time for stats to update
local final_packets=$(get_stats)
local packets_generated=$((final_packets - initial_packets))

print_status " Burst #$burst_id generated ~$packets_generated packets"
print_status " Total packets processed: $final_packets"
}

# Function to display real-time statistics
show_realtime_stats() {
print_status " Real-time Statistics:"

# PEPCTL Stats
local pepctl_stats=$(curl -s "$PEPCTL_STATS_URL" | jq -r '
"PEPCTL Stats:",
" eBPF Packets: \(.ebpf.packets_processed // 0)",
" Uptime: \(.uptime_seconds // 0)s",
" Policies: \(.policies.total_count // 0)"
')
echo -e "${BLUE}$pepctl_stats${NC}"

# Prometheus Stats (if available)
if curl -s "$PROMETHEUS_URL" > /dev/null; then
local prom_packets=$(curl -s "$PROMETHEUS_URL/api/v1/query?query=pepctl_ebpf_packets_processed_total" | jq -r '.data.result[0].value[1] // "N/A"')
local prom_rate=$(curl -s "$PROMETHEUS_URL/api/v1/query?query=rate(pepctl_ebpf_packets_processed_total[1m])" | jq -r '.data.result[0].value[1] // "0"')
echo -e "${BLUE}Prometheus Stats:${NC}"
echo -e "${BLUE} Total Packets: $prom_packets${NC}"
echo -e "${BLUE} Rate (pkt/s): $(printf "%.2f" $prom_rate)${NC}"
fi
}

# Function to run continuous monitoring
run_continuous_test() {
print_status " Starting continuous traffic generation for $TEST_DURATION seconds..."

local start_time=$(date +%s)
local end_time=$((start_time + TEST_DURATION))
local burst_count=1

while [ $(date +%s) -lt $end_time ]; do
generate_traffic_burst $burst_count
show_realtime_stats
echo ""

burst_count=$((burst_count + 1))
sleep $TRAFFIC_INTERVAL
done

print_status " Continuous test completed!"
}

# Function to test monitoring endpoints
test_monitoring_endpoints() {
print_status " Testing monitoring endpoints..."

echo -e "${BLUE}PEPCTL Endpoints:${NC}"
echo " Stats: $PEPCTL_STATS_URL"
echo " Metrics: $PEPCTL_METRICS_URL"
echo " Health: http://127.0.0.1:9090/health"

echo -e "${BLUE}Monitoring Stack:${NC}"
echo " Prometheus: $PROMETHEUS_URL"
echo " Grafana: $GRAFANA_URL (admin/pepctl123)"

echo -e "${BLUE}Direct Dashboard URL:${NC}"
echo " http://localhost:3000/d/4b0d8d4e-6ec5-461b-8943-69fd8c8af23c/pepctl-network-policy-enforcement-dashboard"
}

# Main execution
main() {
case "${1:-continuous}" in
"check")
check_services
;;
"burst")
check_services
generate_traffic_burst 1
show_realtime_stats
;;
"continuous")
check_services
run_continuous_test
;;
"stats")
show_realtime_stats
;;
"endpoints")
test_monitoring_endpoints
;;
"help")
echo "Usage: $0 [check|burst|continuous|stats|endpoints|help]"
echo " check - Check if all services are running"
echo " burst - Generate single traffic burst"
echo " continuous - Run continuous traffic generation (default)"
echo " stats - Show current statistics"
echo " endpoints - Show monitoring endpoints"
echo " help - Show this help"
;;
*)
print_error "Unknown command: $1"
echo "Use '$0 help' for usage information"
exit 1
;;
esac
}

# Run main function with all arguments
main "$@" 