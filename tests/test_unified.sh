#!/bin/bash

# PEPCTL Unified Testing Script
# Consolidates functionality from multiple test scripts

set -euo pipefail

# Configuration
PEPCTL_API_URL="http://127.0.0.1:9090"
ADMIN_URL="http://127.0.0.1:8080"
SLEEP_TIME=3
VERBOSE=false

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Test modes
MODE=""
POLICIES_FILE=""
TRAFFIC_INTENSITY="normal" # light, normal, heavy

# Print usage
usage() {
cat << EOF
PEPCTL Unified Testing Script

Usage: $0 [OPTIONS] MODE

MODES:
traffic-only Generate traffic without policies (basic testing)
policies-with-traffic Load policies and test all packet categories
metrics-demo Demonstrate all metrics with traffic
comprehensive Full test suite (policies + traffic + metrics)
quick Quick smoke test

OPTIONS:
-p, --policies FILE Policy file to load (default: auto-select)
-i, --intensity LEVEL Traffic intensity: light|normal|heavy (default: normal)
-u, --url URL PEPCTL API URL (default: $PEPCTL_API_URL)
-v, --verbose Verbose output
-h, --help Show this help

EXAMPLES:
# Quick smoke test
$0 quick

# Test with custom policies
$0 -p test_comprehensive_policies.json policies-with-traffic

# Heavy traffic testing
$0 -i heavy traffic-only

# Full comprehensive test
$0 comprehensive

EOF
}

# Logging functions
log_info() {
echo -e "${BLUE}[$(date '+%H:%M:%S')] INFO: $1${NC}"
}

log_success() {
echo -e "${GREEN}[$(date '+%H:%M:%S')] SUCCESS: $1${NC}"
}

log_warning() {
echo -e "${YELLOW}[$(date '+%H:%M:%S')] WARNING: $1${NC}"
}

log_error() {
echo -e "${RED}[$(date '+%H:%M:%S')] ERROR: $1${NC}"
}

log_test() {
echo -e "${PURPLE}[$(date '+%H:%M:%S')] TEST: $1${NC}"
}

log_verbose() {
if [[ "$VERBOSE" == "true" ]]; then
echo -e "${CYAN}[$(date '+%H:%M:%S')] VERBOSE: $1${NC}"
fi
}

# Check if PEPCTL daemon is running
check_daemon() {
log_verbose "Checking if PEPCTL daemon is running..."

if ! curl -s --connect-timeout 5 "$PEPCTL_API_URL/stats" > /dev/null 2>&1; then
log_error "PEPCTL daemon is not running or not accessible at $PEPCTL_API_URL"
log_info "Please start the daemon first: sudo ./build/src/pepctl --config tests/test_config.json --daemon"
exit 1
fi

log_verbose "PEPCTL daemon is running"
}

# Get current metrics
get_metrics() {
echo -e "${CYAN} Current Packet Statistics:${NC}"
local stats=$(curl -s "$PEPCTL_API_URL/stats" 2>/dev/null)

if echo "$stats" | jq empty 2>/dev/null; then
echo " Service: $(echo "$stats" | jq -r '.service')"
echo " Uptime: $(echo "$stats" | jq -r '.uptime_seconds')s"
echo " Policies: $(echo "$stats" | jq -r '.policies.total_count')"
echo " eBPF Processed: $(echo "$stats" | jq -r '.ebpf.packets_processed')"
echo " Daemon Processed: $(echo "$stats" | jq -r '.daemon.packets_processed')"
echo " Allowed: $(echo "$stats" | jq -r '.daemon.packets_allowed')"
echo " Blocked: $(echo "$stats" | jq -r '.daemon.packets_blocked')"
echo " Logged: $(echo "$stats" | jq -r '.daemon.packets_logged')"
echo " Rate-limited: $(echo "$stats" | jq -r '.daemon.packets_rate_limited')"
else
log_error "Failed to get metrics"
fi
echo
}

# Get detailed metrics breakdown
get_detailed_metrics() {
echo -e "${PURPLE} Detailed Metrics Breakdown:${NC}"
curl -s "$PEPCTL_API_URL/metrics" 2>/dev/null | grep -E "pepctl_daemon_packets_.*_total [0-9]" | while read line; do
metric=$(echo "$line" | awk '{print $1}' | sed 's/pepctl_daemon_packets_//' | sed 's/_total//')
value=$(echo "$line" | awk '{print $2}')
printf " %-15s: %s\n" "$metric" "$value"
done
echo
}

# List current policies
list_policies() {
log_info "Current policies:"
local policies=$(curl -s "$PEPCTL_API_URL/policies" 2>/dev/null)

if echo "$policies" | jq empty 2>/dev/null; then
local count=$(echo "$policies" | jq length)
if [[ "$count" -eq 0 ]]; then
log_warning "No policies loaded"
else
echo "$policies" | jq -r '.[] | " \(.id): \(.action) \(.src.protocol) \(.src.ip):\(.src.port) \(.dst.ip):\(.dst.port) (hits: \(.hit_count))"'
log_info "Total policies: $count"
fi
else
log_error "Failed to get policies"
fi
echo
}

# Load policies from file
load_policies() {
local policies_file="$1"

if [[ ! -f "$policies_file" ]]; then
log_error "Policies file not found: $policies_file"
return 1
fi

log_info "Loading policies from: $policies_file"

# Validate JSON first
if ! jq empty "$policies_file" 2>/dev/null; then
log_error "Invalid JSON in policies file: $policies_file"
return 1
fi

# Show policies being loaded if verbose
if [[ "$VERBOSE" == "true" ]]; then
log_verbose "Policies to be loaded:"
jq -r '.[] | " - ID: \(.id), Action: \(.action)"' "$policies_file"
fi

# Load policies
local response=$(curl -s -X POST \
-H "Content-Type: application/json" \
-d @"$policies_file" \
"$PEPCTL_API_URL/policies" 2>/dev/null)

if echo "$response" | jq -e '.status == "success"' > /dev/null 2>&1; then
local count=$(jq length "$policies_file")
log_success "Successfully loaded $count policies"
sleep 2 # Allow policies to sync
return 0
else
log_error "Failed to load policies"
if [[ "$VERBOSE" == "true" ]]; then
echo "Response: $response"
fi
return 1
fi
}

# Traffic generation functions
generate_icmp_traffic() {
local intensity="$1"
log_test "Generating ICMP traffic (intensity: $intensity)"

case "$intensity" in
light)
ping -c 5 -i 0.5 127.0.0.1 >/dev/null 2>&1 &
;;
normal)
ping -c 10 -i 0.2 127.0.0.1 >/dev/null 2>&1 &
ping -c 5 -s 1000 127.0.0.1 >/dev/null 2>&1 &
;;
heavy)
ping -c 20 -i 0.05 127.0.0.1 >/dev/null 2>&1 &
ping -c 10 -s 1000 127.0.0.1 >/dev/null 2>&1 &
ping -c 15 -i 0.1 127.0.0.1 >/dev/null 2>&1 &
;;
esac
}

generate_tcp_traffic() {
local intensity="$1"
log_test "Generating TCP traffic (intensity: $intensity)"

local ports=(22 80 443 8080 9090 3000)
local iterations

case "$intensity" in
light) iterations=2 ;;
normal) iterations=5 ;;
heavy) iterations=10 ;;
esac

for port in "${ports[@]}"; do
for i in $(seq 1 $iterations); do
curl -s --connect-timeout 1 "http://127.0.0.1:$port" >/dev/null 2>&1 &
nc -z 127.0.0.1 $port >/dev/null 2>&1 &
done
done
}

generate_udp_traffic() {
local intensity="$1"
log_test "Generating UDP traffic (intensity: $intensity)"

local ports=(53 123 161 514)
local iterations

case "$intensity" in
light) iterations=3 ;;
normal) iterations=8 ;;
heavy) iterations=15 ;;
esac

for port in "${ports[@]}"; do
for i in $(seq 1 $iterations); do
echo "test packet $i" | nc -u -w1 127.0.0.1 $port >/dev/null 2>&1 &
done
done
}

generate_mixed_traffic() {
local intensity="$1"
log_test "Generating mixed protocol traffic (intensity: $intensity)"

generate_icmp_traffic "$intensity"
generate_tcp_traffic "$intensity"
generate_udp_traffic "$intensity"

wait # Wait for all background processes
}

# Test modes
test_traffic_only() {
log_info " Traffic-Only Testing Mode"
echo "Generating traffic without specific policies (default ALLOW behavior)"
echo

get_metrics

log_info "Generating traffic..."
generate_mixed_traffic "$TRAFFIC_INTENSITY"

sleep $SLEEP_TIME
log_success "Traffic generation completed"
get_metrics
}

test_policies_with_traffic() {
log_info " Policies-with-Traffic Testing Mode"
echo "Loading policies and testing all packet categories"
echo

# Determine policies file
if [[ -z "$POLICIES_FILE" ]]; then
# Auto-select policies file
if [[ -f "test_icmp_comprehensive.json" ]]; then
POLICIES_FILE="test_icmp_comprehensive.json"
elif [[ -f "policies/test_comprehensive_policies.json" ]]; then
POLICIES_FILE="policies/test_comprehensive_policies.json"
else
log_error "No policies file found. Please specify with -p option."
return 1
fi
fi

log_info "Initial state:"
get_metrics
list_policies

# Load policies
if load_policies "$POLICIES_FILE"; then
log_success "Policies loaded successfully"
list_policies
else
log_error "Failed to load policies, continuing with default behavior"
fi

# Generate traffic for each category
log_info "Testing ICMP traffic (should trigger policies)..."
generate_icmp_traffic "$TRAFFIC_INTENSITY"
sleep $SLEEP_TIME
get_metrics

log_info "Testing TCP traffic (should trigger policies)..."
generate_tcp_traffic "$TRAFFIC_INTENSITY"
sleep $SLEEP_TIME
get_metrics

log_info "Testing UDP traffic (should trigger policies)..."
generate_udp_traffic "$TRAFFIC_INTENSITY"
sleep $SLEEP_TIME
get_metrics

log_success "Policy testing completed"
}

test_metrics_demo() {
log_info " Metrics Demo Mode"
echo "Demonstrating all metrics with targeted traffic"
echo

get_metrics
get_detailed_metrics

# Generate traffic in waves
for wave in 1 2 3; do
log_info "Traffic wave $wave..."
generate_mixed_traffic "normal"
sleep 2
get_metrics
done

log_success "Metrics demonstration completed"
get_detailed_metrics
}

test_comprehensive() {
log_info " Comprehensive Testing Mode"
echo "Full test suite: policies + traffic + metrics"
echo

# Run all test modes
test_policies_with_traffic
echo
test_metrics_demo

log_success "Comprehensive testing completed"
}

test_quick() {
log_info " Quick Smoke Test"
echo "Basic functionality check"
echo

get_metrics

log_info "Generating light traffic..."
generate_mixed_traffic "light"
sleep 2

get_metrics
log_success "Quick test completed"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
case $1 in
-p|--policies)
POLICIES_FILE="$2"
shift 2
;;
-i|--intensity)
TRAFFIC_INTENSITY="$2"
shift 2
;;
-u|--url)
PEPCTL_API_URL="$2"
shift 2
;;
-v|--verbose)
VERBOSE=true
shift
;;
-h|--help)
usage
exit 0
;;
traffic-only|policies-with-traffic|metrics-demo|comprehensive|quick)
MODE="$1"
shift
;;
*)
log_error "Unknown option: $1"
usage
exit 1
;;
esac
done

# Validate mode
if [[ -z "$MODE" ]]; then
log_error "No test mode specified"
usage
exit 1
fi

# Validate traffic intensity
if [[ ! "$TRAFFIC_INTENSITY" =~ ^(light|normal|heavy)$ ]]; then
log_error "Invalid traffic intensity: $TRAFFIC_INTENSITY"
usage
exit 1
fi

# Check dependencies
for cmd in curl jq; do
if ! command -v $cmd &> /dev/null; then
log_error "$cmd is required but not installed"
exit 1
fi
done

# Main execution
echo -e "${CYAN} PEPCTL Unified Testing Script${NC}"
echo -e "${CYAN}=================================${NC}"
log_info "Mode: $MODE"
log_info "Traffic intensity: $TRAFFIC_INTENSITY"
log_info "API URL: $PEPCTL_API_URL"
if [[ -n "$POLICIES_FILE" ]]; then
log_info "Policies file: $POLICIES_FILE"
fi
echo

# Check daemon
check_daemon

# Execute test mode
case "$MODE" in
traffic-only)
test_traffic_only
;;
policies-with-traffic)
test_policies_with_traffic
;;
metrics-demo)
test_metrics_demo
;;
comprehensive)
test_comprehensive
;;
quick)
test_quick
;;
esac

echo
log_success " Testing completed successfully!"
echo
echo -e "${CYAN} Check your monitoring dashboards:${NC}"
echo " - PEPCTL Stats: $PEPCTL_API_URL/stats"
echo " - Prometheus: http://localhost:9091/graph"
echo " - Grafana: http://localhost:3000 (admin/pepctl123)" 