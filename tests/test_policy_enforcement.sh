#!/bin/bash

# PEPCTL Policy Enforcement Test Script
# Tests policy enforcement with different protocols, ports, and traffic patterns

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

# Configuration
PEPCTL_ADMIN_URL="http://127.0.0.1:8080"
PEPCTL_STATS_URL="http://127.0.0.1:9090/stats"
PEPCTL_METRICS_URL="http://127.0.0.1:9090/metrics"
TEST_DURATION=30

echo -e "${BLUE} PEPCTL Policy Enforcement Test Suite${NC}"
echo -e "${BLUE}===========================================${NC}"

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

print_test() {
echo -e "${PURPLE}[$(date '+%H:%M:%S')] TEST: $1${NC}"
}

# Function to get current packet statistics
get_stats() {
curl -s "$PEPCTL_STATS_URL" | jq -r '.ebpf.packets_processed // 0'
}

# Function to get daemon statistics
get_daemon_stats() {
local stats=$(curl -s "$PEPCTL_STATS_URL" | jq -r '.daemon')
echo "$stats"
}

# Function to add a policy
add_policy() {
local policy_json="$1"
print_status "Adding policy: $(echo "$policy_json" | jq -r '.id')"

local response=$(curl -s -X POST \
-H "Content-Type: application/json" \
-d "$policy_json" \
"$PEPCTL_ADMIN_URL/policies")

if echo "$response" | jq -e '.success' > /dev/null 2>&1; then
print_status " Policy added successfully"
return 0
else
print_error " Failed to add policy: $response"
return 1
fi
}

# Function to remove a policy
remove_policy() {
local policy_id="$1"
print_status "Removing policy: $policy_id"

local response=$(curl -s -X DELETE "$PEPCTL_ADMIN_URL/policies/$policy_id")

if echo "$response" | jq -e '.success' > /dev/null 2>&1; then
print_status " Policy removed successfully"
return 0
else
print_error " Failed to remove policy: $response"
return 1
fi
}

# Function to list current policies
list_policies() {
print_status "Current policies:"
curl -s "$PEPCTL_ADMIN_URL/policies" | jq -r '.policies[] | " - \(.id): \(.action) \(.src.ip):\(.src.port) -> \(.dst.ip):\(.dst.port) (\(.src.protocol))"'
}

# Function to generate TCP traffic to specific port
generate_tcp_traffic() {
local target_ip="$1"
local target_port="$2"
local count="${3:-5}"

print_status " Generating TCP traffic to $target_ip:$target_port ($count attempts)"

for i in $(seq 1 $count); do
timeout 2 curl -s --connect-timeout 1 "http://$target_ip:$target_port" > /dev/null 2>&1 &
done
wait
}

# Function to generate UDP traffic to specific port
generate_udp_traffic() {
local target_ip="$1"
local target_port="$2"
local count="${3:-5}"

print_status " Generating UDP traffic to $target_ip:$target_port ($count packets)"

for i in $(seq 1 $count); do
echo "test packet $i" | timeout 1 nc -u -w1 "$target_ip" "$target_port" > /dev/null 2>&1 &
done
wait
}

# Function to generate ICMP traffic
generate_icmp_traffic() {
local target_ip="$1"
local count="${3:-5}"

print_status " Generating ICMP traffic to $target_ip ($count pings)"
ping -c $count -i 0.2 "$target_ip" > /dev/null 2>&1
}

# Function to test traffic before and after policy
test_traffic_with_policy() {
local policy_json="$1"
local test_function="$2"
local test_args="$3"

print_test "Testing traffic behavior with policy enforcement"

# Get baseline stats
local initial_packets=$(get_stats)
local initial_daemon=$(get_daemon_stats)

print_status " Initial stats: $initial_packets packets processed"

# Generate traffic WITHOUT policy
print_status " Phase 1: Traffic WITHOUT policy (should be allowed)"
eval "$test_function $test_args"
sleep 2

local after_no_policy=$(get_stats)
local packets_no_policy=$((after_no_policy - initial_packets))
print_status " Packets processed without policy: $packets_no_policy"

# Add the policy
add_policy "$policy_json"
sleep 1

# Generate traffic WITH policy
print_status " Phase 2: Traffic WITH policy (behavior depends on policy)"
local before_policy=$(get_stats)
eval "$test_function $test_args"
sleep 2

local after_policy=$(get_stats)
local packets_with_policy=$((after_policy - before_policy))
print_status " Packets processed with policy: $packets_with_policy"

# Get final daemon stats
local final_daemon=$(get_daemon_stats)
print_status " Final daemon stats:"
echo "$final_daemon" | jq -r '" Processed: \(.packets_processed), Allowed: \(.packets_allowed), Blocked: \(.packets_blocked)"'

# Remove the policy
local policy_id=$(echo "$policy_json" | jq -r '.id')
remove_policy "$policy_id"

# Compare results
print_status " Analysis:"
if [ "$packets_with_policy" -lt "$packets_no_policy" ]; then
print_status " Policy appears to be blocking traffic (fewer packets processed)"
elif [ "$packets_with_policy" -eq "$packets_no_policy" ]; then
print_status "️ Policy doesn't affect this traffic (same packet count)"
else
print_status "️ Unexpected result (more packets with policy)"
fi
}

# Test case 1: Block HTTP traffic to port 8080
test_block_http_8080() {
print_test "Test 1: Block HTTP traffic to port 8080"

local policy='{
"id": "block_http_8080",
"action": "BLOCK",
"src": {"ip": "0.0.0.0", "port": 0, "protocol": "TCP"},
"dst": {"ip": "127.0.0.1", "port": 8080, "protocol": "TCP"},
"description": "Block all HTTP traffic to port 8080"
}'

test_traffic_with_policy "$policy" "generate_tcp_traffic" "127.0.0.1 8080 10"
}

# Test case 2: Block UDP traffic to port 53 (DNS)
test_block_udp_dns() {
print_test "Test 2: Block UDP traffic to port 53 (DNS)"

local policy='{
"id": "block_udp_dns",
"action": "BLOCK", 
"src": {"ip": "0.0.0.0", "port": 0, "protocol": "UDP"},
"dst": {"ip": "127.0.0.1", "port": 53, "protocol": "UDP"},
"description": "Block UDP DNS queries"
}'

test_traffic_with_policy "$policy" "generate_udp_traffic" "127.0.0.1 53 10"
}

# Test case 3: Allow specific port while blocking others
test_selective_allow() {
print_test "Test 3: Allow port 9090 while blocking port 8080"

# First add a block policy for 8080
local block_policy='{
"id": "block_8080",
"action": "BLOCK",
"src": {"ip": "0.0.0.0", "port": 0, "protocol": "TCP"},
"dst": {"ip": "127.0.0.1", "port": 8080, "protocol": "TCP"},
"description": "Block port 8080"
}'

# Then add an allow policy for 9090 (higher priority)
local allow_policy='{
"id": "allow_9090",
"action": "ALLOW",
"src": {"ip": "0.0.0.0", "port": 0, "protocol": "TCP"},
"dst": {"ip": "127.0.0.1", "port": 9090, "protocol": "TCP"},
"description": "Allow port 9090"
}'

print_status "Adding both policies..."
add_policy "$block_policy"
add_policy "$allow_policy"

print_status "Testing traffic to blocked port 8080..."
local before_8080=$(get_stats)
generate_tcp_traffic "127.0.0.1" "8080" "5"
sleep 1
local after_8080=$(get_stats)

print_status "Testing traffic to allowed port 9090..."
local before_9090=$(get_stats)
generate_tcp_traffic "127.0.0.1" "9090" "5"
sleep 1
local after_9090=$(get_stats)

print_status "Results:"
print_status " Port 8080 (blocked): $((after_8080 - before_8080)) packets"
print_status " Port 9090 (allowed): $((after_9090 - before_9090)) packets"

# Cleanup
remove_policy "block_8080"
remove_policy "allow_9090"
}

# Test case 4: Rate limiting test
test_rate_limiting() {
print_test "Test 4: Rate limiting test"

local policy='{
"id": "rate_limit_test",
"action": "RATE_LIMIT",
"src": {"ip": "0.0.0.0", "port": 0, "protocol": "TCP"},
"dst": {"ip": "127.0.0.1", "port": 3000, "protocol": "TCP"},
"rateLimitBps": 1024,
"description": "Rate limit to 1KB/s"
}'

test_traffic_with_policy "$policy" "generate_tcp_traffic" "127.0.0.1 3000 20"
}

# Function to run comprehensive test suite
run_comprehensive_tests() {
print_status " Running comprehensive policy enforcement tests..."

# Check if PEPCTL is running
if ! curl -s "$PEPCTL_STATS_URL" > /dev/null; then
print_error "PEPCTL daemon is not running!"
exit 1
fi

print_status " Initial system state:"
list_policies
echo ""

# Run all test cases
test_block_http_8080
echo ""

test_block_udp_dns 
echo ""

test_selective_allow
echo ""

test_rate_limiting
echo ""

print_status " All policy enforcement tests completed!"
}

# Function to demonstrate live policy changes
demo_live_policy_changes() {
print_test "Live Policy Change Demonstration"

print_status " Starting live demonstration..."
print_status "This will show real-time policy enforcement changes"

# Start continuous traffic generation in background
print_status "Starting background traffic to port 8080..."
(
while true; do
curl -s --connect-timeout 1 "http://127.0.0.1:8080" > /dev/null 2>&1 || true
sleep 1
done
) &
local traffic_pid=$!

# Monitor for 10 seconds without policy
print_status " Monitoring traffic WITHOUT policy for 10 seconds..."
local start_packets=$(get_stats)
sleep 10
local no_policy_packets=$(get_stats)
local packets_no_policy=$((no_policy_packets - start_packets))

# Add blocking policy
local policy='{
"id": "demo_block",
"action": "BLOCK",
"src": {"ip": "0.0.0.0", "port": 0, "protocol": "TCP"},
"dst": {"ip": "127.0.0.1", "port": 8080, "protocol": "TCP"},
"description": "Demo blocking policy"
}'

print_status " Adding BLOCK policy..."
add_policy "$policy"

# Monitor for 10 seconds with policy
print_status " Monitoring traffic WITH blocking policy for 10 seconds..."
local policy_start=$(get_stats)
sleep 10
local with_policy_packets=$(get_stats)
local packets_with_policy=$((with_policy_packets - policy_start))

# Remove policy
print_status " Removing policy..."
remove_policy "demo_block"

# Monitor for 5 more seconds
print_status " Monitoring traffic AFTER policy removal for 5 seconds..."
local after_start=$(get_stats)
sleep 5
local after_packets=$(get_stats)
local packets_after=$((after_packets - after_start))

# Stop background traffic
kill $traffic_pid 2>/dev/null || true

# Show results
print_status " Live Demo Results:"
print_status " Before policy: $packets_no_policy packets in 10s"
print_status " With policy: $packets_with_policy packets in 10s"
print_status " After removal: $packets_after packets in 5s"

if [ "$packets_with_policy" -lt "$packets_no_policy" ]; then
print_status " Policy successfully blocked traffic!"
else
print_status "️ Policy may not have blocked traffic as expected"
fi
}

# Main execution
main() {
case "${1:-help}" in
"comprehensive")
run_comprehensive_tests
;;
"demo")
demo_live_policy_changes
;;
"block-http")
test_block_http_8080
;;
"block-udp")
test_block_udp_dns
;;
"selective")
test_selective_allow
;;
"rate-limit")
test_rate_limiting
;;
"policies")
list_policies
;;
"help")
echo "PEPCTL Policy Enforcement Test Suite"
echo ""
echo "Usage: $0 [command]"
echo ""
echo "Commands:"
echo " comprehensive - Run all policy enforcement tests"
echo " demo - Live policy change demonstration"
echo " block-http - Test HTTP blocking on port 8080"
echo " block-udp - Test UDP blocking on port 53"
echo " selective - Test selective allow/block"
echo " rate-limit - Test rate limiting"
echo " policies - List current policies"
echo " help - Show this help"
echo ""
echo "Examples:"
echo " $0 demo # Live demonstration"
echo " $0 comprehensive # Full test suite"
echo " $0 block-http # Test HTTP blocking"
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