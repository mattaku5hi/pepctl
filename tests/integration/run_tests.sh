#!/bin/bash

# PEPCTL Integration Test Suite
# Tests the complete functionality of pepctl daemon

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${PEPCTL_BUILD_DIR:-${SCRIPT_DIR}/../../build-ninja}"
PEPCTL_BIN="${BUILD_DIR}/src/pepctl"
TEST_CLIENT="${BUILD_DIR}/tests/integration/pepctl_test_client"
EBPF_OBJ="${BUILD_DIR}/ebpf/packet_filter.o"
TEST_CONFIG="/tmp/pepctl_test_config.json"
TEST_LOG="/tmp/pepctl_test.log"
ADMIN_PORT=18080
METRICS_PORT=19090

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
echo -e "${RED}[ERROR]${NC} $1"
}

# Cleanup function
cleanup() {
log_info "Cleaning up test environment..."

# Kill pepctl if running
if [ -n "$PEPCTL_PID" ] && kill -0 "$PEPCTL_PID" 2>/dev/null; then
log_info "Stopping pepctl daemon (PID: $PEPCTL_PID)"
kill "$PEPCTL_PID"
wait "$PEPCTL_PID" 2>/dev/null || true
fi

# Clean up test files
rm -f "$TEST_CONFIG" "$TEST_LOG"

log_info "Cleanup complete"
}

# Set up signal handling
trap cleanup EXIT INT TERM

# Check if running as root
check_root() {
if [ "$EUID" -ne 0 ]; then
log_error "Integration tests must be run as root for eBPF operations"
log_info "Please run: sudo $0"
exit 1
fi
}

# Create test configuration
create_test_config() {
log_info "Creating test configuration..."

cat > "$TEST_CONFIG" << EOF
{
"log_level": "debug",
"log_file": "$TEST_LOG",
"admin_port": $ADMIN_PORT,
"metrics_port": $METRICS_PORT,
"interface": "lo",
"daemon_mode": false,
"enable_metrics": true,
"policy_capacity": 1000,
"ebpf_program_path": "$EBPF_OBJ",
"policy_cleanup_interval": 60
}
EOF

log_info "Test configuration created at $TEST_CONFIG"
}

# Start pepctl daemon
start_pepctl() {
log_info "Starting pepctl daemon..."

if [ ! -f "$PEPCTL_BIN" ]; then
log_error "pepctl binary not found at $PEPCTL_BIN"
log_info "Please build the project first: cmake --preset clang-ninja-debug && cmake --build --preset build-debug"
exit 1
fi

# Start pepctl in background
"$PEPCTL_BIN" --config "$TEST_CONFIG" --foreground &
PEPCTL_PID=$!

log_info "Started pepctl daemon (PID: $PEPCTL_PID)"

# Wait for daemon to start
sleep 3

# Check if daemon is still running
if ! kill -0 "$PEPCTL_PID" 2>/dev/null; then
log_error "pepctl daemon failed to start"
if [ -f "$TEST_LOG" ]; then
log_error "Log output:"
tail -20 "$TEST_LOG"
fi
exit 1
fi

log_info "pepctl daemon started successfully"
}

# Test health endpoint
test_health() {
log_info "Testing health endpoint..."

local response=$(curl -s -w "%{http_code}" "http://localhost:$ADMIN_PORT/health" -o /dev/null)

if [ "$response" == "200" ]; then
log_info " Health endpoint test passed"
return 0
else
log_error " Health endpoint test failed (HTTP $response)"
return 1
fi
}

# Test metrics endpoint
test_metrics() {
log_info "Testing metrics endpoint..."

local response=$(curl -s "http://localhost:$METRICS_PORT/metrics")

if echo "$response" | grep -q "pepctl_"; then
log_info " Metrics endpoint test passed"
return 0
else
log_error " Metrics endpoint test failed"
log_error "Response: $response"
return 1
fi
}

# Test policy management
test_policy_management() {
log_info "Testing policy management..."

# Add a test policy
local policy_json='{
"id": "test_block_policy",
"action": "BLOCK",
"src_ip": "192.168.1.100",
"dst_ip": "0.0.0.0",
"src_port": 0,
"dst_port": 80,
"protocol": "TCP"
}'

local response=$(curl -s -w "%{http_code}" \
-X POST \
-H "Content-Type: application/json" \
-d "$policy_json" \
"http://localhost:$ADMIN_PORT/api/v1/policies" \
-o /dev/null)

if [ "$response" == "200" ] || [ "$response" == "201" ]; then
log_info " Policy creation test passed"
else
log_error " Policy creation test failed (HTTP $response)"
return 1
fi

# Get all policies
local policies=$(curl -s "http://localhost:$ADMIN_PORT/api/v1/policies")

if echo "$policies" | grep -q "test_block_policy"; then
log_info " Policy retrieval test passed"
else
log_error " Policy retrieval test failed"
log_error "Response: $policies"
return 1
fi

# Delete the test policy
response=$(curl -s -w "%{http_code}" \
-X DELETE \
"http://localhost:$ADMIN_PORT/api/v1/policies/test_block_policy" \
-o /dev/null)

if [ "$response" == "200" ] || [ "$response" == "204" ]; then
log_info " Policy deletion test passed"
return 0
else
log_error " Policy deletion test failed (HTTP $response)"
return 1
fi
}

# Test system info endpoint
test_system_info() {
log_info "Testing system info endpoint..."

local response=$(curl -s "http://localhost:$ADMIN_PORT/api/v1/info")

if echo "$response" | grep -q "pepctl"; then
log_info " System info test passed"
return 0
else
log_error " System info test failed"
log_error "Response: $response"
return 1
fi
}

# Run performance test
test_performance() {
log_info "Running performance test..."

# This is a basic performance test - in a real scenario,
# we would generate actual network traffic
local start_time=$(date +%s)

# Add multiple policies quickly
for i in {1..100}; do
local policy_json="{
\"id\": \"perf_test_$i\",
\"action\": \"ALLOW\",
\"src_ip\": \"192.168.1.$((i % 255))\",
\"dst_ip\": \"0.0.0.0\",
\"src_port\": 0,
\"dst_port\": $((8000 + i)),
\"protocol\": \"TCP\"
}"

curl -s -X POST \
-H "Content-Type: application/json" \
-d "$policy_json" \
"http://localhost:$ADMIN_PORT/api/v1/policies" > /dev/null
done

local end_time=$(date +%s)
local duration=$((end_time - start_time))

log_info " Performance test completed: 100 policies in ${duration}s"

# Cleanup performance test policies
for i in {1..100}; do
curl -s -X DELETE "http://localhost:$ADMIN_PORT/api/v1/policies/perf_test_$i" > /dev/null
done

return 0
}

# Main test runner
run_tests() {
log_info "Starting pepctl integration test suite..."

local tests_passed=0
local tests_total=0

# Array of test functions
local tests=(
"test_health"
"test_metrics"
"test_system_info"
"test_policy_management"
"test_performance"
)

for test in "${tests[@]}"; do
tests_total=$((tests_total + 1))
log_info "Running $test..."

if $test; then
tests_passed=$((tests_passed + 1))
else
log_error "Test $test failed"
fi

echo # Empty line for readability
done

# Print summary
log_info "Test Results:"
log_info " Passed: $tests_passed/$tests_total"

if [ "$tests_passed" -eq "$tests_total" ]; then
log_info " All tests passed!"
return 0
else
log_error " Some tests failed"
return 1
fi
}

# Main execution
main() {
log_info "PEPCTL Integration Test Suite"
log_info "============================="

check_root
create_test_config
start_pepctl

# Give daemon time to initialize
sleep 2

run_tests
local result=$?

return $result
}

# Run main function
main "$@" 