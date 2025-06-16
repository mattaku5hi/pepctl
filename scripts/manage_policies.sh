#!/bin/bash

# PEPCTL Policy Management Script
# Unified script to add policies from JSON file or remove all policies

set -euo pipefail

# Default values
ADMIN_URL="http://192.168.3.66:9090"
ACTION=""
POLICIES_FILE=""
POLICY_ID=""
BACKUP_FILE=""
VERBOSE=false

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Print usage
usage() {
cat << EOF
PEPCTL Policy Management Script

Usage: $0 [OPTIONS] ACTION

ACTIONS:
add <policies.json> Add policies from JSON file
remove <policy_id> Remove specific policy by ID
remove-all Remove all policies
list List current policies
stats Show current statistics
backup <file> Backup current policies to file
restore <file> Restore policies from backup file

OPTIONS:
-u, --url URL Admin URL (default: $ADMIN_URL)
-v, --verbose Verbose output
-h, --help Show this help

NETWORK INTERFACE:
Current interface: enx00e099002775 (192.168.3.66)
Previous interface: lo (127.0.0.1) - for comparison

EXAMPLES:
# Add policies from file
$0 add policies/test_comprehensive_policies.json

# Remove specific policy
$0 remove rate_limit_icmp_strict

# Remove all policies
$0 remove-all

# Backup current policies
$0 backup my_policies_backup.json

# Restore policies from backup
$0 restore my_policies_backup.json

# List current policies
$0 list

# Show statistics
$0 stats

EOF
}

# Logging functions
log_info() {
echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
echo -e "${RED}[ERROR]${NC} $1"
}

log_verbose() {
if [[ "$VERBOSE" == "true" ]]; then
echo -e "${BLUE}[VERBOSE]${NC} $1"
fi
}

# Check if PEPCTL daemon is running
check_daemon() {
log_verbose "Checking if PEPCTL daemon is running..."

if ! curl -s --connect-timeout 5 "$ADMIN_URL/stats" > /dev/null 2>&1; then
log_error "PEPCTL daemon is not running or not accessible at $ADMIN_URL"
log_info "Please start the daemon first: sudo ./build/src/pepctl --config tests/test_config.json --daemon"
exit 1
fi

log_verbose "PEPCTL daemon is running"
}

# Verify if a policy exists
verify_policy_exists() {
local policy_id="$1"
local policies
policies=$(curl -s "$ADMIN_URL/policies" 2>/dev/null)

if echo "$policies" | jq empty 2>/dev/null; then
echo "$policies" | jq -e --arg id "$policy_id" '.[] | select(.id == $id)' >/dev/null 2>&1
else
return 1
fi
}

# Add policies from JSON file with enhanced validation
add_policies() {
local policies_file="$1"

if [[ ! -f "$policies_file" ]]; then
log_error "Policies file not found: $policies_file"
exit 1
fi

log_info "Adding policies from: $policies_file"
log_verbose "Admin URL: $ADMIN_URL"

# Validate JSON structure
if ! jq empty "$policies_file" 2>/dev/null; then
log_error "Invalid JSON in policies file: $policies_file"
exit 1
fi

# Validate it's an array
if ! jq -e 'type == "array"' "$policies_file" >/dev/null 2>&1; then
log_error "Policies file must contain a JSON array"
exit 1
fi

# Check for required fields in each policy
local validation_errors=0
while IFS= read -r policy_index; do
local policy_id=$(jq -r ".[$policy_index].id // empty" "$policies_file")
local policy_action=$(jq -r ".[$policy_index].action // empty" "$policies_file")

if [[ -z "$policy_id" ]]; then
log_error "Policy at index $policy_index missing required 'id' field"
((validation_errors++))
fi

if [[ -z "$policy_action" ]]; then
log_error "Policy at index $policy_index missing required 'action' field"
((validation_errors++))
elif [[ ! "$policy_action" =~ ^(ALLOW|BLOCK|LOG_ONLY|RATE_LIMIT)$ ]]; then
log_error "Policy '$policy_id' has invalid action: $policy_action"
((validation_errors++))
fi
done < <(jq -r 'keys[]' "$policies_file")

if [[ $validation_errors -gt 0 ]]; then
log_error "Found $validation_errors validation errors. Aborting."
exit 1
fi

# Check for duplicate policy IDs in file
local duplicate_ids
duplicate_ids=$(jq -r '[.[].id] | group_by(.) | map(select(length > 1)) | flatten | unique | .[]' "$policies_file" 2>/dev/null)
if [[ -n "$duplicate_ids" ]]; then
log_error "Duplicate policy IDs found in file: $duplicate_ids"
exit 1
fi

# Check for conflicts with existing policies
local existing_policies
existing_policies=$(curl -s "$ADMIN_URL/policies" 2>/dev/null)
if echo "$existing_policies" | jq empty 2>/dev/null; then
local conflicts=()
while IFS= read -r new_id; do
if echo "$existing_policies" | jq -e --arg id "$new_id" '.[] | select(.id == $id)' >/dev/null 2>&1; then
conflicts+=("$new_id")
fi
done < <(jq -r '.[].id' "$policies_file")

if [[ ${#conflicts[@]} -gt 0 ]]; then
log_warning "The following policy IDs already exist and will be updated:"
printf ' - %s\n' "${conflicts[@]}"
echo
fi
fi

# Show policies being added if verbose
if [[ "$VERBOSE" == "true" ]]; then
log_verbose "Policies to be added:"
jq -r '.[] | " - ID: \(.id), Action: \(.action), Src: \(.src.ip // "any"):\(.src.port // 0), Dst: \(.dst.ip // "any"):\(.dst.port // 0)"' "$policies_file"
echo
fi

# Add policies with retry logic
local response
local retry_count=0
local max_retries=3

while [[ $retry_count -lt $max_retries ]]; do
response=$(curl -s --max-time 30 -X POST \
-H "Content-Type: application/json" \
-d @"$policies_file" \
"$ADMIN_URL/policies" 2>/dev/null)

if echo "$response" | jq -e '.status == "success"' > /dev/null 2>&1; then
local count
count=$(jq length "$policies_file")
log_success "Successfully added $count policies"

if [[ "$VERBOSE" == "true" ]]; then
echo "$response" | jq -r '.message // "Policies added successfully"'
fi

# Verify policies were actually added
sleep 1
local verification_failed=0
while IFS= read -r policy_id; do
if ! verify_policy_exists "$policy_id"; then
log_warning "Policy '$policy_id' was not found after adding"
((verification_failed++))
fi
done < <(jq -r '.[].id' "$policies_file")

if [[ $verification_failed -gt 0 ]]; then
log_warning "$verification_failed policies may not have been added correctly"
fi

return 0
else
((retry_count++))
if [[ $retry_count -lt $max_retries ]]; then
log_warning "Failed to add policies (attempt $retry_count/$max_retries), retrying..."
sleep 2
fi
fi
done

log_error "Failed to add policies after $max_retries attempts"
if [[ "$VERBOSE" == "true" ]]; then
echo "Last response: $response"
fi
exit 1
}

# Remove specific policy by ID
remove_policy() {
local policy_id="$1"

if [[ -z "$policy_id" ]]; then
log_error "Policy ID is required"
exit 1
fi

log_info "Removing policy: $policy_id"
log_verbose "Admin URL: $ADMIN_URL"

# Check if policy exists first
if ! verify_policy_exists "$policy_id"; then
log_error "Policy '$policy_id' not found"
exit 1
fi

# Remove the policy with retry logic
local response
local retry_count=0
local max_retries=3

while [[ $retry_count -lt $max_retries ]]; do
response=$(curl -s --max-time 10 -X DELETE "$ADMIN_URL/policies?id=$policy_id" 2>/dev/null)

if echo "$response" | jq -e '.status == "success"' > /dev/null 2>&1; then
log_success "Successfully removed policy: $policy_id"

# Verify policy was actually removed
sleep 1
if verify_policy_exists "$policy_id"; then
log_warning "Policy '$policy_id' still exists after removal"
fi

return 0
else
((retry_count++))
if [[ $retry_count -lt $max_retries ]]; then
log_warning "Failed to remove policy (attempt $retry_count/$max_retries), retrying..."
sleep 2
fi
fi
done

log_error "Failed to remove policy '$policy_id' after $max_retries attempts"
if [[ "$VERBOSE" == "true" ]]; then
echo "Last response: $response"
fi
exit 1
}

# Remove all policies using external command approach
remove_all_policies() {
log_info "Removing all policies..."
log_verbose "Admin URL: $ADMIN_URL"

# Create a temporary script to avoid shell issues
local temp_script="/tmp/pepctl_remove_all_$$"
cat > "$temp_script" << 'EOF'
#!/bin/bash
ADMIN_URL="$1"
VERBOSE="$2"

removed_count=0
max_iterations=50

for ((i=1; i<=max_iterations; i++)); do
if [[ "$VERBOSE" == "true" ]]; then
echo "[VERBOSE] Checking for policies (iteration $i)..."
fi

# Get first policy ID
policy_id=$(curl -s --connect-timeout 5 --max-time 10 "$ADMIN_URL/policies" | jq -r '.[0].id // empty' 2>/dev/null)

if [[ -z "$policy_id" || "$policy_id" == "null" ]]; then
if [[ "$VERBOSE" == "true" ]]; then
echo "[VERBOSE] No more policies to remove"
fi
break
fi

if [[ "$VERBOSE" == "true" ]]; then
echo "[VERBOSE] Removing policy: $policy_id"
fi

# Remove the policy
response=$(curl -s --connect-timeout 5 --max-time 10 -X DELETE "$ADMIN_URL/policies?id=$policy_id" 2>/dev/null)

if echo "$response" | grep -q '"status":"success"'; then
((removed_count++))
if [[ "$VERBOSE" == "true" ]]; then
echo "[VERBOSE] Removed policy: $policy_id"
fi
else
echo "[WARNING] Failed to remove policy: $policy_id"
if [[ "$VERBOSE" == "true" ]]; then
echo "Response: $response"
fi
break
fi

sleep 0.1
done

echo "Removed $removed_count policies"
exit 0
EOF

chmod +x "$temp_script"

# Execute the temporary script
if "$temp_script" "$ADMIN_URL" "$VERBOSE"; then
log_success "Successfully completed policy removal"
else
log_error "Policy removal script failed"
rm -f "$temp_script"
exit 1
fi

# Clean up
rm -f "$temp_script"
}

# Backup current policies to file
backup_policies() {
local backup_file="$1"

if [[ -z "$backup_file" ]]; then
log_error "Backup filename is required"
exit 1
fi

log_info "Backing up policies to: $backup_file"
log_verbose "Admin URL: $ADMIN_URL"

# Get current policies
local policies
policies=$(curl -s --max-time 10 "$ADMIN_URL/policies" 2>/dev/null)

if ! echo "$policies" | jq empty 2>/dev/null; then
log_error "Failed to get current policies"
exit 1
fi

local policy_count
policy_count=$(echo "$policies" | jq length)

if [[ "$policy_count" -eq 0 ]]; then
log_warning "No policies to backup"
echo "[]" > "$backup_file"
else
# Pretty print the JSON and save to file
echo "$policies" | jq '.' > "$backup_file"

if [[ $? -eq 0 ]]; then
log_success "Successfully backed up $policy_count policies to $backup_file"
else
log_error "Failed to write backup file: $backup_file"
exit 1
fi
fi
}

# Restore policies from backup file
restore_policies() {
local backup_file="$1"

if [[ -z "$backup_file" ]]; then
log_error "Backup filename is required"
exit 1
fi

if [[ ! -f "$backup_file" ]]; then
log_error "Backup file not found: $backup_file"
exit 1
fi

log_info "Restoring policies from: $backup_file"

# Use the enhanced add_policies function
add_policies "$backup_file"
}

# List current policies
list_policies() {
log_info "Current policies:"
log_verbose "Admin URL: $ADMIN_URL"

local policies
policies=$(curl -s "$ADMIN_URL/policies" 2>/dev/null)

if ! echo "$policies" | jq empty 2>/dev/null; then
log_error "Failed to get policies"
exit 1
fi

local count
count=$(echo "$policies" | jq length)

if [[ "$count" -eq 0 ]]; then
log_warning "No policies loaded"
return
fi

echo "$policies" | jq -r '.[] | " ID: \(.id)\n Action: \(.action)\n Src: \(.src.ip):\(.src.port) (\(.src.protocol))\n Dst: \(.dst.ip):\(.dst.port) (\(.dst.protocol))\n Hits: \(.hit_count)\n"'

log_info "Total policies: $count"
}

# Show statistics
show_stats() {
log_info "Current statistics:"
log_verbose "Admin URL: $ADMIN_URL"

local stats
stats=$(curl -s "$ADMIN_URL/stats" 2>/dev/null)

if ! echo "$stats" | jq empty 2>/dev/null; then
log_error "Failed to get statistics"
exit 1
fi

echo
echo " PEPCTL Statistics:"
echo " Service: $(echo "$stats" | jq -r '.service')"
echo " Version: $(echo "$stats" | jq -r '.version')"
echo " Uptime: $(echo "$stats" | jq -r '.uptime_seconds') seconds"
echo
echo " Policies:"
echo " Total: $(echo "$stats" | jq -r '.policies.total_count')"
echo
echo " eBPF:"
echo " Packets processed: $(echo "$stats" | jq -r '.ebpf.packets_processed')"
echo
echo " Daemon:"
echo " Packets processed: $(echo "$stats" | jq -r '.daemon.packets_processed')"
echo " Packets allowed: $(echo "$stats" | jq -r '.daemon.packets_allowed')"
echo " Packets blocked: $(echo "$stats" | jq -r '.daemon.packets_blocked')"
echo " Packets logged: $(echo "$stats" | jq -r '.daemon.packets_logged')"
echo " Packets rate-limited: $(echo "$stats" | jq -r '.daemon.packets_rate_limited')"
echo " Bytes processed: $(echo "$stats" | jq -r '.daemon.bytes_processed')"
echo
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
case $1 in
-u|--url)
ADMIN_URL="$2"
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
add)
ACTION="add"
if [[ $# -lt 2 ]]; then
log_error "Missing policies file for 'add' action"
usage
exit 1
fi
POLICIES_FILE="$2"
shift 2
;;
remove)
if [[ "$2" == "all" ]] || [[ "$2" == "-all" ]]; then
ACTION="remove-all"
shift 2
else
ACTION="remove"
if [[ $# -lt 2 ]]; then
log_error "Missing policy ID for 'remove' action"
usage
exit 1
fi
POLICY_ID="$2"
shift 2
fi
;;
remove-all)
ACTION="remove-all"
shift
;;
backup)
ACTION="backup"
if [[ $# -lt 2 ]]; then
log_error "Missing backup filename for 'backup' action"
usage
exit 1
fi
BACKUP_FILE="$2"
shift 2
;;
restore)
ACTION="restore"
if [[ $# -lt 2 ]]; then
log_error "Missing backup filename for 'restore' action"
usage
exit 1
fi
BACKUP_FILE="$2"
shift 2
;;
list)
ACTION="list"
shift
;;
stats)
ACTION="stats"
shift
;;
*)
log_error "Unknown option: $1"
usage
exit 1
;;
esac
done

# Validate action
if [[ -z "$ACTION" ]]; then
log_error "No action specified"
usage
exit 1
fi

# Check dependencies
if ! command -v curl &> /dev/null; then
log_error "curl is required but not installed"
exit 1
fi

if ! command -v jq &> /dev/null; then
log_error "jq is required but not installed"
exit 1
fi

# Main execution
log_info " PEPCTL Policy Management"
log_verbose "Action: $ACTION"

# Check daemon for all actions
check_daemon

# Execute action
case "$ACTION" in
add)
add_policies "$POLICIES_FILE"
;;
remove)
remove_policy "$POLICY_ID"
;;
remove-all)
remove_all_policies
;;
backup)
backup_policies "$BACKUP_FILE"
;;
restore)
restore_policies "$BACKUP_FILE"
;;
list)
list_policies
;;
stats)
show_stats
;;
esac

log_success "Operation completed successfully!" 