#!/bin/bash

# PEPCTL Member Variable CamelCase Converter
# This script converts m_ prefixed snake_case variables to camelCase

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_info() {
echo -e "${GREEN}[CAMEL-CASE]${NC} $1"
}

print_warning() {
echo -e "${YELLOW}[CAMEL-CASE]${NC} $1"
}

print_error() {
echo -e "${RED}[CAMEL-CASE]${NC} $1"
}

# Get script directory and project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

print_info "Converting member variables to camelCase in: $PROJECT_ROOT"

# Function to convert snake_case to camelCase
snake_to_camel() {
echo "$1" | sed -E 's/_([a-z])/\U\1/g'
}

# Extensions to process
EXTENSIONS=("*.cpp" "*.hpp" "*.h")

FILES_MODIFIED=0
TOTAL_CHANGES=0

# Define the conversions
declare -A CONVERSIONS=(
["m_current_level"]="m_currentLevel"
["m_main_logger"]="m_mainLogger"
["m_structured_logger"]="m_structuredLogger"
["m_stats_mutex"]="m_statsMutex"
["m_interface_name"]="m_interfaceName"
["m_program_type"]="m_programType"
["m_bpf_obj"]="m_bpfObj"
["m_policies_mutex"]="m_policiesMutex"
["m_rate_limiter"]="m_rateLimiter"
["m_running"]="m_running"
["m_worker_thread"]="m_workerThread"
["m_admin_port"]="m_adminPort"
["m_metrics_port"]="m_metricsPort"
["m_log_level"]="m_logLevel"
["m_log_file"]="m_logFile"
["m_daemon_mode"]="m_daemonMode"
["m_enable_metrics"]="m_enableMetrics"
["m_policy_capacity"]="m_policyCapacity"
["m_ebpf_program_path"]="m_ebpfProgramPath"
["m_config_file_path"]="m_configFilePath"
)

for ext in "${EXTENSIONS[@]}"; do
while IFS= read -r -d '' file; do
# Skip files in build directory
if [[ "$file" == *"/build/"* ]]; then
continue
fi

print_info "Processing: $(basename "$file")"

# Create backup
cp "$file" "$file.backup"

CHANGES_IN_FILE=0

# Apply each conversion
for old_name in "${!CONVERSIONS[@]}"; do
new_name="${CONVERSIONS[$old_name]}"

# Count occurrences before replacement
count=$(grep -c "$old_name" "$file" || true)

if [[ $count -gt 0 ]]; then
# Replace all occurrences
sed -i "s/${old_name}/${new_name}/g" "$file"
print_info " Converted: $old_name $new_name ($count occurrences)"
CHANGES_IN_FILE=$((CHANGES_IN_FILE + count))
fi
done

# Check if file was actually modified
if ! diff -q "$file" "$file.backup" >/dev/null 2>&1; then
FILES_MODIFIED=$((FILES_MODIFIED + 1))
print_info " Modified: $(basename "$file") ($CHANGES_IN_FILE changes)"
TOTAL_CHANGES=$((TOTAL_CHANGES + CHANGES_IN_FILE))
else
# No changes, restore backup
mv "$file.backup" "$file"
fi

# Remove backup if it exists
[[ -f "$file.backup" ]] && rm "$file.backup"

done < <(find "$PROJECT_ROOT" -name "$ext" -type f -print0)
done

# Summary
echo ""
print_info "CamelCase conversion complete!"
echo " Files modified: $FILES_MODIFIED" 
echo " Total variable renames: $TOTAL_CHANGES"

if [[ $FILES_MODIFIED -gt 0 ]]; then
print_warning "Files have been modified. Please review changes before committing."
print_info "To see changes: git diff"
print_info "To revert: git checkout -- ."
print_info "Next step: Update header files with new variable declarations"
else
print_info "No snake_case member variables found or all were already camelCase."
fi 