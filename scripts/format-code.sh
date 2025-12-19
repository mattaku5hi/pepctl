#!/bin/bash

# PEPCTL Code Formatting and Analysis Script
# This script formats all C++ source files using clang-format and runs clang-tidy checks

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Options
FORMAT_ONLY=false
TIDY_ONLY=false
FIX_TIDY=false
FIX_BOOL=false
CAMEL_CASE=false

# Parallel processing options
PARALLEL=true # Default to parallel execution
SEQUENTIAL=false
JOBS="" # Auto-detect by default

# Auto-detect number of CPU cores
detect_cpu_cores() {
if command -v nproc >/dev/null 2>&1; then
nproc
elif [[ -f /proc/cpuinfo ]]; then
grep -c '^processor' /proc/cpuinfo
else
echo "4" # Fallback
fi
}

# Set default number of jobs if not specified
if [[ -z "$JOBS" ]]; then
DETECTED_CORES=$(detect_cpu_cores)
# Use 75% of cores to leave some for system
JOBS=$(( DETECTED_CORES * 3 / 4 ))
[[ $JOBS -lt 1 ]] && JOBS=1
fi

# Function to print colored output
print_info() {
echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
echo -e "${RED}[ERROR]${NC} $1"
}

print_tidy() {
echo -e "${BLUE}[TIDY]${NC} $1"
}

# Function to show usage
show_usage() {
echo "Usage: $0 [OPTIONS]"
echo ""
echo "Options:"
echo " --format-only Run only clang-format (no clang-tidy)"
echo " --tidy-only Run only clang-tidy (no clang-format)"
echo " --fix-tidy Auto-fix clang-tidy issues where possible"
echo " --fix-bool Fix implicit bool conversions explicitly"
echo " --camel-case Convert member variables to camelCase"
echo " --parallel Use parallel clang-tidy (faster, default)"
echo " --sequential Use sequential clang-tidy (slower, more detailed)"
echo " -j, --jobs N Number of parallel jobs (default: auto-detect)"
echo " -h, --help Show this help message"
echo ""
echo "Default: Run both clang-format and clang-tidy in parallel"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
case $1 in
--format-only)
FORMAT_ONLY=true
shift
;;
--tidy-only)
TIDY_ONLY=true
shift
;;
--fix-tidy)
FIX_TIDY=true
shift
;;
--fix-bool)
FIX_BOOL=true
shift
;;
--camel-case)
CAMEL_CASE=true
shift
;;
--parallel)
PARALLEL=true
shift
;;
--sequential)
SEQUENTIAL=true
shift
;;
-j|--jobs)
JOBS=$2
shift
shift
;;
-h|--help)
show_usage
exit 0
;;
*)
print_error "Unknown option: $1"
show_usage
exit 1
;;
esac
done

# Check if tools are available
if [[ "$FORMAT_ONLY" != "true" && "$TIDY_ONLY" == "true" ]]; then
# Only need clang-tidy
if ! command -v clang-tidy &> /dev/null; then
print_error "clang-tidy is not installed. Please install it with:"
echo " sudo apt install clang-tidy"
exit 1
fi
elif [[ "$TIDY_ONLY" != "true" ]]; then
# Need clang-format
if ! command -v clang-format &> /dev/null; then
print_error "clang-format is not installed. Please install it with:"
echo " sudo apt install clang-format"
exit 1
fi

# Also need clang-tidy if not format-only
if [[ "$FORMAT_ONLY" != "true" ]] && ! command -v clang-tidy &> /dev/null; then
print_error "clang-tidy is not installed. Please install it with:"
echo " sudo apt install clang-tidy"
exit 1
fi
fi

# Get script directory and project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Check if configuration files exist
if [[ "$TIDY_ONLY" != "true" && ! -f "$PROJECT_ROOT/.clang-format" ]]; then
print_error ".clang-format file not found in project root"
exit 1
fi

if [[ "$FORMAT_ONLY" != "true" && ! -f "$PROJECT_ROOT/.clang-tidy" ]]; then
print_error ".clang-tidy file not found in project root"
exit 1
fi

print_info "Code analysis and formatting in: $PROJECT_ROOT"
if [[ "$TIDY_ONLY" != "true" ]]; then
print_info "Using clang-format version: $(clang-format --version)"
fi
if [[ "$FORMAT_ONLY" != "true" ]]; then
print_info "Using clang-tidy version: $(clang-tidy --version)"
fi

# Statistics
FILES_FORMATTED=0
FILES_TIDY_CHECKED=0
FILES_WITH_TIDY_ISSUES=0
TOTAL_FILES=0

# Extensions to process
EXTENSIONS=("*.cpp" "*.hpp" "*.c" "*.h" "*.cc" "*.cxx")

# Function to generate compilation database
generate_compile_db() {
local BUILD_DIR="$PROJECT_ROOT/build-ninja"

if [[ ! -d "$BUILD_DIR" ]]; then
print_warning "Build directory not found. Creating one..."
mkdir -p "$BUILD_DIR"
fi

print_info "Generating compile_commands.json for clang-tidy..."
(cd "$PROJECT_ROOT" && cmake --preset clang-ninja-debug >/dev/null)

# Copy to project root for run-clang-tidy
if [[ -f "$BUILD_DIR/compile_commands.json" ]]; then
cp "$BUILD_DIR/compile_commands.json" "$PROJECT_ROOT/"
fi
cd "$PROJECT_ROOT"
}

# Build compile_commands.json for clang-tidy if it doesn't exist
if [[ "$FORMAT_ONLY" != "true" && ! -f "$PROJECT_ROOT/build-ninja/compile_commands.json" ]]; then
generate_compile_db
fi

# Collect source files
SOURCE_FILES=()
for ext in "${EXTENSIONS[@]}"; do
while IFS= read -r -d '' file; do
TOTAL_FILES=$((TOTAL_FILES + 1))

# Skip files in build directory
if [[ "$file" == *"/build/"* || "$file" == *"/build-ninja/"* || "$file" == *"/build-ninja-release/"* ]]; then
continue
fi

SOURCE_FILES+=("$file")
done < <(find "$PROJECT_ROOT" -name "$ext" -type f -print0)
done

# Sequential clang-tidy (original method)
run_tidy_sequential() {
local FILES_WITH_TIDY_ISSUES=0
local FILES_TIDY_CHECKED=0

for file in "${SOURCE_FILES[@]}"; do
# Skip header files for clang-tidy (they need to be included in .cpp files)
if [[ "$file" == *.h || "$file" == *.hpp ]]; then
continue
fi

FILES_TIDY_CHECKED=$((FILES_TIDY_CHECKED + 1))

# Prepare clang-tidy command 
TIDY_CMD="clang-tidy"
if [[ "$FIX_TIDY" == "true" ]]; then
TIDY_CMD="$TIDY_CMD --fix"
fi

# Run clang-tidy and capture output
TIDY_OUTPUT=$(cd "$PROJECT_ROOT" && $TIDY_CMD "$file" -p build-ninja 2>&1 || true)

# Check if there are issues
if echo "$TIDY_OUTPUT" | grep -q "warning:\|error:"; then
print_tidy "Issues found in $(basename "$file"):"
echo "$TIDY_OUTPUT" | grep -E "(warning:|error:)" | head -3
FILES_WITH_TIDY_ISSUES=$((FILES_WITH_TIDY_ISSUES + 1))

if [[ "$FIX_TIDY" != "true" ]]; then
print_tidy " Run with --fix-tidy to auto-fix where possible"
fi
fi
done

echo " Files analyzed with clang-tidy: $FILES_TIDY_CHECKED"
echo " Files with tidy issues: $FILES_WITH_TIDY_ISSUES"

if [[ $FILES_WITH_TIDY_ISSUES -gt 0 ]]; then
FILES_WITH_TIDY_ISSUES_GLOBAL=$FILES_WITH_TIDY_ISSUES
fi
}

# Parallel clang-tidy using run-clang-tidy
run_tidy_parallel() {
# Ensure we have a compilation database
if [[ ! -f "$PROJECT_ROOT/compile_commands.json" ]]; then
generate_compile_db
fi

# Prepare run-clang-tidy command
PARALLEL_CMD="run-clang-tidy -j $JOBS"
if [[ "$FIX_TIDY" == "true" ]]; then
PARALLEL_CMD="$PARALLEL_CMD -fix"
fi

# Add source file filter (only our source files, exclude headers)
PARALLEL_CMD="$PARALLEL_CMD -header-filter='.*/(src|include)/.*' '.*\.cpp$|.*\.cc$|.*\.cxx$'"

# Count CPP files for reporting
CPP_FILE_COUNT=0
for file in "${SOURCE_FILES[@]}"; do
if [[ "$file" == *.cpp || "$file" == *.cc || "$file" == *.cxx ]]; then
CPP_FILE_COUNT=$((CPP_FILE_COUNT + 1))
fi
done

print_info "Running clang-tidy on $CPP_FILE_COUNT source files with $JOBS parallel jobs..."

# Run in project root where compile_commands.json is located
cd "$PROJECT_ROOT"

TIDY_OUTPUT=$(eval $PARALLEL_CMD 2>&1 || true)

echo " Files analyzed with clang-tidy: $CPP_FILE_COUNT (parallel)"

# Check if there are issues in the output
if echo "$TIDY_OUTPUT" | grep -q "warning:\|error:"; then
local issue_count=$(echo "$TIDY_OUTPUT" | grep -c "warning:\|error:" || echo "0")
echo " Clang-tidy issues found: $issue_count"

if [[ "$FIX_TIDY" != "true" ]]; then
print_tidy "Sample issues:"
echo "$TIDY_OUTPUT" | grep -E "(warning:|error:)" | head -5
print_tidy " Run with --fix-tidy to auto-fix where possible"
fi
FILES_WITH_TIDY_ISSUES_GLOBAL=1
else
echo " Files with tidy issues: 0"
print_success " All files pass clang-tidy checks (parallel)"
fi
}

# Run formatting
for file in "${SOURCE_FILES[@]}"; do
# Run clang-format
if [[ "$TIDY_ONLY" != "true" ]]; then
if ! clang-format --dry-run --Werror "$file" >/dev/null 2>&1; then
print_info "Formatting: $(basename "$file")"
clang-format -i "$file"
FILES_FORMATTED=$((FILES_FORMATTED + 1))
fi
fi
done

# Run clang-tidy analysis
FILES_WITH_TIDY_ISSUES_GLOBAL=0
if [[ "$FORMAT_ONLY" != "true" ]]; then
print_info "Running clang-tidy analysis${FIX_TIDY:+ with auto-fix}..."

# Handle parallel vs sequential execution
if [[ "$SEQUENTIAL" == "true" || "$PARALLEL" == "false" ]]; then
print_info "Using sequential clang-tidy (1 thread)..."
run_tidy_sequential
else
print_info "Using parallel clang-tidy ($JOBS threads)..."
run_tidy_parallel
fi
fi

# Run bool conversion fixer if requested
if [[ "$FIX_BOOL" == "true" ]]; then
print_info "Running explicit bool conversion fixer..."
"$PROJECT_ROOT/scripts/explicit-bool-fix.sh"
fi

# Run camelCase conversion if requested
if [[ "$CAMEL_CASE" == "true" ]]; then
print_info "Converting member variables to camelCase..."
"$PROJECT_ROOT/scripts/convert-to-camelcase.sh"
fi

# Summary
echo ""
print_info "Analysis complete!"
echo " Total files found: $TOTAL_FILES"

if [[ "$TIDY_ONLY" != "true" ]]; then
echo " Files formatted: $FILES_FORMATTED"
fi

# Exit with appropriate code
if [[ $FILES_FORMATTED -gt 0 ]]; then
print_warning "Some files were reformatted. Please review the changes before committing."
exit 1
elif [[ $FILES_WITH_TIDY_ISSUES_GLOBAL -gt 0 ]]; then
print_warning "Some files have clang-tidy issues. Please fix them before committing."
echo ""
print_info "Common fixes:"
echo " • Replace 'if(condition)' with 'if(condition == true)' for explicit bool comparison"
echo " • Use '--fix-bool' option to automatically fix bool conversions"
echo " • Use modern C++ features suggested by modernize-* checks"
echo " • Follow performance recommendations from performance-* checks"
exit 1
else
print_info "All files are properly formatted and pass semantic checks."
fi 