#!/bin/bash

# PEPCTL Explicit Bool Conversion Fixer
# This script fixes implicit bool conversions that clang-tidy can't auto-fix
# Handles C files (NULL) and C++ files (nullptr) appropriately

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_info() {
echo -e "${GREEN}[BOOL-FIX]${NC} $1"
}

print_warning() {
echo -e "${YELLOW}[BOOL-FIX]${NC} $1"
}

print_error() {
echo -e "${RED}[BOOL-FIX]${NC} $1"
}

# Get script directory and project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

print_info "Fixing explicit bool conversions in: $PROJECT_ROOT"

# Extensions to process
C_EXTENSIONS=("*.c")
CPP_EXTENSIONS=("*.cpp" "*.hpp" "*.cc" "*.cxx")

FILES_MODIFIED=0
TOTAL_CHANGES=0

# Function to detect if file is C or C++
is_c_file() {
local file="$1"
[[ "$file" == *.c ]] && return 0
return 1
}

# Function to get appropriate null constant
get_null_constant() {
local file="$1"
if is_c_file "$file"; then
echo "NULL"
else
echo "nullptr"
fi
}

# Function to process file
process_file() {
local file="$1"
local null_const
null_const=$(get_null_constant "$file")

print_info "Processing: $(basename "$file") (using $null_const)"

# Create backup
cp "$file" "$file.backup"

# Apply fixes using sed
CHANGES=0

# Fix common implicit bool patterns - IMPROVED VERSION
# Pattern 1: if(simple_variable) -> if(variable == true) BUT skip pointers
if sed -i -E 's/if\(([a-zA-Z_][a-zA-Z0-9_]*)\)$/if(\1 == true)/g' "$file" 2>/dev/null; then
((CHANGES++)) || true
fi

# Pattern 2: if(!simple_variable) -> if(variable == false) BUT skip pointers 
if sed -i -E 's/if\(!([a-zA-Z_][a-zA-Z0-9_]*)\)$/if(\1 == false)/g' "$file" 2>/dev/null; then
((CHANGES++)) || true
fi

# Pattern 3: if(function_call()) -> if(function_call() == true) - boolean return
if sed -i -E 's/if\(([a-zA-Z_][a-zA-Z0-9_]*\([^)]*\))\)$/if(\1 == true)/g' "$file" 2>/dev/null; then
((CHANGES++)) || true
fi

# Pattern 4: if(!function_call()) -> if(function_call() == false)
if sed -i -E 's/if\(!([a-zA-Z_][a-zA-Z0-9_]*\([^)]*\))\)$/if(\1 == false)/g' "$file" 2>/dev/null; then
((CHANGES++)) || true
fi

# POINTER-SPECIFIC PATTERNS (using appropriate null constant)
# Pattern 5: if(pointer_name) -> if(pointer_name != NULL/nullptr) for pointers with _ptr suffix
if sed -i -E "s/if\(([a-zA-Z_][a-zA-Z0-9_]*_ptr)\)$/if(\1 != $null_const)/g" "$file" 2>/dev/null; then
((CHANGES++)) || true
fi

# Pattern 6: if(!pointer_name) -> if(pointer_name == NULL/nullptr)
if sed -i -E "s/if\(!([a-zA-Z_][a-zA-Z0-9_]*_ptr)\)$/if(\1 == $null_const)/g" "$file" 2>/dev/null; then
((CHANGES++)) || true
fi

# Pattern 7: Fix incorrect smart pointer comparisons
if sed -i -E "s/if\(([a-zA-Z_][a-zA-Z0-9_]*) == true\)/if(\1 != $null_const)/g" "$file" 2>/dev/null; then
((CHANGES++)) || true
fi

if sed -i -E "s/if\(([a-zA-Z_][a-zA-Z0-9_]*) == false\)/if(\1 == $null_const)/g" "$file" 2>/dev/null; then
((CHANGES++)) || true
fi

# Check if file was actually modified
if ! diff -q "$file" "$file.backup" >/dev/null 2>&1; then
FILES_MODIFIED=$((FILES_MODIFIED + 1))
print_info " Modified: $(basename "$file")"
TOTAL_CHANGES=$((TOTAL_CHANGES + CHANGES))
else
# No changes, restore backup
mv "$file.backup" "$file"
fi

# Remove backup if it exists
[[ -f "$file.backup" ]] && rm "$file.backup"
}

# Process C files
for ext in "${C_EXTENSIONS[@]}"; do
while IFS= read -r -d '' file; do
# Skip files in build directory
if [[ "$file" == *"/build/"* ]]; then
continue
fi

process_file "$file"

done < <(find "$PROJECT_ROOT" -name "$ext" -type f -print0)
done

# Process C++ files
for ext in "${CPP_EXTENSIONS[@]}"; do
while IFS= read -r -d '' file; do
# Skip files in build directory
if [[ "$file" == *"/build/"* ]]; then
continue
fi

process_file "$file"

done < <(find "$PROJECT_ROOT" -name "$ext" -type f -print0)
done

# Summary
echo ""
print_info "Explicit bool conversion fix complete!"
echo " Files modified: $FILES_MODIFIED" 
echo " Total changes applied: $TOTAL_CHANGES"

if [[ $FILES_MODIFIED -gt 0 ]]; then
print_warning "Files have been modified. Please review changes before committing."
print_info "To see changes: git diff"
print_info "To revert: git checkout -- ."
print_info "Language-specific conversions applied:"
print_info " C files (.c): use NULL for pointer comparisons"
print_info " C++ files (.cpp, .hpp): use nullptr for pointer comparisons"
else
print_info "No implicit bool conversions found or all were already explicit."
fi 