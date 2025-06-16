#!/bin/bash

# PEPCTL Version Management Script
# Updates version across CMakeLists.txt, Debian changelog, and VERSION file

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Function to show current versions
show_versions() {
    echo "Current versions:"
    echo "=================="
    
    # CMake version
    CMAKE_VERSION=$(grep "project.*VERSION" "$PROJECT_ROOT/CMakeLists.txt" | sed -n 's/.*VERSION \([0-9.]*\).*/\1/p')
    echo "CMake version: $CMAKE_VERSION"
    
    # VERSION file
    if [ -f "$PROJECT_ROOT/VERSION" ]; then
        VERSION_FILE=$(cat "$PROJECT_ROOT/VERSION")
        echo "VERSION file: $VERSION_FILE"
    else
        echo "VERSION file: Not found"
    fi
    
    # Debian changelog
    if [ -f "$PROJECT_ROOT/packaging/debian/changelog" ]; then
        DEB_VERSION=$(head -1 "$PROJECT_ROOT/packaging/debian/changelog" | sed -n 's/pepctl (\([^)]*\)).*/\1/p')
        echo "Debian version: $DEB_VERSION"
    else
        echo "Debian changelog: Not found"
    fi
    
    echo ""
}

# Function to update version
update_version() {
    local new_version="$1"
    local debian_revision="${2:-1}"
    
    if [ -z "$new_version" ]; then
        echo "Error: No version specified"
        echo "Usage: $0 update <version> [debian_revision]"
        echo "Example: $0 update 1.1.0 1"
        exit 1
    fi
    
    # Validate version format
    if ! echo "$new_version" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+$'; then
        echo "Error: Invalid version format. Use X.Y.Z (e.g., 1.0.0)"
        exit 1
    fi
    
    echo "Updating to version $new_version-$debian_revision..."
    
    # Update VERSION file
    echo "$new_version" > "$PROJECT_ROOT/VERSION"
    echo "Updated VERSION file"
    
    # Update CMakeLists.txt
    sed -i "s/project(pepctl VERSION [0-9.]*/project(pepctl VERSION $new_version/" "$PROJECT_ROOT/CMakeLists.txt"
    echo "Updated CMakeLists.txt"
    
    # Update Debian changelog
    if command -v dch >/dev/null 2>&1; then
        cd "$PROJECT_ROOT"
        export DEBEMAIL="dev@pepctl.org"
        export DEBFULLNAME="PEPCTL Development Team"
        dch -v "$new_version-$debian_revision" "Version $new_version release"
        echo "Updated Debian changelog using dch"
    else
        echo "Warning: 'dch' command not found. Please update packaging/debian/changelog manually"
        echo "New version should be: $new_version-$debian_revision"
    fi
    
    echo ""
    echo "Version update completed!"
    show_versions
}

# Function to check version consistency
check_consistency() {
    echo "Checking version consistency..."
    echo "=============================="
    
    # Get versions
    CMAKE_VERSION=$(grep "project.*VERSION" "$PROJECT_ROOT/CMakeLists.txt" | sed -n 's/.*VERSION \([0-9.]*\).*/\1/p')
    VERSION_FILE=""
    if [ -f "$PROJECT_ROOT/VERSION" ]; then
        VERSION_FILE=$(cat "$PROJECT_ROOT/VERSION")
    fi
    DEB_VERSION=""
    if [ -f "$PROJECT_ROOT/packaging/debian/changelog" ]; then
        DEB_VERSION=$(head -1 "$PROJECT_ROOT/packaging/debian/changelog" | sed -n 's/pepctl (\([^-]*\)).*/\1/p')
    fi
    
    # Check consistency
    local consistent=true
    
    if [ "$CMAKE_VERSION" != "$VERSION_FILE" ]; then
        echo "MISMATCH: CMake ($CMAKE_VERSION) vs VERSION file ($VERSION_FILE)"
        consistent=false
    fi
    
    if [ "$CMAKE_VERSION" != "$DEB_VERSION" ]; then
        echo "MISMATCH: CMake ($CMAKE_VERSION) vs Debian ($DEB_VERSION)"
        consistent=false
    fi
    
    if [ "$consistent" = true ]; then
        echo "All versions are consistent: $CMAKE_VERSION"
    else
        echo ""
        echo "Run '$0 update <version>' to fix inconsistencies"
    fi
    
    echo ""
}

# Function to show help
show_help() {
    echo "PEPCTL Version Management Script"
    echo "==============================="
    echo ""
    echo "Usage: $0 <command> [arguments]"
    echo ""
    echo "Commands:"
    echo "  show                     Show current versions"
    echo "  update <version> [rev]   Update to new version (default debian revision: 1)"
    echo "  check                    Check version consistency"
    echo "  help                     Show this help"
    echo ""
    echo "Examples:"
    echo "  $0 show"
    echo "  $0 update 1.1.0"
    echo "  $0 update 1.1.0 2"
    echo "  $0 check"
    echo ""
}

# Main script logic
case "${1:-show}" in
    show)
        show_versions
        ;;
    update)
        update_version "$2" "$3"
        ;;
    check)
        check_consistency
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        echo "Unknown command: $1"
        echo ""
        show_help
        exit 1
        ;;
esac 