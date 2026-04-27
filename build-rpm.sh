#!/bin/bash
#
# Build DONET RPM package
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

VERSION="1.0.0"
RPM_BUILD_DIR="rpm-build"
SPEC_FILE="donet.spec"

echo "Building DONET RPM package..."

# Clean previous build
rm -rf "$RPM_BUILD_DIR"
mkdir -p "$RPM_BUILD_DIR"

# Build RPM
rpmbuild -bb "$SPEC_FILE" \
    --define "_topdir $(pwd)/$RPM_BUILD_DIR" \
    --define "_builddir $(pwd)/$RPM_BUILD_DIR/BUILD" \
    --define "_rpmdir $(pwd)/$RPM_BUILD_DIR/RPMS" \
    --define "_sourcedir $(pwd)" \
    --define "_specdir $(pwd)" \
    --define "_srcrpmdir $(pwd)/$RPM_BUILD_DIR/SRPMS" \
    --define "_prefix /usr/local" 2>&1 || true

# Find the built RPM
if [ -f "$RPM_BUILD_DIR/RPMS/noarch/donet-${VERSION}-1.noarch.rpm" ]; then
    cp "$RPM_BUILD_DIR/RPMS/noarch/donet-${VERSION}-1.noarch.rpm" "./donet-${VERSION}-1.noarch.rpm"
    echo ""
    echo "✓ Package built: donet-${VERSION}-1.noarch.rpm"
    echo ""
    echo "To install:"
    echo "  sudo rpm -ivh donet-${VERSION}-1.noarch.rpm"
    echo ""
elif [ -f "$RPM_BUILD_DIR/RPMS/x86_64/donet-${VERSION}-1.x86_64.rpm" ]; then
    cp "$RPM_BUILD_DIR/RPMS/x86_64/donet-${VERSION}-1.x86_64.rpm" "./donet-${VERSION}-1.x86_64.rpm"
    echo ""
    echo "✓ Package built: donet-${VERSION}-1.x86_64.rpm"
    echo ""
    echo "To install:"
    echo "  sudo rpm -ivh donet-${VERSION}-1.x86_64.rpm"
    echo ""
else
    echo "RPM build may have encountered issues. Check output above."
    echo "You may need to install: sudo yum install rpm-build"
fi
