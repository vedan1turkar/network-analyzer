#!/bin/bash
#
# Build DONET .deb package
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

VERSION="1.0.0"
PKG_NAME="donet_${VERSION}_all.deb"
BUILD_DIR="debian-build"
INSTALL_DIR="$BUILD_DIR/usr/local"

echo "Building DONET .deb package..."

# Clean previous build
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR/DEBIAN"
mkdir -p "$INSTALL_DIR/bin"
mkdir -p "$INSTALL_DIR/share/donet"
mkdir -p "$BUILD_DIR/etc/donet"
mkdir -p "$BUILD_DIR/var/log/donet"

# Copy files
echo "Copying files..."

# Copy Python package
cp -r __init__.py cli.py packet_capture.py threat_analyzer.py reporter.py config.py "$INSTALL_DIR/share/donet/"
cp requirements.txt pyproject.toml "$INSTALL_DIR/share/donet/"
cp config.example.yaml "$INSTALL_DIR/share/donet/"

# Create wrapper script in bin
cat > "$INSTALL_DIR/bin/donet" << 'EOF'
#!/bin/bash
# DONET wrapper
exec python3 /usr/local/share/donet/cli.py "$@"
EOF
chmod +x "$INSTALL_DIR/bin/donet"

# Copy Debian control file
cp debian/DEBIAN/control "$BUILD_DIR/DEBIAN/"
cp debian/DEBIAN/postinst "$BUILD_DIR/DEBIAN/"

# Set permissions
chmod 755 "$BUILD_DIR/DEBIAN/postinst"

# Build package
dpkg-deb --build "$BUILD_DIR" "$PKG_NAME"

echo ""
echo "✓ Package built: $PKG_NAME"
echo ""
echo "To install:"
echo "  sudo dpkg -i $PKG_NAME"
echo ""
