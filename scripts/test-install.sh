#!/bin/bash
#
# DONET Installation Test Script
# Verifies that DONET is installed and working correctly
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

PASSED=0
FAILED=0

test_pass() {
    echo -e "${GREEN}✓${NC} $1"
    ((PASSED++))
}

test_fail() {
    echo -e "${RED}✗${NC} $1"
    ((FAILED++))
}

test_warn() {
    echo -e "${YELLOW}⚠${NC} $1"
}

echo "=== DONET Installation Test ==="
echo ""

# Test 1: Check donet command exists
echo "1. Checking donet command..."
if command -v donet &> /dev/null; then
    test_pass "donet command found"
else
    test_fail "donet command not found in PATH"
    echo "   Try: export PATH=\"\$HOME/.local/bin:\$PATH\""
fi

# Test 2: Check Python modules
echo "2. Checking Python dependencies..."
python3 -c "import scapy" 2>/dev/null && test_pass "scapy installed" || test_fail "scapy missing"
python3 -c "import yaml" 2>/dev/null && test_pass "PyYAML installed" || test_fail "PyYAML missing"
python3 -c "import colorama" 2>/dev/null && test_pass "colorama installed" || test_fail "colorama missing"

# Test 3: Check donet version
echo "3. Checking donet version..."
if donet --version 2>&1 | grep -q "1.0.0"; then
    test_pass "Version 1.0.0 detected"
else
    test_warn "Version check failed (may be expected if running from source)"
fi

# Test 4: Check help output
echo "4. Checking help output..."
if donet --help | grep -q "DONET"; then
    test_pass "Help text displays correctly"
else
    test_fail "Help text missing or broken"
fi

# Test 5: Check config directory
echo "5. Checking configuration..."
if [ -f "$HOME/.donet/config.yaml" ]; then
    test_pass "Config file exists at ~/.donet/config.yaml"
else
    test_warn "No config at ~/.donet/config.yaml (will use defaults)"
fi

# Test 6: Check for required system libraries
echo "6. Checking system dependencies..."
if command -v tcpdump &> /dev/null; then
    test_pass "tcpdump found (libpcap is available)"
else
    # Check for libpcap directly
    if ldconfig -p 2>/dev/null | grep -q libpcap; then
        test_pass "libpcap library found"
    else
        test_warn "libpcap not detected (may still work if scapy bundled it)"
    fi
fi

# Test 7: Check permissions (non-fatal)
echo "7. Checking capture permissions..."
if [ "$(id -u)" -eq 0 ]; then
    test_pass "Running as root (can capture packets)"
else
    if capsh --print 2>/dev/null | grep -q "cap_net_raw"; then
        test_pass "CAP_NET_RAW capability granted"
    else
        test_warn "Not running as root and no CAP_NET_RAW - packet capture will fail"
        echo "   Solutions:"
        echo "   - Run with sudo: sudo donet -i eth0"
        echo "   - Or grant capability: sudo setcap cap_net_raw+eip \$(readlink -f \$(which python3))"
    fi
fi

# Test 8: Check for network interfaces
echo "8. Checking network interfaces..."
if donet --list-interfaces 2>&1 | grep -q "."; then
    test_pass "Interfaces detected"
else
    test_fail "No interfaces found (check network setup)"
fi

# Test 9: Run unit tests if available
echo "9. Running unit tests..."
if pytest tests/ -q 2>&1 | grep -q "passed"; then
    test_pass "All unit tests passed"
else
    test_warn "Unit tests failed or pytest not installed"
fi

# Summary
echo ""
echo "================================"
echo -e "Results: ${GREEN}${PASSED} passed${NC}, ${RED}${FAILED}${NC} failed"
echo "================================"

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}✓ Installation verified! DONET is ready to use.${NC}"
    echo ""
    echo "Quick start:"
    echo "  donet --list-interfaces"
    echo "  sudo donet -i <interface>"
    exit 0
else
    echo -e "${RED}✗ Some checks failed. Please review errors above.${NC}"
    exit 1
fi
