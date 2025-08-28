#!/bin/bash

#############################################################################
# STIG Script Debug Helper
# This script helps diagnose issues with the main STIG deployment script
#############################################################################

echo "=== STIG Script Debug Helper ==="
echo "Date: $(date)"
echo

# Check if running as root
echo "1. Checking user privileges..."
if [[ $EUID -eq 0 ]]; then
    echo "   ✓ Running as root"
else
    echo "   ✗ NOT running as root (required for STIG script)"
    echo "   Please run: sudo $0"
    exit 1
fi
echo

# Check system information
echo "2. System Information:"
echo "   OS Release:"
if [[ -f /etc/redhat-release ]]; then
    echo "     $(cat /etc/redhat-release)"
else
    echo "     /etc/redhat-release not found"
fi

echo "   Kernel Version: $(uname -r)"
echo "   Architecture: $(uname -m)"
echo

# Check required commands
echo "3. Checking required commands..."
required_commands=("dnf" "systemctl" "firewall-cmd" "grep" "awk" "sed")
for cmd in "${required_commands[@]}"; do
    if command -v "$cmd" >/dev/null 2>&1; then
        echo "   ✓ $cmd found"
    else
        echo "   ✗ $cmd NOT found"
    fi
done
echo

# Check log directory
echo "4. Checking log directory..."
LOG_DIR="/var/log/stig-deployment"
if [[ -d "$LOG_DIR" ]]; then
    echo "   ✓ Log directory exists: $LOG_DIR"
    echo "   Directory contents:"
    ls -la "$LOG_DIR" | head -10
else
    echo "   Creating log directory: $LOG_DIR"
    mkdir -p "$LOG_DIR"
    if [[ $? -eq 0 ]]; then
        echo "   ✓ Log directory created successfully"
    else
        echo "   ✗ Failed to create log directory"
    fi
fi
echo

# Test basic script syntax
echo "5. Testing main script syntax..."
SCRIPT_PATH="./rhel9-stig-azure-deployment.sh"
if [[ -f "$SCRIPT_PATH" ]]; then
    echo "   Script found: $SCRIPT_PATH"
    echo "   Checking syntax..."
    if bash -n "$SCRIPT_PATH"; then
        echo "   ✓ Script syntax is valid"
    else
        echo "   ✗ Script has syntax errors"
    fi
else
    echo "   ✗ Script not found: $SCRIPT_PATH"
fi
echo

# Test individual function
echo "6. Testing V-257777 function (first failing control)..."
cat << 'EOF' > /tmp/test_v257777.sh
#!/bin/bash

# Simple test of the problematic function
stig_257777_test() {
    echo "Testing V-257777 function..."
    
    local rhel_version
    rhel_version=$(cat /etc/redhat-release 2>/dev/null || echo "Unknown")
    
    echo "Current RHEL version: $rhel_version"
    
    # Check if version contains RHEL 9
    if [[ "$rhel_version" =~ "Red Hat Enterprise Linux".*"9\." ]]; then
        echo "RHEL 9 detected - version appears to be supported"
        return 0
    else
        echo "Unable to verify RHEL 9 version support"
        return 1
    fi
}

stig_257777_test
EOF

chmod +x /tmp/test_v257777.sh
echo "   Running isolated test..."
if /tmp/test_v257777.sh; then
    echo "   ✓ V-257777 function works in isolation"
else
    echo "   ✗ V-257777 function failed in isolation"
fi
rm -f /tmp/test_v257777.sh
echo

echo "=== Debug Complete ==="
echo "If the script syntax is valid but still fails, try running with:"
echo "  bash -x ./rhel9-stig-azure-deployment.sh"
echo "This will show detailed execution steps."
