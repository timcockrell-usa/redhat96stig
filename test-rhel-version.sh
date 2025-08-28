#!/bin/bash

#############################################################################
# Simple RHEL Version Test - Debugging V-257777 Issue
#############################################################################

echo "=== Simple RHEL Version Test ==="
echo "Date: $(date)"
echo

# Test 1: Read the version file
echo "1. Reading /etc/redhat-release:"
if [[ -f /etc/redhat-release ]]; then
    rhel_version=$(cat /etc/redhat-release 2>/dev/null || echo "Failed to read")
    echo "   Content: '$rhel_version'"
else
    echo "   File not found!"
    exit 1
fi
echo

# Test 2: Test different regex patterns
echo "2. Testing regex patterns:"

# Pattern 1: Original (failing)
if [[ "$rhel_version" =~ "Red Hat Enterprise Linux".*"9\." ]]; then
    echo "   ✓ Pattern 1 (original): MATCHES"
else
    echo "   ✗ Pattern 1 (original): NO MATCH"
fi

# Pattern 2: Simplified
if [[ "$rhel_version" =~ "Red Hat Enterprise Linux".*"9" ]]; then
    echo "   ✓ Pattern 2 (simplified): MATCHES"
else
    echo "   ✗ Pattern 2 (simplified): NO MATCH"
fi

# Pattern 3: Using grep
if echo "$rhel_version" | grep -q "Red Hat Enterprise Linux.*9"; then
    echo "   ✓ Pattern 3 (grep): MATCHES"
else
    echo "   ✗ Pattern 3 (grep): NO MATCH"
fi

# Pattern 4: Even simpler
if echo "$rhel_version" | grep -q "release 9"; then
    echo "   ✓ Pattern 4 (release 9): MATCHES"
else
    echo "   ✗ Pattern 4 (release 9): NO MATCH"
fi

# Pattern 5: Most robust
if echo "$rhel_version" | grep -E "(Red Hat Enterprise Linux.*9|release 9)" >/dev/null 2>&1; then
    echo "   ✓ Pattern 5 (extended regex): MATCHES"
else
    echo "   ✗ Pattern 5 (extended regex): NO MATCH"
fi

echo

# Test 3: Show what we're actually working with
echo "3. String analysis:"
echo "   Length: ${#rhel_version}"
echo "   Contains 'Red Hat': $(echo "$rhel_version" | grep -o "Red Hat" || echo "NO")"
echo "   Contains '9': $(echo "$rhel_version" | grep -o "9" || echo "NO")"
echo "   Contains 'release': $(echo "$rhel_version" | grep -o "release" || echo "NO")"

echo
echo "=== Test Complete ==="

# Return success if any pattern matches
if echo "$rhel_version" | grep -E "(Red Hat Enterprise Linux.*9|release 9)" >/dev/null 2>&1; then
    echo "✓ RHEL 9 version verification: SUCCESS"
    exit 0
else
    echo "✗ RHEL 9 version verification: FAILED"
    exit 1
fi
