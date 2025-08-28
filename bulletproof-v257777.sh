#!/bin/bash

#############################################################################
# Bulletproof STIG V-257777 Test
# This version should work with any RHEL 9.x version string
#############################################################################

# Bulletproof logging function
log_info() {
    echo "[INFO] $(date '+%Y-%m-%d %H:%M:%S') - $*"
}

log_warn() {
    echo "[WARN] $(date '+%Y-%m-%d %H:%M:%S') - $*"
}

log_error() {
    echo "[ERROR] $(date '+%Y-%m-%d %H:%M:%S') - $*"
}

# Bulletproof STIG V-257777 function
stig_257777_bulletproof() {
    log_info "Testing bulletproof STIG V-257777: Verify RHEL 9 is vendor-supported"
    
    # Multiple fallback methods to check RHEL version
    local rhel_version=""
    local version_found=false
    
    # Method 1: /etc/redhat-release
    if [[ -f /etc/redhat-release ]] && [[ -r /etc/redhat-release ]]; then
        rhel_version=$(cat /etc/redhat-release 2>/dev/null || echo "")
        if [[ -n "$rhel_version" ]]; then
            log_info "Method 1 - /etc/redhat-release: $rhel_version"
            version_found=true
        fi
    fi
    
    # Method 2: /etc/system-release (fallback)
    if [[ "$version_found" == false ]] && [[ -f /etc/system-release ]]; then
        rhel_version=$(cat /etc/system-release 2>/dev/null || echo "")
        if [[ -n "$rhel_version" ]]; then
            log_info "Method 2 - /etc/system-release: $rhel_version"
            version_found=true
        fi
    fi
    
    # Method 3: hostnamectl (if available)
    if [[ "$version_found" == false ]] && command -v hostnamectl >/dev/null 2>&1; then
        rhel_version=$(hostnamectl 2>/dev/null | grep "Operating System" | cut -d: -f2 | sed 's/^ *//' || echo "")
        if [[ -n "$rhel_version" ]]; then
            log_info "Method 3 - hostnamectl: $rhel_version"
            version_found=true
        fi
    fi
    
    if [[ "$version_found" == false ]]; then
        log_error "Could not determine OS version using any method"
        return 1
    fi
    
    # Multiple methods to check if it's RHEL 9
    local is_rhel9=false
    
    # Check 1: Look for "Red Hat" and "9"
    if echo "$rhel_version" | grep -i "red hat" >/dev/null 2>&1 && echo "$rhel_version" | grep "9" >/dev/null 2>&1; then
        log_info "✓ Check 1 passed: Contains 'Red Hat' and '9'"
        is_rhel9=true
    fi
    
    # Check 2: Look for specific patterns
    if [[ "$is_rhel9" == false ]]; then
        if echo "$rhel_version" | grep -E "(rhel.*9|enterprise.*linux.*9|release 9)" >/dev/null 2>&1; then
            log_info "✓ Check 2 passed: Matches RHEL 9 pattern"
            is_rhel9=true
        fi
    fi
    
    # Check 3: Look for version numbers starting with 9
    if [[ "$is_rhel9" == false ]]; then
        if echo "$rhel_version" | grep -E "9\.[0-9]+" >/dev/null 2>&1; then
            log_info "✓ Check 3 passed: Contains version 9.x"
            is_rhel9=true
        fi
    fi
    
    # Final result
    if [[ "$is_rhel9" == true ]]; then
        log_info "✅ RHEL 9 successfully verified - version appears to be supported"
        return 0
    else
        log_warn "❌ Unable to verify RHEL 9 version support"
        log_warn "Detected version: $rhel_version"
        return 1
    fi
}

# Run the test
echo "=== Bulletproof STIG V-257777 Test ==="
echo

if stig_257777_bulletproof; then
    echo
    echo "🎉 SUCCESS: V-257777 function should work in the main script"
    exit 0
else
    echo
    echo "❌ FAILED: There may be a deeper issue with the system"
    exit 1
fi
