#!/bin/bash

#############################################################################
# RHEL 9 STIG Test Script for Microsoft Azure
# This is a simplified version for testing basic functionality
#############################################################################

# Script metadata
readonly SCRIPT_NAME="rhel9-stig-test"
readonly SCRIPT_VERSION="1.0-test"
readonly SCRIPT_DATE="2025-08-28"

# Safer error handling for testing
set -e

# Ensure script is run as root
if [[ $EUID -ne 0 ]]; then
   echo "ERROR: This script must be run as root (or with sudo)" 
   exit 1
fi

# Logging setup
readonly LOG_DIR="/var/log/stig-deployment"
readonly LOG_FILE="${LOG_DIR}/stig_test_$(date +%F_%H-%M-%S).log"

# Create log directory if it doesn't exist
mkdir -p "${LOG_DIR}"

# Setup logging to both console and file
exec > >(tee -a "${LOG_FILE}")
exec 2> >(tee -a "${LOG_FILE}" >&2)

# Color codes for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m' # No Color

# Global counters
declare -i TOTAL_CONTROLS=0
declare -i APPLIED_CONTROLS=0
declare -i SKIPPED_CONTROLS=0
declare -i FAILED_CONTROLS=0

# Logging functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $*"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $*"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $*"
}

# Test function to verify basic functionality
test_basic_functions() {
    log_info "Testing basic functions..."
    ((TOTAL_CONTROLS++))
    
    # Test 1: Check OS info
    log_info "Test 1: OS Information"
    if [[ -f /etc/redhat-release ]]; then
        local os_info
        os_info=$(cat /etc/redhat-release 2>/dev/null || echo "Unknown")
        log_info "OS: $os_info"
    else
        log_warn "/etc/redhat-release not found"
    fi
    
    # Test 2: Check basic commands
    log_info "Test 2: Required Commands"
    local required_commands=("dnf" "systemctl" "firewall-cmd")
    for cmd in "${required_commands[@]}"; do
        if command -v "$cmd" >/dev/null 2>&1; then
            log_info "✓ $cmd found"
        else
            log_warn "✗ $cmd NOT found"
        fi
    done
    
    # Test 3: Check disk space
    log_info "Test 3: Disk Space"
    local available_space
    available_space=$(df / 2>/dev/null | awk 'NR==2 {print $4}' 2>/dev/null || echo "0")
    if [[ "$available_space" != "0" ]]; then
        log_info "Available space: $available_space KB"
    else
        log_warn "Could not determine disk space"
    fi
    
    ((APPLIED_CONTROLS++))
    log_info "Basic function test completed successfully"
}

# Simple STIG function test (V-257777 equivalent)
test_stig_257777() {
    log_info "Testing STIG V-257777: Verify RHEL 9 is vendor-supported"
    ((TOTAL_CONTROLS++))
    
    if [[ -f /etc/redhat-release ]]; then
        local rhel_version
        rhel_version=$(cat /etc/redhat-release 2>/dev/null || echo "Unknown")
        
        log_info "Current RHEL version: $rhel_version"
        
        # Check if version contains RHEL 9
        if echo "$rhel_version" | grep -q "Red Hat Enterprise Linux.*9\." 2>/dev/null; then
            log_info "✓ RHEL 9 detected - version appears to be supported"
            ((APPLIED_CONTROLS++))
            return 0
        else
            log_warn "Unable to verify RHEL 9 version support"
            ((FAILED_CONTROLS++))
            return 1
        fi
    else
        log_error "/etc/redhat-release file not found"
        ((FAILED_CONTROLS++))
        return 1
    fi
}

# Main function
main() {
    log_info "====================================================================="
    log_info "Starting RHEL 9 STIG Test Script for Microsoft Azure"
    log_info "Script: $SCRIPT_NAME v$SCRIPT_VERSION"
    log_info "Date: $SCRIPT_DATE"
    log_info "Log File: $LOG_FILE"
    log_info "====================================================================="
    
    # Run tests
    test_basic_functions
    test_stig_257777
    
    # Summary
    log_info "====================================================================="
    log_info "Test Summary:"
    log_info "Total Controls Tested: $TOTAL_CONTROLS"
    log_info "Successfully Applied: $APPLIED_CONTROLS"
    log_info "Failed: $FAILED_CONTROLS"
    log_info "Skipped: $SKIPPED_CONTROLS"
    log_info "====================================================================="
    
    if [[ $FAILED_CONTROLS -eq 0 ]]; then
        log_info "✓ All tests passed! The main script should work correctly."
        return 0
    else
        log_error "✗ Some tests failed. Check the issues above before running main script."
        return 1
    fi
}

# Error handling
cleanup() {
    local exit_code=$?
    if [[ $exit_code -ne 0 ]]; then
        log_error "Test script exited with error code: $exit_code"
        log_error "Check the log file for details: $LOG_FILE"
    fi
}

trap cleanup EXIT

# Execute main function
main "$@"

# Exit with appropriate code
if [[ $FAILED_CONTROLS -gt 0 ]]; then
    exit 1
else
    exit 0
fi
