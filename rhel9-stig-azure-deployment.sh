#!/bin/bash

#############################################################################
#                                                                           #
#  RHEL 9 STIG Deployment Script for Microsoft Azure                       #
#  Version: 1.0                                                             #
#  Date: 2025-08-28                                                         #
#  Purpose: Automate DISA STIG compliance configuration for RHEL 9         #
#           while preserving Azure Bastion connectivity                     #
#                                                                           #
#  Security Sources:                                                        #
#  - RHEL 9 STIG V2R5 Manual (DISA)                                        #
#  - Cloud Computing SRG V1R4 (DISA)                                       #
#  - Red Hat Security Hardening Guide                                      #
#  - MITRE RHEL 9 STIG Baseline                                            #
#                                                                           #
#############################################################################

# Script metadata
readonly SCRIPT_NAME="rhel9-stig-azure-deployment"
readonly SCRIPT_VERSION="1.0"
readonly SCRIPT_DATE="$(date +%F)"

# Exit on any error, undefined variable, or pipe failure
# Note: Using more lenient error handling for Azure environment compatibility
set -euo pipefail

# Ensure script is run as root
if [[ $EUID -ne 0 ]]; then
   echo "ERROR: This script must be run as root (or with sudo)" 
   exit 1
fi

# Logging setup
readonly LOG_DIR="/var/log/stig-deployment"
readonly LOG_FILE="${LOG_DIR}/stig_deployment_$(date +%F_%H-%M-%S).log"
readonly SUMMARY_LOG="${LOG_DIR}/stig_summary_$(date +%F_%H-%M-%S).log"

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

# DOD Banner Text (STIG V-257779 requirement)
readonly DOD_BANNER_TEXT="You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the following conditions:

-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.

-At any time, the USG may inspect and seize data stored on this IS.

-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.

-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.

-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."

#############################################################################
# Utility Functions
#############################################################################

log_info() {
    echo -e "${GREEN}[INFO]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $*"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $*"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $*"
}

log_skip() {
    echo -e "${BLUE}[SKIP]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $*"
}

check_file_exists() {
    local file="$1"
    if [[ -f "$file" ]]; then
        return 0
    else
        return 1
    fi
}

backup_config_file() {
    local file="$1"
    if [[ -f "$file" ]]; then
        cp "$file" "${file}.backup.$(date +%Y%m%d_%H%M%S)"
        log_info "Backed up $file"
    fi
}

update_config_setting() {
    local file="$1"
    local setting="$2"
    local value="$3"
    local comment="$4"
    
    backup_config_file "$file"
    
    # Remove existing setting if present
    sed -i "/^${setting}/d" "$file"
    sed -i "/^#.*${setting}/d" "$file"
    
    # Add new setting
    echo "# ${comment}" >> "$file"
    echo "${setting} ${value}" >> "$file"
    
    log_info "Updated ${setting} in $file"
}

service_is_enabled() {
    systemctl is-enabled "$1" &>/dev/null
}

service_is_active() {
    systemctl is-active "$1" &>/dev/null
}

package_is_installed() {
    rpm -q "$1" &>/dev/null
}

#############################################################################
# STIG Control Functions
#############################################################################

# STIG V-257777: Verify RHEL 9 is vendor-supported (Bulletproof version)
stig_257777() {
    log_info "Applying STIG V-257777: Verify RHEL 9 is vendor-supported"
    ((TOTAL_CONTROLS++))
    
    # Multiple fallback methods to determine RHEL version
    local rhel_version=""
    local version_found=false
    
    # Method 1: /etc/redhat-release (primary)
    if [[ -f /etc/redhat-release ]] && [[ -r /etc/redhat-release ]]; then
        rhel_version=$(cat /etc/redhat-release 2>/dev/null || echo "")
        if [[ -n "$rhel_version" ]]; then
            log_info "OS version detected: $rhel_version"
            version_found=true
        fi
    fi
    
    # Method 2: /etc/system-release (fallback)
    if [[ "$version_found" == false ]] && [[ -f /etc/system-release ]]; then
        rhel_version=$(cat /etc/system-release 2>/dev/null || echo "")
        if [[ -n "$rhel_version" ]]; then
            log_info "OS version detected (fallback): $rhel_version"
            version_found=true
        fi
    fi
    
    if [[ "$version_found" == false ]]; then
        log_error "Could not determine OS version"
        ((FAILED_CONTROLS++))
        return 1
    fi
    
    # Multiple verification methods for RHEL 9
    local is_rhel9=false
    
    # Check 1: Look for "Red Hat" and "9"
    if echo "$rhel_version" | grep -i "red hat" >/dev/null 2>&1 && echo "$rhel_version" | grep "9" >/dev/null 2>&1; then
        is_rhel9=true
    fi
    
    # Check 2: Look for specific RHEL patterns
    if [[ "$is_rhel9" == false ]]; then
        if echo "$rhel_version" | grep -iE "(rhel.*9|enterprise.*linux.*9|release 9)" >/dev/null 2>&1; then
            is_rhel9=true
        fi
    fi
    
    # Check 3: Look for version 9.x
    if [[ "$is_rhel9" == false ]]; then
        if echo "$rhel_version" | grep -E "9\.[0-9]+" >/dev/null 2>&1; then
            is_rhel9=true
        fi
    fi
    
    # Final result
    if [[ "$is_rhel9" == true ]]; then
        log_info "RHEL 9 detected - version appears to be supported"
        ((APPLIED_CONTROLS++))
    else
        log_warn "Unable to verify RHEL 9 version support: $rhel_version"
        ((FAILED_CONTROLS++))
    fi
}

# STIG V-257778: Install security updates
stig_257778() {
    log_info "Applying STIG V-257778: Install security patches and updates"
    ((TOTAL_CONTROLS++))
    
    log_info "Updating system packages..."
    if dnf update -y; then
        log_info "System packages updated successfully"
        ((APPLIED_CONTROLS++))
    else
        log_error "Failed to update system packages"
        ((FAILED_CONTROLS++))
    fi
}

# STIG V-257779: Configure DOD login banner
stig_257779() {
    log_info "Applying STIG V-257779: Configure DOD Notice and Consent Banner"
    ((TOTAL_CONTROLS++))
    
    # Configure /etc/issue
    echo "$DOD_BANNER_TEXT" > /etc/issue
    chmod 644 /etc/issue
    chown root:root /etc/issue
    
    # Configure /etc/issue.net for network logins
    echo "$DOD_BANNER_TEXT" > /etc/issue.net
    chmod 644 /etc/issue.net
    chown root:root /etc/issue.net
    
    log_info "DOD banner configured in /etc/issue and /etc/issue.net"
    ((APPLIED_CONTROLS++))
}

# STIG V-257781: Disable graphical interface
stig_257781() {
    log_info "Applying STIG V-257781: Set default target to multi-user (disable GUI)"
    ((TOTAL_CONTROLS++))
    
    if systemctl get-default | grep -q "graphical.target"; then
        systemctl set-default multi-user.target
        log_info "Default target set to multi-user.target"
        ((APPLIED_CONTROLS++))
    else
        log_info "System already configured for multi-user target"
        ((APPLIED_CONTROLS++))
    fi
}

# STIG V-257782: Enable hardware random number generator
stig_257782() {
    log_info "Applying STIG V-257782: Enable hardware random number generator"
    ((TOTAL_CONTROLS++))
    
    # Check if FIPS mode is enabled (this control is N/A if FIPS is on)
    if [[ -f /proc/sys/crypto/fips_enabled ]] && [[ "$(cat /proc/sys/crypto/fips_enabled)" == "1" ]]; then
        log_info "FIPS mode enabled - STIG V-257782 is Not Applicable"
        ((APPLIED_CONTROLS++))
        return
    fi
    
    if ! package_is_installed rng-tools; then
        dnf install -y rng-tools
    fi
    
    systemctl enable --now rngd
    
    if service_is_active rngd; then
        log_info "rngd service enabled and started"
        ((APPLIED_CONTROLS++))
    else
        log_error "Failed to start rngd service"
        ((FAILED_CONTROLS++))
    fi
}

# STIG V-257783: Enable systemd-journald
stig_257783() {
    log_info "Applying STIG V-257783: Enable systemd-journald service"
    ((TOTAL_CONTROLS++))
    
    systemctl enable --now systemd-journald
    
    if service_is_active systemd-journald; then
        log_info "systemd-journald service enabled and active"
        ((APPLIED_CONTROLS++))
    else
        log_error "Failed to enable systemd-journald service"
        ((FAILED_CONTROLS++))
    fi
}

# STIG V-257784: Disable Ctrl-Alt-Delete burst
stig_257784() {
    log_info "Applying STIG V-257784: Disable Ctrl-Alt-Delete burst key sequence"
    ((TOTAL_CONTROLS++))
    
    # Configure systemd to disable Ctrl-Alt-Delete burst
    local systemd_conf="/etc/systemd/system.conf"
    backup_config_file "$systemd_conf"
    
    # Remove any existing CtrlAltDelBurstAction settings
    sed -i '/^CtrlAltDelBurstAction/d' "$systemd_conf"
    sed -i '/^#.*CtrlAltDelBurstAction/d' "$systemd_conf"
    
    # Add the setting
    echo "CtrlAltDelBurstAction=none" >> "$systemd_conf"
    
    systemctl daemon-reload
    
    log_info "Ctrl-Alt-Delete burst sequence disabled"
    ((APPLIED_CONTROLS++))
}

# STIG V-257785: Disable Ctrl-Alt-Delete target
stig_257785() {
    log_info "Applying STIG V-257785: Disable x86 Ctrl-Alt-Delete key sequence"
    ((TOTAL_CONTROLS++))
    
    systemctl mask --now ctrl-alt-del.target
    
    if systemctl is-masked ctrl-alt-del.target; then
        log_info "ctrl-alt-del.target masked successfully"
        ((APPLIED_CONTROLS++))
    else
        log_error "Failed to mask ctrl-alt-del.target"
        ((FAILED_CONTROLS++))
    fi
}

# STIG V-257786: Disable debug-shell
stig_257786() {
    log_info "Applying STIG V-257786: Disable debug-shell systemd service"
    ((TOTAL_CONTROLS++))
    
    systemctl mask --now debug-shell.service
    
    if systemctl is-masked debug-shell.service; then
        log_info "debug-shell.service masked successfully"
        ((APPLIED_CONTROLS++))
    else
        log_error "Failed to mask debug-shell.service"
        ((FAILED_CONTROLS++))
    fi
}

# STIG V-257787: Require boot loader superuser password
stig_257787() {
    log_info "Applying STIG V-257787: Set boot loader superuser password"
    ((TOTAL_CONTROLS++))
    
    log_warn "GRUB2 password must be set manually by administrator"
    log_info "Use 'grub2-setpassword' command to set GRUB superuser password"
    log_info "Then run 'grub2-mkconfig -o /boot/grub2/grub.cfg' to apply changes"
    
    # We can't automate this as it requires interactive password input
    ((SKIPPED_CONTROLS++))
}

# STIG V-257788: Disable interactive boot
stig_257788() {
    log_info "Applying STIG V-257788: Disable interactive boot process"
    ((TOTAL_CONTROLS++))
    
    grubby --update-kernel=ALL --remove-args="systemd.confirm_spawn"
    
    log_info "Interactive boot disabled"
    ((APPLIED_CONTROLS++))
}

# STIG V-257789: Configure unique superuser name
stig_257789() {
    log_info "Applying STIG V-257789: Configure unique GRUB superuser name"
    ((TOTAL_CONTROLS++))
    
    log_warn "GRUB superuser configuration requires manual setup"
    log_info "Administrator must manually configure /etc/grub.d/01_users with unique superuser name"
    log_info "Avoid using easily guessable names like 'admin', 'administrator', 'root'"
    
    ((SKIPPED_CONTROLS++))
}

# STIG V-257790: Set GRUB configuration file ownership
stig_257790() {
    log_info "Applying STIG V-257790: Set /boot/grub2/grub.cfg group ownership to root"
    ((TOTAL_CONTROLS++))
    
    if [[ -f /boot/grub2/grub.cfg ]]; then
        chgrp root /boot/grub2/grub.cfg
        log_info "Set /boot/grub2/grub.cfg group ownership to root"
        ((APPLIED_CONTROLS++))
    else
        log_warn "/boot/grub2/grub.cfg not found"
        ((FAILED_CONTROLS++))
    fi
}

# STIG V-257936: Enable firewalld service
stig_257936() {
    log_info "Applying STIG V-257936: Enable firewalld service"
    ((TOTAL_CONTROLS++))
    
    # Check if we're in a container
    if [[ "$(systemd-detect-virt)" == "docker" ]]; then
        log_info "Container environment detected - firewalld management handled by container platform"
        ((APPLIED_CONTROLS++))
        return
    fi
    
    # AZURE BASTION CONSIDERATION: firewalld might affect Bastion connectivity
    log_skip "SKIPPED: firewalld enablement might affect Azure Bastion connectivity"
    log_info "Manual Action Required: Enable firewalld with appropriate rules for Azure Bastion"
    log_info "Commands to run manually after reviewing network requirements:"
    log_info "  systemctl enable --now firewalld"
    log_info "  firewall-cmd --permanent --add-service=ssh"
    log_info "  firewall-cmd --reload"
    
    ((SKIPPED_CONTROLS++))
}

# STIG V-257979: Enable SSH service
stig_257979() {
    log_info "Applying STIG V-257979: Enable SSH service"
    ((TOTAL_CONTROLS++))
    
    if ! package_is_installed openssh-server; then
        dnf install -y openssh-server
    fi
    
    systemctl enable --now sshd
    
    if service_is_active sshd; then
        log_info "SSH service enabled and active"
        ((APPLIED_CONTROLS++))
    else
        log_error "Failed to enable SSH service"
        ((FAILED_CONTROLS++))
    fi
}

# STIG V-257981: Configure SSH banner
stig_257981() {
    log_info "Applying STIG V-257981: Configure SSH banner"
    ((TOTAL_CONTROLS++))
    
    # AZURE BASTION CONSIDERATION: SSH configuration changes might affect Bastion
    log_skip "SKIPPED: SSH banner configuration might affect Azure Bastion connectivity"
    log_info "Manual Action Required: Configure SSH banner after verifying Bastion compatibility"
    log_info "Add to /etc/ssh/sshd_config: Banner /etc/issue"
    log_info "Then restart sshd: systemctl restart sshd"
    
    ((SKIPPED_CONTROLS++))
}

# STIG V-257985: Disable SSH root login
stig_257985() {
    log_info "Applying STIG V-257985: Disable SSH root login"
    ((TOTAL_CONTROLS++))
    
    # AZURE BASTION CONSIDERATION: This might affect Bastion if using root login
    log_skip "SKIPPED: SSH PermitRootLogin configuration might affect Azure Bastion connectivity"
    log_info "Manual Action Required: Configure PermitRootLogin after verifying Bastion setup"
    log_info "Add to /etc/ssh/sshd_config: PermitRootLogin no"
    log_info "Ensure you have alternative admin access before applying this change"
    
    ((SKIPPED_CONTROLS++))
}

# STIG V-257995: Configure SSH timeout - ClientAliveCountMax
stig_257995() {
    log_info "Applying STIG V-257995: Configure SSH ClientAliveCountMax"
    ((TOTAL_CONTROLS++))
    
    # AZURE BASTION CONSIDERATION: SSH timeout settings might affect Bastion sessions
    log_skip "SKIPPED: SSH timeout configuration might affect Azure Bastion sessions"
    log_info "Manual Action Required: Configure SSH timeouts after verifying Bastion requirements"
    log_info "Add to /etc/ssh/sshd_config: ClientAliveCountMax 1"
    
    ((SKIPPED_CONTROLS++))
}

# STIG V-257996: Configure SSH timeout - ClientAliveInterval
stig_257996() {
    log_info "Applying STIG V-257996: Configure SSH ClientAliveInterval"
    ((TOTAL_CONTROLS++))
    
    # AZURE BASTION CONSIDERATION: SSH timeout settings might affect Bastion sessions
    log_skip "SKIPPED: SSH timeout configuration might affect Azure Bastion sessions"
    log_info "Manual Action Required: Configure SSH timeouts after verifying Bastion requirements"
    log_info "Add to /etc/ssh/sshd_config: ClientAliveInterval 600"
    
    ((SKIPPED_CONTROLS++))
}

# Configure file permissions and ownership
configure_file_permissions() {
    log_info "Configuring file permissions and ownership"
    ((TOTAL_CONTROLS++))
    
    # Set proper permissions on key system files
    local files_to_secure=(
        "/etc/shadow:600:root:root"
        "/etc/gshadow:600:root:root"
        "/etc/passwd:644:root:root"
        "/etc/group:644:root:root"
        "/etc/fstab:644:root:root"
        "/etc/issue:644:root:root"
        "/etc/issue.net:644:root:root"
    )
    
    for file_spec in "${files_to_secure[@]}"; do
        IFS=':' read -r file perms owner group <<< "$file_spec"
        if [[ -f "$file" ]]; then
            chmod "$perms" "$file"
            chown "$owner:$group" "$file"
            log_info "Secured $file with permissions $perms and ownership $owner:$group"
        fi
    done
    
    ((APPLIED_CONTROLS++))
}

# Remove unnecessary packages
remove_unnecessary_packages() {
    log_info "Removing unnecessary packages"
    ((TOTAL_CONTROLS++))
    
    local packages_to_remove=(
        "nfs-utils"          # STIG V-257828
        "rsh-server"         # STIG V-257830  
        "gssproxy"           # STIG V-257832
        "quagga"             # STIG V-257836
        "telnet-server"
        "rsh"
        "ypbind"
        "ypserv"
        "tftp"
        "tftp-server"
        "talk"
        "talk-server"
    )
    
    local removed_count=0
    for package in "${packages_to_remove[@]}"; do
        if package_is_installed "$package"; then
            if dnf remove -y "$package"; then
                log_info "Removed package: $package"
                ((removed_count++))
            else
                log_warn "Failed to remove package: $package"
            fi
        fi
    done
    
    log_info "Removed $removed_count unnecessary packages"
    ((APPLIED_CONTROLS++))
}

# Configure audit system
configure_audit_system() {
    log_info "Configuring audit system"
    ((TOTAL_CONTROLS++))
    
    if ! package_is_installed audit; then
        dnf install -y audit
    fi
    
    systemctl enable --now auditd
    
    if service_is_active auditd; then
        log_info "Audit system enabled and configured"
        ((APPLIED_CONTROLS++))
    else
        log_error "Failed to enable audit system"
        ((FAILED_CONTROLS++))
    fi
}

# Configure system logging
configure_system_logging() {
    log_info "Configuring system logging"
    ((TOTAL_CONTROLS++))
    
    if ! package_is_installed rsyslog; then
        dnf install -y rsyslog
    fi
    
    systemctl enable --now rsyslog
    
    if service_is_active rsyslog; then
        log_info "System logging enabled and configured"
        ((APPLIED_CONTROLS++))
    else
        log_error "Failed to enable system logging"
        ((FAILED_CONTROLS++))
    fi
}

# Configure time synchronization
configure_time_sync() {
    log_info "Configuring time synchronization"
    ((TOTAL_CONTROLS++))
    
    if ! package_is_installed chrony; then
        dnf install -y chrony
    fi
    
    systemctl enable --now chronyd
    
    if service_is_active chronyd; then
        log_info "Time synchronization enabled and configured"
        ((APPLIED_CONTROLS++))
    else
        log_error "Failed to enable time synchronization"
        ((FAILED_CONTROLS++))
    fi
}

# Configure kernel parameters
configure_kernel_parameters() {
    log_info "Configuring kernel security parameters"
    ((TOTAL_CONTROLS++))
    
    local sysctl_conf="/etc/sysctl.d/99-stig-security.conf"
    
    cat > "$sysctl_conf" << 'EOF'
# RHEL 9 STIG Security Kernel Parameters
# IP Forwarding
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# IP Redirects
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Source routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# ICMP redirects
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0

# Log suspicious packets
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# Ignore ICMP ping requests
net.ipv4.icmp_echo_ignore_all = 1

# Ignore broadcast requests
net.ipv4.icmp_echo_ignore_broadcasts = 1

# SYN flood protection
net.ipv4.tcp_syncookies = 1

# Address space randomization
kernel.randomize_va_space = 2

# Core dumps
kernel.core_pattern = |/bin/false
EOF

    sysctl -p "$sysctl_conf"
    
    log_info "Kernel security parameters configured"
    ((APPLIED_CONTROLS++))
}

#############################################################################
# Cloud Computing SRG Placeholder Functions
#############################################################################

# TODO: Implement Cloud Computing SRG controls
# These are placeholder functions for manual implementation

cloud_srg_data_encryption() {
    log_info "Cloud SRG: Data encryption requirements"
    log_warn "Manual implementation required for cloud-specific encryption controls"
    log_info "Reference: DoD Cloud Computing SRG V1R4, Section 5.11"
}

cloud_srg_access_controls() {
    log_info "Cloud SRG: Access control requirements"
    log_warn "Manual implementation required for cloud-specific access controls"
    log_info "Reference: DoD Cloud Computing SRG V1R4, Section 5.4"
}

cloud_srg_monitoring() {
    log_info "Cloud SRG: Continuous monitoring requirements"
    log_warn "Manual implementation required for cloud-specific monitoring"
    log_info "Reference: DoD Cloud Computing SRG V1R4, Section 5.3"
}

#############################################################################
# Main Execution Function
#############################################################################

main() {
    log_info "====================================================================="
    log_info "Starting RHEL 9 STIG Deployment for Microsoft Azure"
    log_info "Script: $SCRIPT_NAME v$SCRIPT_VERSION"
    log_info "Date: $SCRIPT_DATE"
    log_info "Log File: $LOG_FILE"
    log_info "====================================================================="
    
    # Pre-flight checks
    log_info "Performing pre-flight checks..."
    
    # Check OS version (with error handling)
    if [[ -f /etc/redhat-release ]]; then
        local os_info
        os_info=$(cat /etc/redhat-release 2>/dev/null || echo "Unknown")
        log_info "Detected OS: $os_info"
        
        if ! echo "$os_info" | grep -E "(Red Hat Enterprise Linux.*9|release 9)" 2>/dev/null; then
            log_error "This script is designed for RHEL 9. Current OS may not be supported."
            log_warn "Continuing anyway, but results may be unpredictable."
        else
            log_info "RHEL 9 confirmed - proceeding with STIG deployment"
        fi
    else
        log_warn "/etc/redhat-release not found. Cannot verify OS version."
    fi
    
    # Check available disk space (with error handling)
    local available_space
    available_space=$(df / 2>/dev/null | awk 'NR==2 {print $4}' 2>/dev/null || echo "0")
    if [[ "$available_space" != "0" ]] && [[ $available_space -lt 1048576 ]]; then  # Less than 1GB
        log_warn "Less than 1GB of free space available. Consider cleaning up disk space."
    fi
    
    log_info "Pre-flight checks completed"
    
    # Start applying STIG controls
    log_info "Beginning STIG control implementation..."
    
    # Basic system configuration
    stig_257777  # Verify vendor support
    stig_257778  # Install updates
    stig_257779  # Configure DOD banner
    stig_257781  # Disable GUI
    stig_257782  # Enable RNG
    stig_257783  # Enable journald
    stig_257784  # Disable Ctrl-Alt-Del burst
    stig_257785  # Disable Ctrl-Alt-Del target
    stig_257786  # Disable debug shell
    stig_257787  # GRUB password (manual)
    stig_257788  # Disable interactive boot
    stig_257789  # GRUB superuser (manual)
    stig_257790  # GRUB file ownership
    
    # Network and SSH configuration (mostly skipped for Azure Bastion compatibility)
    stig_257936  # Firewalld (skipped)
    stig_257979  # Enable SSH
    stig_257981  # SSH banner (skipped)
    stig_257985  # SSH root login (skipped)
    stig_257995  # SSH timeout 1 (skipped)
    stig_257996  # SSH timeout 2 (skipped)
    
    # Additional security configurations
    configure_file_permissions
    remove_unnecessary_packages
    configure_audit_system
    configure_system_logging
    configure_time_sync
    configure_kernel_parameters
    
    # Cloud Computing SRG placeholders
    cloud_srg_data_encryption
    cloud_srg_access_controls
    cloud_srg_monitoring
    
    # Generate summary
    generate_summary
    
    log_info "====================================================================="
    log_info "RHEL 9 STIG Deployment Complete"
    log_info "====================================================================="
    log_info "Applied Controls: $APPLIED_CONTROLS"
    log_info "Skipped Controls: $SKIPPED_CONTROLS"
    log_info "Failed Controls: $FAILED_CONTROLS"
    log_info "Total Controls: $TOTAL_CONTROLS"
    log_info ""
    log_info "Log files:"
    log_info "  - Detailed log: $LOG_FILE"
    log_info "  - Summary log: $SUMMARY_LOG"
    log_info ""
    log_warn "IMPORTANT: Several SSH and network-related controls were skipped"
    log_warn "to preserve Azure Bastion connectivity. Review the log for manual"
    log_warn "implementation steps after confirming your access method."
    log_info "====================================================================="
    
    # Reboot recommendation
    if [[ $APPLIED_CONTROLS -gt 0 ]]; then
        log_warn "A system reboot is recommended to ensure all changes take effect."
        log_info "Run 'reboot' when ready to restart the system."
    fi
}

generate_summary() {
    log_info "Generating deployment summary..."
    
    cat > "$SUMMARY_LOG" << EOF
RHEL 9 STIG Deployment Summary
==============================
Date: $(date)
Hostname: $(hostname)
OS Version: $(cat /etc/redhat-release 2>/dev/null || echo "Unknown")

Control Statistics:
- Total Controls: $TOTAL_CONTROLS
- Applied Controls: $APPLIED_CONTROLS
- Skipped Controls: $SKIPPED_CONTROLS
- Failed Controls: $FAILED_CONTROLS
- Success Rate: $(( APPLIED_CONTROLS * 100 / TOTAL_CONTROLS ))%

Azure Bastion Considerations:
The following controls were skipped to preserve Azure Bastion connectivity:
- SSH Banner Configuration (V-257981)
- SSH Root Login Restriction (V-257985)
- SSH Timeout Settings (V-257995, V-257996)
- Firewall Configuration (V-257936)

Manual Actions Required:
1. Configure GRUB2 superuser password (V-257787)
2. Configure unique GRUB superuser name (V-257789)
3. Review and implement SSH hardening after verifying Bastion setup
4. Implement Cloud Computing SRG controls as needed
5. Configure firewall rules appropriate for Azure environment

Next Steps:
1. Review the detailed log: $LOG_FILE
2. Test Azure Bastion connectivity
3. Implement manual configuration items
4. Perform STIG compliance validation
5. Schedule regular security updates

EOF

    log_info "Summary generated: $SUMMARY_LOG"
}

# Trap to ensure cleanup on script exit
cleanup() {
    local exit_code=$?
    if [[ $exit_code -ne 0 ]]; then
        log_error "Script exited with error code: $exit_code"
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
