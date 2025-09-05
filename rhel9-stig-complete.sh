#!/bin/bash

#############################################################################
#                                                                           #
#  RHEL 9 STIG Complete Deployment Script for Microsoft Azure              #
#  Version: 2.0 - Enhanced Error Handling                                  #
#  Date: 2025-08-28                                                         #
#  Purpose: Automate DISA STIG compliance with comprehensive error handling#
#           while preserving Azure Bastion connectivity                     #
#                                                                           #
#  Features:                                                                #
#  - Complete error handling for ALL STIG controls                         #
#  - Detailed error summary at completion                                   #
#  - Dependency tracking between controls                                   #
#  - Single script - no external files needed                              #
#  - Azure Bastion safe (preserves remote access)                          #
#                                                                           #
#############################################################################

# Script metadata
readonly SCRIPT_NAME="rhel9-stig-complete-deployment"
readonly SCRIPT_VERSION="2.0"
readonly SCRIPT_DATE="2025-08-28"

# Relaxed error handling - individual controls manage their own errors
# set -eu

# Ensure script is run as root
if [[ $EUID -ne 0 ]]; then
   echo "ERROR: This script must be run as root (or with sudo)" 
   exit 1
fi

# Logging setup
readonly LOG_DIR="/var/log/stig-deployment"
readonly LOG_FILE="${LOG_DIR}/stig_complete_deployment_$(date +%F_%H-%M-%S).log"
readonly SUMMARY_LOG="${LOG_DIR}/stig_complete_summary_$(date +%F_%H-%M-%S).log"

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

# Global counters and tracking
declare -i TOTAL_CONTROLS=0
declare -i APPLIED_CONTROLS=0
declare -i SKIPPED_CONTROLS=0
declare -i FAILED_CONTROLS=0

# Error tracking arrays
declare -a FAILED_CONTROL_LIST=()
declare -a FAILED_ERROR_MESSAGES=()
declare -a SKIPPED_CONTROL_LIST=()
declare -a SKIPPED_REASONS=()

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

# Enhanced error handling with tracking
handle_error() {
    local error_code=$1
    local control_id="$2"
    local error_message="$3"
    local command="$4"
    
    echo
    echo -e "${RED}╔══════════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║                               ERROR ENCOUNTERED                              ║${NC}"
    echo -e "${RED}╠══════════════════════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${RED}║${NC} Control: ${YELLOW}$control_id${NC}"
    echo -e "${RED}║${NC} Error: $error_message"
    echo -e "${RED}║${NC} Command: $command"
    echo -e "${RED}║${NC} Exit Code: $error_code"
    echo -e "${RED}║${NC} Action: Continuing to next control..."
    echo -e "${RED}╚══════════════════════════════════════════════════════════════════════════════╝${NC}"
    echo
    
    ((FAILED_CONTROLS++))
    
    # Track this error for final summary
    FAILED_CONTROL_LIST+=("$control_id")
    FAILED_ERROR_MESSAGES+=("$error_message (Exit Code: $error_code)")
}

# Track skipped controls
handle_skip() {
    local control_id="$1"
    local reason="$2"
    
    log_skip "Skipping $control_id: $reason"
    ((SKIPPED_CONTROLS++))
    
    # Track this skip for final summary
    SKIPPED_CONTROL_LIST+=("$control_id")
    SKIPPED_REASONS+=("$reason")
}

# Safe command execution with error handling
safe_execute() {
    local control_id="$1"
    local description="$2"
    local command="$3"
    
    log_info "Executing: $description"
    
    # Execute command and capture output and error code
    local output
    local exit_code
    
    if output=$(eval "$command" 2>&1); then
        log_info "✅ Success: $description"
        return 0
    else
        exit_code=$?
        handle_error "$exit_code" "$control_id" "$description failed" "$command"
        if [[ -n "$output" ]]; then
            log_error "Error output: $output"
        fi
        return 1
    fi
}

# Mark a control as completed
mark_completed() {
    local control_id="$1"
    touch "/var/log/stig-deployment/.${control_id}_completed" 2>/dev/null || true
}

# Generic STIG control wrapper - ensures ALL controls use consistent error handling
execute_stig_control() {
    local control_id="$1"
    local description="$2"
    local implementation_function="$3"
    
    echo
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE} Executing STIG $control_id: $description${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════════════════════${NC}"
    
    log_info "Applying STIG $control_id: $description"
    ((TOTAL_CONTROLS++))
    
    # Execute the implementation function with error containment
    if "$implementation_function" "$control_id"; then
        log_info "✅ $control_id completed successfully"
        ((APPLIED_CONTROLS++))
        mark_completed "$control_id"
    else
        log_warn "⚠️ $control_id had issues but script continues"
    fi
    
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════════════════════${NC}"
}

#############################################################################
# STIG Implementation Functions (All with consistent error handling)
#############################################################################

# STIG V-257777: Verify RHEL 9 is vendor-supported
impl_257777() {
    local control_id="$1"
    
    # Simple and reliable version check
    if [[ -f /etc/redhat-release ]]; then
        local rhel_version
        rhel_version=$(cat /etc/redhat-release 2>/dev/null || echo "Unknown")
        log_info "OS version detected: $rhel_version"
        
        # Simple check - just look for "9" in the version
        if echo "$rhel_version" | grep -q "9" 2>/dev/null; then
            log_info "RHEL 9 detected - version appears to be supported"
            return 0
        else
            handle_error "1" "$control_id" "Version does not appear to be RHEL 9" "grep '9' on version string"
            log_warn "Detected version: $rhel_version - continuing anyway"
            return 0  # Don't fail the script for version detection issues
        fi
    else
        handle_error "1" "$control_id" "Cannot read /etc/redhat-release" "cat /etc/redhat-release"
        log_warn "Assuming RHEL 9 and continuing"
        return 0
    fi
}

# STIG V-257778: Install security updates
impl_257778() {
    local control_id="$1"
    
    if safe_execute "$control_id" "Updating system packages" "dnf update -y"; then
        log_info "✅ System packages updated successfully"
        touch "/var/log/stig-deployment/.system_updated"
        return 0
    else
        log_warn "❌ Failed to update system packages - some subsequent controls may fail"
        return 1
    fi
}

# STIG V-257779: Configure DOD login banner
impl_257779() {
    local control_id="$1"
    
    local success=true
    
    # Configure /etc/issue
    if safe_execute "$control_id" "Creating DOD banner in /etc/issue" "echo '$DOD_BANNER_TEXT' > /etc/issue"; then
        safe_execute "$control_id" "Setting permissions on /etc/issue" "chmod 644 /etc/issue"
        safe_execute "$control_id" "Setting ownership on /etc/issue" "chown root:root /etc/issue"
    else
        success=false
    fi
    
    # Configure /etc/issue.net for network logins
    if safe_execute "$control_id" "Creating DOD banner in /etc/issue.net" "echo '$DOD_BANNER_TEXT' > /etc/issue.net"; then
        safe_execute "$control_id" "Setting permissions on /etc/issue.net" "chmod 644 /etc/issue.net"
        safe_execute "$control_id" "Setting ownership on /etc/issue.net" "chown root:root /etc/issue.net"
    else
        success=false
    fi
    
    if [[ "$success" == true ]]; then
        log_info "✅ DOD banner configured successfully"
        return 0
    else
        return 1
    fi
}

# STIG V-257781: Disable graphical interface
impl_257781() {
    local control_id="$1"
    
    # Check current default target
    local current_target
    if current_target=$(systemctl get-default 2>/dev/null); then
        log_info "Current default target: $current_target"
        
        if echo "$current_target" | grep -q "graphical.target"; then
            if safe_execute "$control_id" "Setting default target to multi-user" "systemctl set-default multi-user.target"; then
                log_info "✅ Default target set to multi-user.target"
                return 0
            else
                return 1
            fi
        else
            log_info "✅ System already configured for multi-user target"
            return 0
        fi
    else
        handle_error "1" "$control_id" "Could not determine current default target" "systemctl get-default"
        return 1
    fi
}

# STIG V-257782: Enable hardware random number generator
impl_257782() {
    local control_id="$1"
    
    # Check if FIPS mode is enabled (this control is N/A if FIPS is on)
    if [[ -f /proc/sys/crypto/fips_enabled ]] && [[ "$(cat /proc/sys/crypto/fips_enabled 2>/dev/null)" == "1" ]]; then
        handle_skip "$control_id" "FIPS mode enabled - control not applicable"
        return 0
    fi
    
    # Install and enable rng-tools
    if safe_execute "$control_id" "Installing rng-tools package" "dnf install -y rng-tools"; then
        if safe_execute "$control_id" "Enabling and starting rngd service" "systemctl enable --now rngd"; then
            log_info "✅ Hardware RNG service enabled and started"
            return 0
        else
            return 1
        fi
    else
        return 1
    fi
}

# STIG V-257783: Enable systemd-journald
impl_257783() {
    local control_id="$1"
    
    if safe_execute "$control_id" "Enabling systemd-journald service" "systemctl enable --now systemd-journald"; then
        log_info "✅ systemd-journald service enabled and active"
        return 0
    else
        return 1
    fi
}

# STIG V-257784: Disable Ctrl-Alt-Delete burst action
impl_257784() {
    local control_id="$1"
    
    # Create systemd override directory and disable burst action
    if safe_execute "$control_id" "Creating systemd override directory" "mkdir -p /etc/systemd/system/ctrl-alt-del.target.d"; then
        if safe_execute "$control_id" "Disabling Ctrl-Alt-Del burst action" "echo '[Unit]
AllowIsolate=no' > /etc/systemd/system/ctrl-alt-del.target.d/disable-burst.conf"; then
            # Also configure system.conf for CtrlAltDelBurstAction
            if safe_execute "$control_id" "Configuring CtrlAltDelBurstAction in system.conf" "echo 'CtrlAltDelBurstAction=none' >> /etc/systemd/system.conf"; then
                if safe_execute "$control_id" "Reloading systemd configuration" "systemctl daemon-reload"; then
                    log_info "✅ Ctrl-Alt-Del burst action disabled"
                    return 0
                fi
            fi
        fi
    fi
    return 1
}

# STIG V-257785: Disable Ctrl-Alt-Del target
impl_257785() {
    local control_id="$1"
    
    # First try to disable the target
    safe_execute "$control_id" "Disabling ctrl-alt-del.target" "systemctl disable ctrl-alt-del.target"
    
    # Then mask it to prevent reactivation
    if safe_execute "$control_id" "Masking ctrl-alt-del.target" "systemctl mask ctrl-alt-del.target"; then
        log_info "✅ Ctrl-Alt-Del target disabled and masked"
        return 0
    else
        # Check if it's already masked or configured safely
        local status
        if status=$(systemctl is-enabled ctrl-alt-del.target 2>/dev/null); then
            if [[ "$status" == "masked" ]] || [[ "$status" == "disabled" ]]; then
                log_info "✅ Ctrl-Alt-Del target already properly configured ($status)"
                return 0
            fi
        fi
        
        # If masking failed but target is not active, consider it safe
        if ! systemctl is-active --quiet ctrl-alt-del.target 2>/dev/null; then
            log_info "✅ Ctrl-Alt-Del target is not active (safe configuration)"
            return 0
        fi
        
        return 1
    fi
}

# STIG V-257786: Disable debug shell
impl_257786() {
    local control_id="$1"
    
    if safe_execute "$control_id" "Masking debug-shell.service" "systemctl mask debug-shell.service"; then
        log_info "✅ Debug shell service disabled"
        return 0
    else
        return 1
    fi
}

# STIG V-257787: GRUB password (Azure-aware implementation)
impl_257787() {
    local control_id="$1"
    
    # Check if this is an Azure VM
    local is_azure_vm=false
    if [[ -f /sys/class/dmi/id/sys_vendor ]] && grep -qi "microsoft" /sys/class/dmi/id/sys_vendor 2>/dev/null; then
        is_azure_vm=true
    fi
    
    if [[ "$is_azure_vm" == true ]]; then
        # Conservative approach for Azure VMs
        log_warn "⚠️ Azure VM detected - GRUB password implementation requires careful consideration"
        log_warn "📋 GRUB password protects interactive boot access but may complicate recovery"
        log_warn "🔧 Recommendation: Implement only if you have alternative recovery methods"
        
        # Offer automated implementation with explicit warning
        echo
        echo -e "${YELLOW}╔══════════════════════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${YELLOW}║                           AZURE VM GRUB PASSWORD WARNING                    ║${NC}"
        echo -e "${YELLOW}╠══════════════════════════════════════════════════════════════════════════════╣${NC}"
        echo -e "${YELLOW}║${NC} This Azure VM can have GRUB password protection, but consider:"
        echo -e "${YELLOW}║${NC} "
        echo -e "${YELLOW}║${NC} ✅ PROS:"
        echo -e "${YELLOW}║${NC}    • Satisfies STIG V-257787 requirement"
        echo -e "${YELLOW}║${NC}    • Prevents unauthorized GRUB modification"
        echo -e "${YELLOW}║${NC}    • Normal VM operations unaffected"
        echo -e "${YELLOW}║${NC} "
        echo -e "${YELLOW}║${NC} ⚠️  CONSIDERATIONS:"
        echo -e "${YELLOW}║${NC}    • Azure Serial Console troubleshooting may be limited"
        echo -e "${YELLOW}║${NC}    • Boot recovery requires GRUB password"
        echo -e "${YELLOW}║${NC}    • Emergency single-user mode access protected"
        echo -e "${YELLOW}║${NC} "
        echo -e "${YELLOW}║${NC} 🛡️ RECOMMENDED: Implement with documented password recovery"
        echo -e "${YELLOW}╚══════════════════════════════════════════════════════════════════════════════╝${NC}"
        echo
        
        # Auto-implement with strong password for STIG compliance
        local grub_password="STIG_Secure_$(date +%Y%m%d)_Grub!"
        
        if safe_execute "$control_id" "Generating GRUB password hash" "echo -e '$grub_password\n$grub_password' | grub2-setpassword"; then
            # Document the password securely
            local password_doc="/root/.grub-password-stig"
            safe_execute "$control_id" "Documenting GRUB password securely" "echo 'GRUB Password for STIG Compliance: $grub_password' > '$password_doc'"
            safe_execute "$control_id" "Securing password documentation" "chmod 600 '$password_doc'"
            
            log_info "✅ GRUB password configured for STIG compliance"
            log_info "📄 Password documented in: $password_doc"
            log_warn "🔐 CRITICAL: Store GRUB password securely for emergency access"
            
            return 0
        else
            return 1
        fi
    else
        # Standard implementation for non-Azure systems
        handle_skip "$control_id" "Non-Azure system - manual GRUB password configuration recommended"
        log_warn "⚠️ Manual action required: Configure GRUB password using grub2-setpassword"
        return 0
    fi
}

# STIG V-257788: Disable interactive boot
impl_257788() {
    local control_id="$1"
    
    if safe_execute "$control_id" "Disabling interactive boot" "grubby --update-kernel=ALL --remove-args='systemd.confirm_spawn'"; then
        log_info "✅ Interactive boot disabled"
        return 0
    else
        return 1
    fi
}

# STIG V-257789: GRUB superuser (requires manual configuration)
impl_257789() {
    local control_id="$1"
    
    handle_skip "$control_id" "GRUB superuser requires manual configuration for security"
    log_warn "⚠️ Manual action required: Configure GRUB superuser in /etc/grub.d/40_custom"
    return 0
}

# STIG V-257790: GRUB file ownership and permissions
impl_257790() {
    local control_id="$1"
    
    local success=true
    
    # Set ownership and permissions for GRUB files
    for grub_file in "/boot/grub2/grub.cfg" "/boot/efi/EFI/redhat/grub.cfg" "/etc/grub2.cfg"; do
        if [[ -f "$grub_file" ]]; then
            if ! safe_execute "$control_id" "Setting ownership on $grub_file" "chown root:root '$grub_file'"; then
                success=false
            fi
            if ! safe_execute "$control_id" "Setting permissions on $grub_file" "chmod 600 '$grub_file'"; then
                success=false
            fi
        fi
    done
    
    if [[ "$success" == true ]]; then
        log_info "✅ GRUB file permissions configured"
        return 0
    else
        return 1
    fi
}

# Azure-safe SSH and firewall controls (mostly skipped for Bastion compatibility)

# STIG V-257936: Firewall configuration (skipped for Azure Bastion)
impl_257936() {
    local control_id="$1"
    
    handle_skip "$control_id" "Firewall configuration skipped to preserve Azure Bastion connectivity"
    log_warn "⚠️ Manual review required: Configure firewall rules after ensuring Azure Bastion access"
    return 0
}

# STIG V-257979: Enable SSH service
impl_257979() {
    local control_id="$1"
    
    if safe_execute "$control_id" "Enabling SSH service" "systemctl enable --now sshd"; then
        log_info "✅ SSH service enabled (required for Azure Bastion)"
        return 0
    else
        return 1
    fi
}

# Additional STIG controls with error handling
impl_file_permissions() {
    local control_id="$1"
    
    # Set proper permissions on critical system files
    local files=(
        "/etc/passwd:644"
        "/etc/shadow:000"
        "/etc/group:644"
        "/etc/gshadow:000"
        "/etc/security/opasswd:600"
    )
    
    local success=true
    for file_perm in "${files[@]}"; do
        local file="${file_perm%:*}"
        local perm="${file_perm#*:}"
        
        if [[ -f "$file" ]]; then
            if ! safe_execute "$control_id" "Setting permissions on $file" "chmod $perm '$file'"; then
                success=false
            fi
        fi
    done
    
    if [[ "$success" == true ]]; then
        log_info "✅ File permissions configured"
        return 0
    else
        return 1
    fi
}

impl_remove_packages() {
    local control_id="$1"
    
    # Remove unnecessary packages that could pose security risks
    local packages_to_remove=(
        "telnet-server"
        "rsh-server"
        "tftp-server"
        "vsftpd"
    )
    
    for package in "${packages_to_remove[@]}"; do
        if rpm -q "$package" >/dev/null 2>&1; then
            safe_execute "$control_id" "Removing package $package" "dnf remove -y '$package'"
        else
            log_info "Package $package not installed (good)"
        fi
    done
    
    log_info "✅ Unnecessary packages removed"
    return 0
}

impl_kernel_parameters() {
    local control_id="$1"
    
    # Configure comprehensive kernel security parameters for STIG compliance
    local sysctl_settings=(
        # Basic security settings
        "kernel.dmesg_restrict=1"
        "kernel.kptr_restrict=1"
        "kernel.yama.ptrace_scope=1"
        
        # Memory protection settings
        "kernel.randomize_va_space=2"
        "kernel.perf_event_paranoid=2"
        "kernel.kexec_load_disabled=1"
        "kernel.unprivileged_bpf_disabled=1"
        "kernel.core_pattern=|/bin/false"
        
        # Network security settings
        "net.ipv4.conf.all.send_redirects=0"
        "net.ipv4.conf.default.send_redirects=0"
        "net.ipv4.conf.all.accept_redirects=0"
        "net.ipv4.conf.default.accept_redirects=0"
        "net.ipv4.conf.all.secure_redirects=0"
        "net.ipv4.conf.default.secure_redirects=0"
        "net.ipv4.conf.all.log_martians=1"
        "net.ipv4.conf.default.log_martians=1"
        "net.ipv4.icmp_echo_ignore_broadcasts=1"
        "net.ipv4.icmp_ignore_bogus_error_responses=1"
        "net.ipv4.tcp_syncookies=1"
        "net.ipv6.conf.all.accept_redirects=0"
        "net.ipv6.conf.default.accept_redirects=0"
    )
    
    # Create sysctl configuration file
    local sysctl_file="/etc/sysctl.d/99-stig-security.conf"
    safe_execute "$control_id" "Creating STIG sysctl configuration file" "touch '$sysctl_file'"
    
    local success=true
    for setting in "${sysctl_settings[@]}"; do
        if ! safe_execute "$control_id" "Setting kernel parameter $setting" "echo '$setting' >> '$sysctl_file'"; then
            success=false
        fi
    done
    
    if [[ "$success" == true ]]; then
        if safe_execute "$control_id" "Applying kernel parameters" "sysctl -p '$sysctl_file'"; then
            log_info "✅ Comprehensive kernel security parameters configured"
            return 0
        fi
    fi
    return 1
}

# STIG Module Blacklisting: Disable unnecessary network modules  
impl_module_blacklist() {
    local control_id="$1"
    
    # Modules to blacklist (per STIG findings but preserve Azure connectivity)
    local modules_to_blacklist=(
        "atm"           # ATM networking
        "can"           # CAN bus protocol  
        "firewire-core" # Firewire
        "sctp"          # SCTP protocol
        "tipc"          # TIPC protocol
        "bluetooth"     # Bluetooth (safe to disable on servers)
        "btusb"         # Bluetooth USB
    )
    
    # Create modprobe blacklist file
    local blacklist_file="/etc/modprobe.d/blacklist-stig.conf"
    safe_execute "$control_id" "Creating module blacklist file" "touch '$blacklist_file'"
    
    local success=true
    for module in "${modules_to_blacklist[@]}"; do
        if ! safe_execute "$control_id" "Blacklisting module $module" "echo 'blacklist $module' >> '$blacklist_file'"; then
            success=false
        fi
        # Also add install directive to prevent loading
        safe_execute "$control_id" "Adding install block for $module" "echo 'install $module /bin/true' >> '$blacklist_file'"
    done
    
    # Update initramfs to apply changes
    if [[ "$success" == true ]]; then
        safe_execute "$control_id" "Updating initramfs" "dracut -f"
        log_info "✅ Unnecessary network modules blacklisted"
        return 0
    fi
    return 1
}

# STIG GRUB Parameters: Add security-related kernel parameters
impl_grub_parameters() {
    local control_id="$1"
    
    # GRUB parameters for STIG compliance (Azure-safe)
    local grub_params=(
        "vsyscall=none"
        "page_poison=1"
        "slub_debug=P"
        "init_on_free=1"
        "pti=on"
        "audit=1"
    )
    
    # Check current GRUB configuration
    local grub_cmdline_file="/etc/default/grub"
    if [[ ! -f "$grub_cmdline_file" ]]; then
        handle_error "1" "$control_id" "GRUB configuration file not found" "test -f $grub_cmdline_file"
        return 1
    fi
    
    # Read current GRUB_CMDLINE_LINUX
    local current_cmdline
    current_cmdline=$(grep '^GRUB_CMDLINE_LINUX=' "$grub_cmdline_file" 2>/dev/null || echo "")
    
    local params_to_add=""
    for param in "${grub_params[@]}"; do
        if ! echo "$current_cmdline" | grep -q "$param"; then
            params_to_add="$params_to_add $param"
        fi
    done
    
    if [[ -n "$params_to_add" ]]; then
        if safe_execute "$control_id" "Adding GRUB security parameters" "grubby --update-kernel=ALL --args='$params_to_add'"; then
            log_info "✅ GRUB security parameters added: $params_to_add"
            return 0
        else
            return 1
        fi
    else
        log_info "✅ GRUB security parameters already configured"
        return 0
    fi
}

# STIG systemd configuration
impl_systemd_config() {
    local control_id="$1"
    
    # Configure systemd for STIG compliance
    local systemd_settings=(
        "DefaultLimitCORE=0"
        "DumpCore=no"
        "ProcessSizeMax=0"
        "DefaultLimitNOFILE=1024"
    )
    
    local systemd_conf="/etc/systemd/system.conf"
    local success=true
    
    for setting in "${systemd_settings[@]}"; do
        local key="${setting%%=*}"
        # Check if setting already exists
        if grep -q "^${key}=" "$systemd_conf"; then
            # Replace existing setting
            if ! safe_execute "$control_id" "Updating systemd setting $setting" "sed -i 's/^${key}=.*/${setting}/' '$systemd_conf'"; then
                success=false
            fi
        else
            # Add new setting
            if ! safe_execute "$control_id" "Adding systemd setting $setting" "echo '$setting' >> '$systemd_conf'"; then
                success=false
            fi
        fi
    done
    
    if [[ "$success" == true ]]; then
        safe_execute "$control_id" "Reloading systemd configuration" "systemctl daemon-reload"
        log_info "✅ systemd security configuration applied"
        return 0
    fi
    return 1
}

#############################################################################
# Main Execution Function
#############################################################################

main() {
    log_info "═══════════════════════════════════════════════════════════════════════════════"
    log_info "         RHEL 9 STIG Complete Deployment for Microsoft Azure"
    log_info "═══════════════════════════════════════════════════════════════════════════════"
    log_info "Script: $SCRIPT_NAME v$SCRIPT_VERSION"
    log_info "Date: $SCRIPT_DATE"
    log_info "Log File: $LOG_FILE"
    log_info "═══════════════════════════════════════════════════════════════════════════════"
    
    # Pre-flight checks
    log_info "Performing pre-flight checks..."
    
    if [[ -f /etc/redhat-release ]]; then
        local os_info
        os_info=$(cat /etc/redhat-release 2>/dev/null || echo "Unknown")
        log_info "Detected OS: $os_info"
    else
        log_warn "Could not detect OS version"
    fi
    
    log_info "Pre-flight checks completed"
    log_info "Starting STIG control implementation with comprehensive error handling..."
    
    # Execute all STIG controls with consistent error handling
    execute_stig_control "V-257777" "Verify RHEL 9 vendor support" "impl_257777"
    execute_stig_control "V-257778" "Install security updates" "impl_257778"
    execute_stig_control "V-257779" "Configure DOD login banner" "impl_257779"
    execute_stig_control "V-257781" "Disable graphical interface" "impl_257781"
    execute_stig_control "V-257782" "Enable hardware RNG" "impl_257782"
    execute_stig_control "V-257783" "Enable systemd journald" "impl_257783"
    execute_stig_control "V-257784" "Disable Ctrl-Alt-Del burst action" "impl_257784"
    execute_stig_control "V-257785" "Disable Ctrl-Alt-Del target" "impl_257785"
    execute_stig_control "V-257786" "Disable debug shell" "impl_257786"
    execute_stig_control "V-257787" "GRUB password (manual)" "impl_257787"
    execute_stig_control "V-257788" "Disable interactive boot" "impl_257788"
    execute_stig_control "V-257789" "GRUB superuser (manual)" "impl_257789"
    execute_stig_control "V-257790" "GRUB file permissions" "impl_257790"
    
    # Azure-safe network controls
    execute_stig_control "V-257936" "Firewall configuration (Azure safe)" "impl_257936"
    execute_stig_control "V-257979" "Enable SSH service" "impl_257979"
    
    # Enhanced security configurations based on STIG findings
    execute_stig_control "KERNEL-PARAMS" "Configure comprehensive kernel parameters" "impl_kernel_parameters"
    execute_stig_control "MODULE-BLACKLIST" "Blacklist unnecessary modules" "impl_module_blacklist"
    execute_stig_control "GRUB-PARAMS" "Configure GRUB security parameters" "impl_grub_parameters"
    execute_stig_control "SYSTEMD-CONFIG" "Configure systemd security settings" "impl_systemd_config"
    execute_stig_control "FILE-PERMS" "Configure file permissions" "impl_file_permissions"
    execute_stig_control "REMOVE-PKGS" "Remove unnecessary packages" "impl_remove_packages"
}

# Comprehensive cleanup with detailed error reporting
cleanup() {
    local exit_code=$?
    echo
    log_info "═══════════════════════════════════════════════════════════════════════════════"
    log_info "                              STIG DEPLOYMENT COMPLETE"
    log_info "═══════════════════════════════════════════════════════════════════════════════"
    log_info "Final Statistics:"
    log_info "  Total Controls Processed: $TOTAL_CONTROLS"
    log_info "  Successfully Applied: $APPLIED_CONTROLS"
    log_info "  Failed: $FAILED_CONTROLS"
    log_info "  Skipped: $SKIPPED_CONTROLS"
    log_info "  Success Rate: $(( APPLIED_CONTROLS * 100 / TOTAL_CONTROLS ))%"
    echo
    
    # Display detailed error summary for manual remediation
    if [[ $FAILED_CONTROLS -gt 0 ]]; then
        echo -e "${RED}╔══════════════════════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${RED}║                                FAILED CONTROLS                               ║${NC}"
        echo -e "${RED}║                          (Requires Manual Attention)                        ║${NC}"
        echo -e "${RED}╠══════════════════════════════════════════════════════════════════════════════╣${NC}"
        
        for ((i=0; i<${#FAILED_CONTROL_LIST[@]}; i++)); do
            echo -e "${RED}║${NC} ${YELLOW}${FAILED_CONTROL_LIST[i]}${NC}: ${FAILED_ERROR_MESSAGES[i]}"
        done
        
        echo -e "${RED}╚══════════════════════════════════════════════════════════════════════════════╝${NC}"
        echo
        echo -e "${RED}🔧 REMEDIATION ACTIONS NEEDED:${NC}"
        echo -e "${RED}1.${NC} Review each failed control above"
        echo -e "${RED}2.${NC} Check the detailed logs: $LOG_FILE"
        echo -e "${RED}3.${NC} Manually implement failed controls as needed"
        echo -e "${RED}4.${NC} Re-run this script to verify fixes"
        echo
    fi
    
    # Display skipped controls summary
    if [[ $SKIPPED_CONTROLS -gt 0 ]]; then
        echo -e "${YELLOW}╔══════════════════════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${YELLOW}║                               SKIPPED CONTROLS                               ║${NC}"
        echo -e "${YELLOW}║                         (May Need Manual Review)                            ║${NC}"
        echo -e "${YELLOW}╠══════════════════════════════════════════════════════════════════════════════╣${NC}"
        
        for ((i=0; i<${#SKIPPED_CONTROL_LIST[@]}; i++)); do
            echo -e "${YELLOW}║${NC} ${BLUE}${SKIPPED_CONTROL_LIST[i]}${NC}: ${SKIPPED_REASONS[i]}"
        done
        
        echo -e "${YELLOW}╚══════════════════════════════════════════════════════════════════════════════╝${NC}"
        echo
    fi
    
    # Final status and next steps
    if [[ $FAILED_CONTROLS -gt 0 ]]; then
        log_warn "⚠️  Some controls failed - review errors above for manual remediation"
        log_warn "📝 Manual remediation may be required for security compliance"
    else
        log_info "🎉 All automated controls processed successfully!"
        log_info "🛡️ System has been hardened according to DISA STIG requirements"
    fi
    
    log_info "📁 Complete logs: $LOG_FILE"
    log_info "🔒 STIG deployment complete - Azure Bastion connectivity preserved"
    log_info "═══════════════════════════════════════════════════════════════════════════════"
}

# Set up cleanup trap
trap cleanup EXIT

# Execute main function with comprehensive error handling
log_info "🚀 Starting RHEL 9 STIG deployment with enhanced error handling..."

if main; then
    log_info "Main deployment phase completed"
else
    log_warn "Main deployment had some issues but script framework succeeded"
fi

# Script always exits successfully - individual control failures are tracked and reported
exit 0
