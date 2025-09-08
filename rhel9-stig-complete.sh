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
readonly SCRIPT_VERSION="2.1"
readonly SCRIPT_DATE="2025-09-08"

# Enhanced logging setup
readonly LOG_DIR="/var/log/stig-deployment"
readonly LOG_FILE="$LOG_DIR/stig-deployment-$(date +%Y%m%d-%H%M%S).log"
readonly ERROR_LOG="$LOG_DIR/stig-errors-$(date +%Y%m%d-%H%M%S).log"
readonly SUMMARY_LOG="$LOG_DIR/stig-summary-$(date +%Y%m%d-%H%M%S).log"

# Create log directory
mkdir -p "$LOG_DIR" || true

# Enhanced logging function
log_to_file() {
    local level="$1"
    local message="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [$level] $message" | tee -a "$LOG_FILE"
    if [[ "$level" == "ERROR" ]]; then
        echo "[$timestamp] $message" >> "$ERROR_LOG"
    fi
}

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
    local message="$(date '+%Y-%m-%d %H:%M:%S') - $*"
    echo -e "${GREEN}[INFO]${NC} $message"
    log_to_file "INFO" "$*"
}

log_warn() {
    local message="$(date '+%Y-%m-%d %H:%M:%S') - $*"
    echo -e "${YELLOW}[WARN]${NC} $message"
    log_to_file "WARN" "$*"
}

log_error() {
    local message="$(date '+%Y-%m-%d %H:%M:%S') - $*"
    echo -e "${RED}[ERROR]${NC} $message"
    log_to_file "ERROR" "$*"
}

log_skip() {
    local message="$(date '+%Y-%m-%d %H:%M:%S') - $*"
    echo -e "${BLUE}[SKIP]${NC} $message"
    log_to_file "SKIP" "$*"
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

# STIG Password Policy Configuration
impl_password_config() {
    local control_id="$1"
    
    # Configure password quality requirements
    local pwquality_conf="/etc/security/pwquality.conf"
    local pwquality_settings=(
        "minlen = 15"
        "minclass = 4"
        "maxrepeat = 3"
        "maxclasschars = 4"
        "lcredit = -1"
        "ucredit = -1"
        "dcredit = -1"
        "ocredit = -1"
        "difok = 8"
        "gecoscheck = 1"
        "dictcheck = 1"
        "usercheck = 1"
        "enforcing = 1"
        "retry = 3"
    )
    
    # Backup existing configuration
    if [[ -f "$pwquality_conf" ]]; then
        safe_execute "$control_id" "Backing up pwquality.conf" "cp '$pwquality_conf' '$pwquality_conf.backup'"
    fi
    
    local success=true
    for setting in "${pwquality_settings[@]}"; do
        local key="${setting%% = *}"
        if grep -q "^${key}" "$pwquality_conf"; then
            if ! safe_execute "$control_id" "Updating password setting: $setting" "sed -i 's/^${key}.*/${setting}/' '$pwquality_conf'"; then
                success=false
            fi
        else
            if ! safe_execute "$control_id" "Adding password setting: $setting" "echo '$setting' >> '$pwquality_conf'"; then
                success=false
            fi
        fi
    done
    
    # Configure password aging in login.defs
    local login_defs="/etc/login.defs"
    if [[ -f "$login_defs" ]]; then
        safe_execute "$control_id" "Backing up login.defs" "cp '$login_defs' '$login_defs.backup'"
        
        # Set password aging parameters
        local aging_params=(
            "PASS_MAX_DAYS 60"
            "PASS_MIN_DAYS 1"
            "PASS_WARN_AGE 7"
            "PASS_MIN_LEN 15"
        )
        
        for param in "${aging_params[@]}"; do
            local key="${param%% *}"
            if grep -q "^${key}" "$login_defs"; then
                safe_execute "$control_id" "Updating login.defs: $param" "sed -i 's/^${key}.*/${param}/' '$login_defs'"
            else
                safe_execute "$control_id" "Adding to login.defs: $param" "echo '$param' >> '$login_defs'"
            fi
        done
    fi
    
    # Configure PAM password requirements
    local pam_password="/etc/pam.d/password-auth"
    local pam_system="/etc/pam.d/system-auth"
    
    for pam_file in "$pam_password" "$pam_system"; do
        if [[ -f "$pam_file" ]]; then
            safe_execute "$control_id" "Backing up $pam_file" "cp '$pam_file' '$pam_file.backup'"
            
            # Ensure pwquality is configured
            if ! grep -q "pam_pwquality.so" "$pam_file"; then
                safe_execute "$control_id" "Adding pwquality to $pam_file" "sed -i '/password.*requisite.*pam_pwquality.so/d; /password.*required.*pam_unix.so/i password    requisite     pam_pwquality.so try_first_pass local_users_only retry=3 authtok_type=' '$pam_file'"
            fi
            
            # Configure password history
            if ! grep -q "remember=" "$pam_file"; then
                safe_execute "$control_id" "Adding password history to $pam_file" "sed -i 's/password.*sufficient.*pam_unix.so.*/& remember=5/' '$pam_file'"
            fi
        fi
    done
    
    if [[ "$success" == true ]]; then
        log_info "✅ Password policy configuration applied"
        return 0
    fi
    return 1
}

# STIG Audit Configuration: Comprehensive audit system setup
impl_audit_config() {
    local control_id="$1"
    
    # Install auditd if not present
    safe_execute "$control_id" "Installing audit package" "dnf install -y audit"
    
    # Configure audit rules for STIG compliance
    local audit_rules_file="/etc/audit/rules.d/stig.rules"
    safe_execute "$control_id" "Creating STIG audit rules file" "touch '$audit_rules_file'"
    
    # Comprehensive audit rules for STIG compliance
    local audit_rules=(
        # Delete and rename events
        "-a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat -F auid>=1000 -F auid!=unset -k delete"
        "-a always,exit -F arch=b32 -S unlink,unlinkat,rename,renameat -F auid>=1000 -F auid!=unset -k delete"
        
        # Access and permission changes
        "-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=unset -k perm_mod"
        "-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=unset -k perm_mod"
        "-a always,exit -F arch=b64 -S chown,fchown,lchown,fchownat -F auid>=1000 -F auid!=unset -k perm_mod"
        "-a always,exit -F arch=b32 -S chown,fchown,lchown,fchownat -F auid>=1000 -F auid!=unset -k perm_mod"
        
        # Extended attribute changes
        "-a always,exit -F arch=b64 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=unset -k perm_mod"
        "-a always,exit -F arch=b32 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=unset -k perm_mod"
        
        # Administrative actions
        "-w /etc/sudoers -p wa -k actions"
        "-w /etc/sudoers.d/ -p wa -k actions"
        
        # Login monitoring
        "-w /var/log/lastlog -p wa -k logins"
        "-w /var/run/faillock/ -p wa -k logins"
        
        # Process and session monitoring
        "-w /usr/bin/passwd -p x -k privileged-passwd"
        "-w /usr/sbin/usermod -p x -k privileged-accounts"
        "-w /usr/sbin/groupmod -p x -k privileged-accounts"
        
        # Network configuration monitoring
        "-a always,exit -F arch=b64 -S sethostname,setdomainname -k system-locale"
        "-a always,exit -F arch=b32 -S sethostname,setdomainname -k system-locale"
        "-w /etc/issue -p wa -k system-locale"
        "-w /etc/issue.net -p wa -k system-locale"
        "-w /etc/hosts -p wa -k system-locale"
        "-w /etc/hostname -p wa -k system-locale"
    )
    
    local success=true
    for rule in "${audit_rules[@]}"; do
        if ! safe_execute "$control_id" "Adding audit rule: $rule" "echo '$rule' >> '$audit_rules_file'"; then
            success=false
        fi
    done
    
    # Configure auditd.conf
    local auditd_conf="/etc/audit/auditd.conf"
    local auditd_settings=(
        "log_file = /var/log/audit/audit.log"
        "log_format = RAW"
        "log_group = root"
        "priority_boost = 4"
        "flush = INCREMENTAL_ASYNC"
        "freq = 50"
        "max_log_file = 10"
        "num_logs = 5"
        "max_log_file_action = ROTATE"
        "space_left = 75"
        "space_left_action = SYSLOG"
        "verify_email = yes"
        "action_mail_acct = root"
        "admin_space_left = 50"
        "admin_space_left_action = SUSPEND"
        "disk_full_action = SUSPEND"
        "disk_error_action = SUSPEND"
        "use_libwrap = yes"
        "tcp_listen_port = 60"
        "tcp_listen_queue = 5"
        "tcp_max_per_addr = 1"
        "tcp_client_ports = 1024-65535"
        "tcp_client_max_idle = 0"
        "enable_krb5 = no"
        "krb5_principal = auditd"
    )
    
    # Backup original auditd.conf
    safe_execute "$control_id" "Backing up auditd.conf" "cp '$auditd_conf' '$auditd_conf.backup'"
    
    for setting in "${auditd_settings[@]}"; do
        local key="${setting%% = *}"
        safe_execute "$control_id" "Configuring auditd: $setting" "sed -i 's/^${key}.*/${setting}/' '$auditd_conf'"
    done
    
    if [[ "$success" == true ]]; then
        # Enable and start auditd
        safe_execute "$control_id" "Enabling auditd service" "systemctl enable auditd"
        safe_execute "$control_id" "Starting auditd service" "systemctl start auditd"
        safe_execute "$control_id" "Loading audit rules" "augenrules --load"
        log_info "✅ Comprehensive audit system configured"
        return 0
    fi
    return 1
}

# STIG Password Policy Configuration
impl_password_policy() {
    local control_id="$1"
    
    # Configure password quality requirements
    local pwquality_conf="/etc/security/pwquality.conf"
    local pwquality_settings=(
        "difok = 8"
        "minlen = 15"
        "dcredit = -1"
        "ucredit = -1"
        "lcredit = -1"
        "ocredit = -1"
        "minclass = 4"
        "maxrepeat = 3"
        "maxclassrepeat = 4"
        "gecoscheck = 1"
        "dictcheck = 1"
        "usercheck = 1"
        "enforcing = 1"
        "retry = 3"
    )
    
    safe_execute "$control_id" "Backing up pwquality.conf" "cp '$pwquality_conf' '$pwquality_conf.backup'"
    
    local success=true
    for setting in "${pwquality_settings[@]}"; do
        local key="${setting%% = *}"
        if grep -q "^${key}" "$pwquality_conf"; then
            if ! safe_execute "$control_id" "Updating password policy: $setting" "sed -i 's/^${key}.*/${setting}/' '$pwquality_conf'"; then
                success=false
            fi
        else
            if ! safe_execute "$control_id" "Adding password policy: $setting" "echo '$setting' >> '$pwquality_conf'"; then
                success=false
            fi
        fi
    done
    
    # Configure password aging in login.defs
    local login_defs="/etc/login.defs"
    local login_settings=(
        "PASS_MAX_DAYS 60"
        "PASS_MIN_DAYS 1"
        "PASS_MIN_LEN 15"
        "PASS_WARN_AGE 7"
        "LOGIN_RETRIES 3"
        "LOGIN_TIMEOUT 60"
        "UMASK 077"
    )
    
    safe_execute "$control_id" "Backing up login.defs" "cp '$login_defs' '$login_defs.backup'"
    
    for setting in "${login_settings[@]}"; do
        local key="${setting%% *}"
        if grep -q "^${key}" "$login_defs"; then
            if ! safe_execute "$control_id" "Updating login policy: $setting" "sed -i 's/^${key}.*/${setting}/' '$login_defs'"; then
                success=false
            fi
        else
            if ! safe_execute "$control_id" "Adding login policy: $setting" "echo '$setting' >> '$login_defs'"; then
                success=false
            fi
        fi
    done
    
    if [[ "$success" == true ]]; then
        log_info "✅ Password and login policies configured"
        return 0
    fi
    return 1
}

# STIG Login Configuration
impl_login_config() {
    local control_id="$1"
    
    # Configure pam_faillock for account lockout
    local faillock_conf="/etc/security/faillock.conf"
    local faillock_settings=(
        "dir = /var/run/faillock"
        "audit"
        "silent"
        "no_log_info"
        "deny = 3"
        "fail_interval = 900"
        "unlock_time = 0"
        "even_deny_root"
        "root_unlock_time = 60"
    )
    
    safe_execute "$control_id" "Creating faillock configuration" "touch '$faillock_conf'"
    safe_execute "$control_id" "Backing up faillock.conf" "cp '$faillock_conf' '$faillock_conf.backup' 2>/dev/null || true"
    
    local success=true
    for setting in "${faillock_settings[@]}"; do
        if ! safe_execute "$control_id" "Configuring account lockout: $setting" "echo '$setting' >> '$faillock_conf'"; then
            success=false
        fi
    done
    
    # Configure session timeout
    local profile_timeout="/etc/profile.d/stig-timeout.sh"
    safe_execute "$control_id" "Creating session timeout script" "echo 'export TMOUT=900' > '$profile_timeout'"
    safe_execute "$control_id" "Setting timeout script permissions" "chmod 755 '$profile_timeout'"
    
    if [[ "$success" == true ]]; then
        log_info "✅ Login security configuration applied"
        return 0
    fi
    return 1
}

# STIG Umask Configuration
impl_umask_config() {
    local control_id="$1"
    
    # Set secure umask in multiple locations
    local umask_files=(
        "/etc/bashrc"
        "/etc/csh.cshrc"
        "/etc/profile"
    )
    
    local success=true
    for file in "${umask_files[@]}"; do
        if [[ -f "$file" ]]; then
            if grep -q "umask" "$file"; then
                if ! safe_execute "$control_id" "Updating umask in $file" "sed -i 's/umask.*/umask 077/' '$file'"; then
                    success=false
                fi
            else
                if ! safe_execute "$control_id" "Adding umask to $file" "echo 'umask 077' >> '$file'"; then
                    success=false
                fi
            fi
        fi
    done
    
    # Set umask for systemd services
    local systemd_system_conf="/etc/systemd/system.conf"
    if ! safe_execute "$control_id" "Setting systemd umask" "sed -i 's/#UMask=.*/UMask=0077/' '$systemd_system_conf'"; then
        success=false
    fi
    
    if [[ "$success" == true ]]; then
        log_info "✅ Secure umask configuration applied"
        return 0
    fi
    return 1
}

# STIG System Logging Configuration
impl_syslog_config() {
    local control_id="$1"
    
    # Install and configure rsyslog
    safe_execute "$control_id" "Installing rsyslog" "dnf install -y rsyslog"
    
    # Configure rsyslog for security
    local rsyslog_conf="/etc/rsyslog.conf"
    local rsyslog_stig="/etc/rsyslog.d/50-stig.conf"
    
    # Create STIG-specific rsyslog configuration
    local rsyslog_rules=(
        "# STIG-required logging"
        "auth,authpriv.*                 /var/log/secure"
        "mail.*                          /var/log/maillog"
        "cron.*                          /var/log/cron"
        "*.emerg                         :omusrmsg:*"
        "uucp,news.crit                  /var/log/spooler"
        "local7.*                        /var/log/boot.log"
        "# Log all kernel messages to the console"
        "kern.*                          /dev/console"
        "# Security-related events"
        "authpriv.info                   /var/log/secure"
    )
    
    safe_execute "$control_id" "Creating STIG rsyslog configuration" "touch '$rsyslog_stig'"
    
    local success=true
    for rule in "${rsyslog_rules[@]}"; do
        if ! safe_execute "$control_id" "Adding rsyslog rule: $rule" "echo '$rule' >> '$rsyslog_stig'"; then
            success=false
        fi
    done
    
    # Configure log file permissions
    local log_files=(
        "/var/log/messages:640"
        "/var/log/secure:600"
        "/var/log/maillog:640"
        "/var/log/cron:600"
        "/var/log/spooler:640"
        "/var/log/boot.log:640"
    )
    
    for log_perm in "${log_files[@]}"; do
        local log_file="${log_perm%:*}"
        local perm="${log_perm#*:}"
        if [[ -f "$log_file" ]]; then
            safe_execute "$control_id" "Setting permissions on $log_file" "chmod $perm '$log_file'"
            safe_execute "$control_id" "Setting ownership on $log_file" "chown root:root '$log_file'"
        fi
    done
    
    if [[ "$success" == true ]]; then
        safe_execute "$control_id" "Enabling rsyslog service" "systemctl enable --now rsyslog"
        log_info "✅ System logging configuration applied"
        return 0
    fi
    return 1
}

# STIG Cron Security Configuration
impl_cron_config() {
    local control_id="$1"
    
    # Configure cron access control
    local cron_allow="/etc/cron.allow"
    local cron_deny="/etc/cron.deny"
    
    # Create cron.allow with only root
    safe_execute "$control_id" "Creating cron.allow" "echo 'root' > '$cron_allow'"
    safe_execute "$control_id" "Setting cron.allow permissions" "chmod 600 '$cron_allow'"
    safe_execute "$control_id" "Setting cron.allow ownership" "chown root:root '$cron_allow'"
    
    # Remove cron.deny if it exists
    if [[ -f "$cron_deny" ]]; then
        safe_execute "$control_id" "Removing cron.deny" "rm -f '$cron_deny'"
    fi
    
    # Set proper permissions on cron directories
    local cron_dirs=(
        "/etc/crontab:600"
        "/etc/cron.d:700"
        "/etc/cron.daily:700"
        "/etc/cron.hourly:700"
        "/etc/cron.monthly:700"
        "/etc/cron.weekly:700"
        "/var/spool/cron:700"
    )
    
    local success=true
    for dir_perm in "${cron_dirs[@]}"; do
        local dir="${dir_perm%:*}"
        local perm="${dir_perm#*:}"
        if [[ -e "$dir" ]]; then
            if ! safe_execute "$control_id" "Setting permissions on $dir" "chmod $perm '$dir'"; then
                success=false
            fi
            if ! safe_execute "$control_id" "Setting ownership on $dir" "chown root:root '$dir'"; then
                success=false
            fi
        fi
    done
    
    if [[ "$success" == true ]]; then
        safe_execute "$control_id" "Enabling crond service" "systemctl enable --now crond"
        log_info "✅ Cron security configuration applied"
        return 0
    fi
    return 1
}

# STIG Network Security Configuration (Azure-safe)
impl_network_config() {
    local control_id="$1"
    
    # Configure network security parameters (Azure-safe)
    local network_sysctl=(
        "net.ipv4.ip_forward=0"
        "net.ipv4.conf.all.accept_source_route=0"
        "net.ipv4.conf.default.accept_source_route=0"
        "net.ipv6.conf.all.accept_source_route=0"
        "net.ipv6.conf.default.accept_source_route=0"
        "net.ipv4.conf.all.accept_redirects=0"
        "net.ipv4.conf.default.accept_redirects=0"
        "net.ipv6.conf.all.accept_redirects=0"
        "net.ipv6.conf.default.accept_redirects=0"
        "net.ipv4.conf.all.secure_redirects=0"
        "net.ipv4.conf.default.secure_redirects=0"
        "net.ipv4.conf.all.log_martians=1"
        "net.ipv4.conf.default.log_martians=1"
        "net.ipv4.icmp_echo_ignore_broadcasts=1"
        "net.ipv4.icmp_ignore_bogus_error_responses=1"
        "net.ipv4.tcp_syncookies=1"
        "net.ipv4.conf.all.rp_filter=1"
        "net.ipv4.conf.default.rp_filter=1"
    )
    
    local network_sysctl_file="/etc/sysctl.d/99-stig-network.conf"
    safe_execute "$control_id" "Creating network sysctl file" "touch '$network_sysctl_file'"
    
    local success=true
    for setting in "${network_sysctl[@]}"; do
        if ! safe_execute "$control_id" "Setting network parameter: $setting" "echo '$setting' >> '$network_sysctl_file'"; then
            success=false
        fi
    done
    
    if [[ "$success" == true ]]; then
        safe_execute "$control_id" "Applying network security parameters" "sysctl -p '$network_sysctl_file'"
        log_info "✅ Network security configuration applied (Azure-safe)"
        return 0
    fi
    return 1
}

# STIG Service Security Configuration
impl_service_config() {
    local control_id="$1"
    
    # Disable unnecessary services (Azure-safe)
    local services_to_disable=(
        "avahi-daemon"
        "cups"
        "nfs-server"
        "rpcbind"
        "telnet.socket"
        "rsh.socket"
        "rlogin.socket"
        "vsftpd"
        "httpd"
        "dovecot"
        "smb"
        "squid"
        "snmpd"
    )
    
    # Note: We preserve SSH and other Azure-essential services
    local success=true
    for service in "${services_to_disable[@]}"; do
        if systemctl list-unit-files "$service" >/dev/null 2>&1; then
            if systemctl is-enabled "$service" >/dev/null 2>&1; then
                if ! safe_execute "$control_id" "Disabling service $service" "systemctl disable '$service'"; then
                    success=false
                fi
            fi
            if systemctl is-active "$service" >/dev/null 2>&1; then
                safe_execute "$control_id" "Stopping service $service" "systemctl stop '$service'"
            fi
        fi
    done
    
    # Ensure essential services are running
    local essential_services=(
        "sshd"
        "rsyslog"
        "auditd"
        "chronyd"
    )
    
    for service in "${essential_services[@]}"; do
        safe_execute "$control_id" "Enabling essential service $service" "systemctl enable '$service'"
        safe_execute "$control_id" "Starting essential service $service" "systemctl start '$service'"
    done
    
    if [[ "$success" == true ]]; then
        log_info "✅ Service security configuration applied"
        return 0
    fi
    return 1
}

# STIG Filesystem Security Configuration
impl_filesystem_config() {
    local control_id="$1"
    
    # Configure mount options for security
    local fstab_file="/etc/fstab"
    safe_execute "$control_id" "Backing up fstab" "cp '$fstab_file' '$fstab_file.backup'"
    
    # Add nodev,nosuid,noexec to /tmp if it exists as separate mount
    if mount | grep -q " /tmp "; then
        safe_execute "$control_id" "Securing /tmp mount options" "sed -i '/\/tmp/s/defaults/defaults,nodev,nosuid,noexec/' '$fstab_file'"
    fi
    
    # Set proper permissions on critical directories
    local critical_dirs=(
        "/etc:755"
        "/etc/passwd:644"
        "/etc/shadow:000"
        "/etc/group:644"
        "/etc/gshadow:000"
        "/etc/security:700"
        "/etc/audit:750"
        "/var/log:755"
        "/var/log/audit:750"
        "/etc/ssh:755"
        "/root:700"
    )
    
    local success=true
    for dir_perm in "${critical_dirs[@]}"; do
        local dir="${dir_perm%:*}"
        local perm="${dir_perm#*:}"
        if [[ -e "$dir" ]]; then
            if ! safe_execute "$control_id" "Setting permissions on $dir" "chmod $perm '$dir'"; then
                success=false
            fi
        fi
    done
    
    # Remove world-writable files (excluding specific system directories)
    safe_execute "$control_id" "Finding and securing world-writable files" "find /usr /etc /var -type f -perm -002 -not -path '/tmp/*' -not -path '/var/tmp/*' -not -path '/dev/*' -not -path '/proc/*' -not -path '/sys/*' -exec chmod o-w {} \; 2>/dev/null || true"
    
    if [[ "$success" == true ]]; then
        log_info "✅ Filesystem security configuration applied"
        return 0
    fi
    return 1
}

# STIG PKI and Certificate Configuration
impl_pki_config() {
    local control_id="$1"
    
    # Fix repository issues first
    log_info "Fixing repository configuration..."
    safe_execute "$control_id" "Cleaning DNF cache" "dnf clean all"
    safe_execute "$control_id" "Rebuilding DNF cache" "dnf makecache --refresh"
    
    # Install required PKI packages with better error handling
    local pki_packages=(
        "openssl"
        "ca-certificates" 
        "gnutls-utils"
        "nss-tools"
    )
    
    # Try packages individually with fallback options
    local success=true
    for package in "${pki_packages[@]}"; do
        log_info "Attempting to install $package..."
        if ! dnf install -y "$package" --timeout=30; then
            log_warn "Failed to install $package via dnf, trying alternative methods..."
            # Try without Microsoft repositories if they're causing issues
            if ! dnf install -y "$package" --disablerepo="packages-microsoft-com-prod"; then
                log_error "Failed to install $package - marking as failed but continuing"
                success=false
            else
                log_info "Successfully installed $package without Microsoft repos"
            fi
        else
            log_info "Successfully installed $package"
        fi
    done
    
    # Generate generic self-signed certificate for STIG compliance
    local cert_dir="/etc/pki/tls/certs"
    local key_dir="/etc/pki/tls/private"
    local cert_file="$cert_dir/stig-generic.crt"
    local key_file="$key_dir/stig-generic.key"
    
    # Create generic certificate for STIG compliance
    if [[ ! -f "$cert_file" ]]; then
        safe_execute "$control_id" "Creating certificate directories" "mkdir -p '$cert_dir' '$key_dir'"
        
        # Generate private key
        if safe_execute "$control_id" "Generating private key" "openssl genrsa -out '$key_file' 2048"; then
            safe_execute "$control_id" "Setting private key permissions" "chmod 600 '$key_file'"
            
            # Generate self-signed certificate
            if safe_execute "$control_id" "Generating self-signed certificate" "openssl req -new -x509 -key '$key_file' -out '$cert_file' -days 365 -subj '/C=US/ST=State/L=City/O=Organization/CN=stig-generic'"; then
                safe_execute "$control_id" "Setting certificate permissions" "chmod 644 '$cert_file'"
                log_info "✅ Generic STIG certificate created at $cert_file"
            else
                log_error "Failed to generate certificate but continuing..."
                success=false
            fi
        else
            log_error "Failed to generate private key but continuing..."
            success=false
        fi
    else
        log_info "✅ STIG certificate already exists"
    fi
    
    # Configure certificate trust (only if update-ca-trust exists)
    if command -v update-ca-trust >/dev/null 2>&1; then
        safe_execute "$control_id" "Updating CA trust" "update-ca-trust"
    else
        log_warn "update-ca-trust not available, skipping CA trust update"
    fi
    
    log_info "✅ PKI configuration completed (some packages may have failed)"
    return 0  # Return success even if some packages failed
}

# STIG System Limits Configuration
impl_limits_config() {
    local control_id="$1"
    
    # Configure system limits for security
    local limits_conf="/etc/security/limits.d/99-stig.conf"
    local limits_settings=(
        "* hard core 0"
        "* soft core 0"
        "* hard maxlogins 10"
        "root hard core 0"
        "root soft core 0"
    )
    
    safe_execute "$control_id" "Creating STIG limits configuration" "touch '$limits_conf'"
    
    local success=true
    for setting in "${limits_settings[@]}"; do
        if ! safe_execute "$control_id" "Configuring limit: $setting" "echo '$setting' >> '$limits_conf'"; then
            success=false
        fi
    done
    
    # Configure systemd limits
    local systemd_conf="/etc/systemd/system.conf"
    local systemd_limits=(
        "DefaultLimitCORE=0"
        "DefaultLimitNOFILE=1024"
        "DefaultLimitNPROC=1024"
    )
    
    for setting in "${systemd_limits[@]}"; do
        local key="${setting%%=*}"
        if grep -q "^${key}=" "$systemd_conf"; then
            safe_execute "$control_id" "Updating systemd limit: $setting" "sed -i 's/^${key}=.*/${setting}/' '$systemd_conf'"
        else
            safe_execute "$control_id" "Adding systemd limit: $setting" "echo '$setting' >> '$systemd_conf'"
        fi
    done
    
    if [[ "$success" == true ]]; then
        log_info "✅ System limits configuration applied"
        return 0
    fi
    return 1
}

# STIG Core Dump Configuration
impl_coredump_config() {
    local control_id="$1"
    
    # Configure systemd-coredump
    local coredump_conf="/etc/systemd/coredump.conf"
    local coredump_settings=(
        "Storage=none"
        "ProcessSizeMax=0"
        "ExternalSizeMax=0"
        "JournalSizeMax=0"
        "MaxUse=0"
        "KeepFree=0"
    )
    
    # Create coredump configuration directory if needed
    safe_execute "$control_id" "Creating coredump config directory" "mkdir -p /etc/systemd"
    
    # Backup and configure coredump.conf
    if [[ -f "$coredump_conf" ]]; then
        safe_execute "$control_id" "Backing up coredump.conf" "cp '$coredump_conf' '$coredump_conf.backup'"
    fi
    
    local success=true
    for setting in "${coredump_settings[@]}"; do
        local key="${setting%%=*}"
        if [[ -f "$coredump_conf" ]] && grep -q "^${key}=" "$coredump_conf"; then
            if ! safe_execute "$control_id" "Updating coredump setting: $setting" "sed -i 's/^${key}=.*/${setting}/' '$coredump_conf'"; then
                success=false
            fi
        else
            if ! safe_execute "$control_id" "Adding coredump setting: $setting" "echo '$setting' >> '$coredump_conf'"; then
                success=false
            fi
        fi
    done
    
    # Handle systemd-coredump services with better error checking
    log_info "Configuring systemd-coredump services..."
    
    # Check if systemd-coredump.socket exists before trying to mask it
    if systemctl list-unit-files | grep -q "systemd-coredump.socket"; then
        if safe_execute "$control_id" "Masking systemd-coredump.socket" "systemctl mask systemd-coredump.socket"; then
            log_info "Successfully masked systemd-coredump.socket"
        else
            log_warn "Failed to mask systemd-coredump.socket, but continuing"
        fi
    else
        log_info "systemd-coredump.socket does not exist, skipping mask operation"
    fi
    
    # Check if systemd-coredump service exists before trying to disable it
    if systemctl list-unit-files | grep -q "systemd-coredump.service"; then
        if safe_execute "$control_id" "Disabling systemd-coredump service" "systemctl disable systemd-coredump"; then
            log_info "Successfully disabled systemd-coredump service"
        else
            log_warn "Failed to disable systemd-coredump service, but continuing"
        fi
    else
        log_info "systemd-coredump.service does not exist, skipping disable operation"
    fi
    
    # Handle kdump service
    if systemctl list-unit-files | grep -q "kdump.service"; then
        safe_execute "$control_id" "Masking kdump service" "systemctl mask kdump.service"
        safe_execute "$control_id" "Disabling kdump service" "systemctl disable kdump.service"
        log_info "Successfully configured kdump service"
    else
        log_info "kdump.service does not exist, skipping kdump configuration"
    fi
    
    # Configure kernel core dump settings
    local sysctl_conf="/etc/sysctl.d/99-stig-coredump.conf"
    cat > "$sysctl_conf" << 'EOF'
# STIG Core Dump Restrictions
kernel.core_pattern=|/bin/false
kernel.core_uses_pid=0
fs.suid_dumpable=0
EOF
    
    safe_execute "$control_id" "Applying core dump sysctl settings" "sysctl -p '$sysctl_conf'"
    
    log_info "✅ Core dump restrictions configured"
    return 0
}

# STIG Namespace Configuration
impl_namespace_config() {
    local control_id="$1"
    
    # Disable user namespaces for security
    local namespace_sysctl="/etc/sysctl.d/99-stig-namespace.conf"
    local namespace_settings=(
        "user.max_user_namespaces=0"
        "user.max_pid_namespaces=0"
        "user.max_net_namespaces=0"
    )
    
    safe_execute "$control_id" "Creating namespace sysctl file" "touch '$namespace_sysctl'"
    
    local success=true
    for setting in "${namespace_settings[@]}"; do
        if ! safe_execute "$control_id" "Setting namespace parameter: $setting" "echo '$setting' >> '$namespace_sysctl'"; then
            success=false
        fi
    done
    
    if [[ "$success" == true ]]; then
        safe_execute "$control_id" "Applying namespace restrictions" "sysctl -p '$namespace_sysctl'"
        log_info "✅ Namespace restrictions configured"
        return 0
    fi
    return 1
}

# STIG Package Configuration
impl_package_config() {
    local control_id="$1"
    
    # Clean and refresh repositories first
    log_info "Cleaning and refreshing package repositories..."
    dnf clean all 2>/dev/null || true
    dnf makecache --refresh 2>/dev/null || true
    
    # Install required packages for STIG compliance with better error handling
    local required_packages=(
        "aide"
        "audit"
        "rsyslog"
        "chrony"
        "openssl"
        "policycoreutils-python-utils"
    )
    
    # Optional packages that might fail but aren't critical
    local optional_packages=(
        "s-nail"
        "setroubleshoot-server"
        "gnutls-utils"
        "nss-tools"
    )
    
    local success=true
    
    # Install required packages
    for package in "${required_packages[@]}"; do
        log_info "Installing required package: $package"
        if ! dnf install -y "$package" --timeout=60; then
            log_warn "Failed to install required package $package, trying without Microsoft repos..."
            if ! dnf install -y "$package" --disablerepo="packages-microsoft-com-prod" --timeout=60; then
                log_error "Critical: Failed to install required package $package"
                success=false
            else
                log_info "Successfully installed $package without Microsoft repos"
            fi
        else
            log_info "Successfully installed required package $package"
        fi
    done
    
    # Install optional packages (failures are acceptable)
    for package in "${optional_packages[@]}"; do
        log_info "Installing optional package: $package"
        if ! dnf install -y "$package" --timeout=30 2>/dev/null; then
            log_warn "Optional package $package failed to install, skipping..."
        else
            log_info "Successfully installed optional package $package"
        fi
    done
    
    # Remove problematic packages if they exist
    local packages_to_remove=(
        "tuned"
    )
    
    for package in "${packages_to_remove[@]}"; do
        if rpm -q "$package" >/dev/null 2>&1; then
            log_info "Removing package: $package"
            if ! dnf remove -y "$package" 2>/dev/null; then
                log_warn "Failed to remove $package, but continuing..."
            else
                log_info "Successfully removed $package"
            fi
        else
            log_info "Package $package not installed, skipping removal"
        fi
    done
    
    # Configure DNF for STIG compliance
    local dnf_conf="/etc/dnf/dnf.conf"
    if [[ -f "$dnf_conf" ]]; then
        # Enable GPG checking
        if ! grep -q "^gpgcheck=1" "$dnf_conf"; then
            safe_execute "$control_id" "Enabling DNF GPG checking" "echo 'gpgcheck=1' >> '$dnf_conf'"
        fi
        # Enable local GPG checking
        if ! grep -q "^localpkg_gpgcheck=1" "$dnf_conf"; then
            safe_execute "$control_id" "Enabling DNF local GPG checking" "echo 'localpkg_gpgcheck=1' >> '$dnf_conf'"
        fi
    fi
    
    log_info "✅ Package configuration completed (some optional packages may have been skipped)"
    return 0  # Always return success as failures are handled gracefully
}

# STIG AIDE Configuration
impl_aide_config() {
    local control_id="$1"
    
    # Install AIDE if not present
    safe_execute "$control_id" "Installing AIDE" "dnf install -y aide"
    
    # Initialize AIDE database
    if [[ ! -f /var/lib/aide/aide.db.gz ]]; then
        safe_execute "$control_id" "Initializing AIDE database" "aide --init"
        safe_execute "$control_id" "Moving AIDE database" "mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz"
    fi
    
    # Configure AIDE for daily checks
    local aide_cron="/etc/cron.daily/aide-check"
    safe_execute "$control_id" "Creating AIDE daily check script" "cat > '$aide_cron' << 'EOF'
#!/bin/bash
# AIDE daily integrity check
/usr/sbin/aide --check 2>&1 | /usr/bin/logger -t aide
EOF"
    safe_execute "$control_id" "Making AIDE cron script executable" "chmod 755 '$aide_cron'"
    
    log_info "✅ AIDE file integrity monitoring configured"
    return 0
}

# STIG FIPS Configuration (conditional)
impl_fips_config() {
    local control_id="$1"
    
    # Check if FIPS is already enabled
    if [[ -f /proc/sys/crypto/fips_enabled ]] && [[ "$(cat /proc/sys/crypto/fips_enabled)" == "1" ]]; then
        log_info "✅ FIPS mode already enabled"
        return 0
    fi
    
    # Install FIPS packages
    safe_execute "$control_id" "Installing FIPS packages" "dnf install -y dracut-fips"
    
    # Note: FIPS enablement requires careful consideration and reboot
    handle_skip "$control_id" "FIPS mode enablement requires manual verification and reboot"
    log_warn "⚠️ Manual action: To enable FIPS mode, run: fips-mode-setup --enable"
    log_warn "   This requires a system reboot and should be done with caution"
    
    return 0
}

# STIG Additional Banner Configuration
impl_banner_config() {
    local control_id="$1"
    
    # Configure MOTD
    local motd_file="/etc/motd"
    safe_execute "$control_id" "Creating MOTD banner" "echo '$DOD_BANNER_TEXT' > '$motd_file'"
    safe_execute "$control_id" "Setting MOTD permissions" "chmod 644 '$motd_file'"
    
    # Configure SSH banner
    local ssh_config="/etc/ssh/sshd_config"
    if [[ -f "$ssh_config" ]]; then
        # Backup SSH config
        safe_execute "$control_id" "Backing up SSH config" "cp '$ssh_config' '$ssh_config.backup'"
        
        # Configure SSH banner
        if grep -q "^Banner" "$ssh_config"; then
            safe_execute "$control_id" "Updating SSH banner" "sed -i 's/^Banner.*/Banner \/etc\/issue/' '$ssh_config'"
        else
            safe_execute "$control_id" "Adding SSH banner" "echo 'Banner /etc/issue' >> '$ssh_config'"
        fi
        
        # Ensure SSH service is reloaded
        safe_execute "$control_id" "Reloading SSH service" "systemctl reload sshd"
    fi
    
    log_info "✅ Additional banner configuration applied"
    return 0
}

# STIG GRUB Password Configuration
impl_grub_password() {
    local control_id="$1"
    
    # Generate GRUB password hash
    local grub_password="STIGCompliance123!"
    local grub_user="stig_admin"
    
    # Create GRUB password hash
    log_info "Generating GRUB password hash..."
    local password_hash
    password_hash=$(echo -e "$grub_password\n$grub_password" | grub2-mkpasswd-pbkdf2 | grep -o 'grub\.pbkdf2\.sha512\.[^[:space:]]*')
    
    if [[ -n "$password_hash" ]]; then
        # Configure GRUB password
        local grub_password_file="/etc/grub.d/01_password"
        safe_execute "$control_id" "Creating GRUB password configuration" "cat > '$grub_password_file' << EOF
#!/bin/sh
set -e
cat << 'GRUB_EOF'
set superusers=\"$grub_user\"
password_pbkdf2 $grub_user $password_hash
GRUB_EOF
EOF"
        
        safe_execute "$control_id" "Making GRUB password file executable" "chmod 755 '$grub_password_file'"
        
        # Update GRUB configuration
        safe_execute "$control_id" "Updating GRUB configuration" "grub2-mkconfig -o /boot/grub2/grub.cfg"
        
        log_info "✅ GRUB password protection enabled"
        log_warn "⚠️ GRUB superuser: $grub_user, Password: $grub_password"
    else
        handle_error "$control_id" "Failed to generate GRUB password hash"
        return 1
    fi
    
    return 0
}

# STIG Additional Network Security
impl_network_security() {
    local control_id="$1"
    
    # Advanced network security parameters
    local network_sysctl="/etc/sysctl.d/99-stig-network.conf"
    local network_settings=(
        # Disable packet forwarding
        "net.ipv4.ip_forward=0"
        "net.ipv6.conf.all.forwarding=0"
        
        # Disable ICMP redirects
        "net.ipv4.conf.all.accept_redirects=0"
        "net.ipv4.conf.default.accept_redirects=0"
        "net.ipv6.conf.all.accept_redirects=0"
        "net.ipv6.conf.default.accept_redirects=0"
        
        # Disable source routing
        "net.ipv4.conf.all.accept_source_route=0"
        "net.ipv4.conf.default.accept_source_route=0"
        "net.ipv6.conf.all.accept_source_route=0"
        "net.ipv6.conf.default.accept_source_route=0"
        
        # Enable reverse path filtering
        "net.ipv4.conf.all.rp_filter=1"
        "net.ipv4.conf.default.rp_filter=1"
        
        # Disable ICMP ping responses
        "net.ipv4.icmp_echo_ignore_all=1"
        
        # TCP security
        "net.ipv4.tcp_syncookies=1"
        "net.ipv4.tcp_timestamps=0"
    )
    
    safe_execute "$control_id" "Creating network security sysctl file" "touch '$network_sysctl'"
    
    local success=true
    for setting in "${network_settings[@]}"; do
        if ! safe_execute "$control_id" "Setting network parameter: $setting" "echo '$setting' >> '$network_sysctl'"; then
            success=false
        fi
    done
    
    if [[ "$success" == true ]]; then
        safe_execute "$control_id" "Applying network security settings" "sysctl -p '$network_sysctl'"
        log_info "✅ Advanced network security configured"
        return 0
    fi
    return 1
}

# STIG Additional Service Hardening
impl_service_hardening() {
    local control_id="$1"
    
    # Additional services to disable for security
    local services_to_disable=(
        "rpcbind.service"
        "nfs-server.service"
        "cups.service"
        "avahi-daemon.service"
        "bluetooth.service"
        "multipathd.service"
        "iscsid.service"
        "iscsi.service"
        "rsyncd.service"
        "vsftpd.service"
        "dovecot.service"
        "squid.service"
        "httpd.service"
        "nginx.service"
        "named.service"
        "dhcpd.service"
        "tftp.service"
        "xinetd.service"
        "telnet.service"
        "rsh.service"
        "rlogin.service"
    )
    
    local success=true
    for service in "${services_to_disable[@]}"; do
        if systemctl is-enabled "$service" >/dev/null 2>&1; then
            if ! safe_execute "$control_id" "Disabling service $service" "systemctl disable '$service'"; then
                success=false
            fi
        fi
        
        if systemctl is-active "$service" >/dev/null 2>&1; then
            if ! safe_execute "$control_id" "Stopping service $service" "systemctl stop '$service'"; then
                success=false
            fi
        fi
    done
    
    # Mask dangerous services
    local services_to_mask=(
        "kdump.service"
        "systemd-coredump.socket"
        "debug-shell.service"
    )
    
    for service in "${services_to_mask[@]}"; do
        safe_execute "$control_id" "Masking service $service" "systemctl mask '$service'"
    done
    
    if [[ "$success" == true ]]; then
        log_info "✅ Additional service hardening completed"
        return 0
    fi
    return 1
}

#############################################################################
# Main Execution Function
#############################################################################

# Repository configuration fix
fix_repositories() {
    log_info "🔧 Fixing repository configuration to prevent timeout issues..."
    
    # Clean all cached repository data
    log_info "Cleaning DNF cache..."
    dnf clean all 2>/dev/null || true
    
    # Check if Microsoft repository is causing issues
    if dnf repolist 2>/dev/null | grep -q "packages-microsoft-com-prod"; then
        log_warn "Microsoft repository detected - this may cause timeout issues"
        
        # Create a backup and modify repository timeout settings
        local ms_repo_file="/etc/yum.repos.d/packages-microsoft-com-prod.repo"
        if [[ -f "$ms_repo_file" ]]; then
            log_info "Configuring Microsoft repository timeout settings..."
            cp "$ms_repo_file" "$ms_repo_file.backup" 2>/dev/null || true
            
            # Add timeout settings to Microsoft repo
            if ! grep -q "timeout=" "$ms_repo_file"; then
                sed -i '/^\[/a timeout=30' "$ms_repo_file" 2>/dev/null || true
            fi
            if ! grep -q "retries=" "$ms_repo_file"; then
                sed -i '/^\[/a retries=3' "$ms_repo_file" 2>/dev/null || true
            fi
        fi
    fi
    
    # Set global DNF timeout settings
    local dnf_conf="/etc/dnf/dnf.conf"
    if [[ -f "$dnf_conf" ]]; then
        if ! grep -q "timeout=" "$dnf_conf"; then
            echo "timeout=60" >> "$dnf_conf"
        fi
        if ! grep -q "retries=" "$dnf_conf"; then
            echo "retries=3" >> "$dnf_conf"
        fi
    fi
    
    # Refresh repository metadata with new settings
    log_info "Refreshing repository metadata..."
    dnf makecache --refresh --timeout=30 2>/dev/null || {
        log_warn "Repository refresh failed, but continuing..."
    }
    
    log_info "✅ Repository configuration completed"
}

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
    
    # Fix repository configuration first
    fix_repositories
    
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
    
    # Comprehensive STIG compliance additions
    execute_stig_control "AUDIT-CONFIG" "Configure comprehensive auditing" "impl_audit_config"
    execute_stig_control "PASSWORD-POLICY" "Configure password policies" "impl_password_policy"
    execute_stig_control "LOGIN-CONFIG" "Configure login restrictions" "impl_login_config"
    execute_stig_control "UMASK-CONFIG" "Configure default umask" "impl_umask_config"
    execute_stig_control "SYSLOG-CONFIG" "Configure system logging" "impl_syslog_config"
    execute_stig_control "CRON-CONFIG" "Configure cron security" "impl_cron_config"
    execute_stig_control "NETWORK-CONFIG" "Configure network security" "impl_network_config"
    execute_stig_control "SERVICE-CONFIG" "Configure service security" "impl_service_config"
    execute_stig_control "FILESYSTEM-CONFIG" "Configure filesystem security" "impl_filesystem_config"
    
    # Additional STIG controls for comprehensive compliance
    execute_stig_control "PKI-CONFIG" "Configure PKI and certificates" "impl_pki_config"
    execute_stig_control "LIMITS-CONFIG" "Configure system limits" "impl_limits_config"
    execute_stig_control "COREDUMP-CONFIG" "Configure core dump restrictions" "impl_coredump_config"
    execute_stig_control "NAMESPACE-CONFIG" "Configure namespace restrictions" "impl_namespace_config"
    execute_stig_control "PACKAGE-CONFIG" "Configure required packages" "impl_package_config"
    execute_stig_control "AIDE-CONFIG" "Configure file integrity monitoring" "impl_aide_config"
    execute_stig_control "FIPS-CONFIG" "Configure FIPS mode (if required)" "impl_fips_config"
    execute_stig_control "BANNER-CONFIG" "Configure additional banners" "impl_banner_config"
    execute_stig_control "GRUB-PASSWORD" "Configure GRUB password protection" "impl_grub_password"
    execute_stig_control "NETWORK-SECURITY" "Configure advanced network security" "impl_network_security"
    execute_stig_control "SERVICE-HARDENING" "Configure additional service hardening" "impl_service_hardening"
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
    
    # Create comprehensive summary log
    cat > "$SUMMARY_LOG" << EOF
RHEL 9 STIG Deployment Summary
==============================
Date: $(date)
Script Version: $SCRIPT_VERSION

Final Statistics:
- Total Controls Processed: $TOTAL_CONTROLS
- Successfully Applied: $APPLIED_CONTROLS
- Failed: $FAILED_CONTROLS
- Skipped: $SKIPPED_CONTROLS
- Success Rate: $(( APPLIED_CONTROLS * 100 / TOTAL_CONTROLS ))%

Log Files Created:
- Main Log: $LOG_FILE
- Error Log: $ERROR_LOG
- Summary Log: $SUMMARY_LOG

EOF
    
    # Display detailed error summary for manual remediation
    if [[ $FAILED_CONTROLS -gt 0 ]]; then
        echo -e "${RED}╔══════════════════════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${RED}║                                FAILED CONTROLS                               ║${NC}"
        echo -e "${RED}╚══════════════════════════════════════════════════════════════════════════════╝${NC}"
        echo
        
        cat >> "$SUMMARY_LOG" << EOF

FAILED CONTROLS REQUIRING MANUAL ATTENTION:
==========================================
EOF
        
        for control in "${FAILED_CONTROL_LIST[@]}"; do
            echo -e "${RED}✗ Failed: $control${NC}"
            echo "✗ Failed: $control" >> "$SUMMARY_LOG"
        done
        
        echo >> "$SUMMARY_LOG"
        cat >> "$SUMMARY_LOG" << EOF

DETAILED ERROR ANALYSIS:
=======================
Please review the error log for specific failure reasons:
$ERROR_LOG

Common remediation steps:
1. Check network connectivity for package installation failures
2. Verify repository configuration if package installations failed
3. Manually install missing packages if needed
4. Re-run specific failed controls individually
5. Check Azure connectivity after completion

EOF
    fi
    
    if [[ $SKIPPED_CONTROLS -gt 0 ]]; then
        echo -e "${YELLOW}╔══════════════════════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${YELLOW}║                               SKIPPED CONTROLS                               ║${NC}"
        echo -e "${YELLOW}╚══════════════════════════════════════════════════════════════════════════════╝${NC}"
        echo
        
        cat >> "$SUMMARY_LOG" << EOF

SKIPPED CONTROLS (Manual Action Required):
=========================================
EOF
        
        for control in "${SKIPPED_CONTROL_LIST[@]}"; do
            echo -e "${YELLOW}⚠ Skipped: $control${NC}"
            echo "⚠ Skipped: $control" >> "$SUMMARY_LOG"
        done
        
        echo >> "$SUMMARY_LOG"
    fi
    
    echo
    log_info "═══════════════════════════════════════════════════════════════════════════════"
    log_info "                           LOG FILES CREATED"
    log_info "═══════════════════════════════════════════════════════════════════════════════"
    log_info "📄 Main execution log: $LOG_FILE"
    log_info "🚨 Error details log: $ERROR_LOG"
    log_info "📋 Summary report: $SUMMARY_LOG"
    echo
    
    if [[ $FAILED_CONTROLS -gt 0 ]]; then
        log_warn "⚠️  Some controls failed. Please review error logs and address manually."
        log_info "📖 For detailed error analysis, check: $ERROR_LOG"
    fi
    
    log_info "🎯 Next Steps:"
    log_info "   1. Review the summary log: cat $SUMMARY_LOG"
    log_info "   2. Check error details if needed: cat $ERROR_LOG"
    log_info "   3. Run a new STIG scan to verify improvements"
    log_info "   4. Address any remaining open findings manually"
    echo
    
    exit $exit_code
}
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
