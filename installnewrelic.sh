#!/bin/bash

# Exit on any error
set -e

# Define your New Relic License Key here
NEWRELIC_LICENSE_KEY="YOUR_LICENSE_KEY"

# Configuration
REQUIRED_SPACE=100000  # 100MB in KB
REQUIRED_MEMORY=524288  # 512MB in KB
CURL_TIMEOUT=30
LOG_FILE="/var/log/newrelic-install.log"
GPG_KEY_FINGERPRINT="A758B3FBCD43BE8D123A3476BB29EE038ECCE87C"

# Create log directory if it doesn't exist
if [ ! -d "$(dirname "$LOG_FILE")" ]; then
    mkdir -p "$(dirname "$LOG_FILE")"
fi

# Support for proxy environments
if [ -n "$http_proxy" ] || [ -n "$https_proxy" ]; then
    export HTTPS_PROXY="$https_proxy"
    export HTTP_PROXY="$http_proxy"
    export http_proxy="$http_proxy"
    export https_proxy="$https_proxy"
fi

# Function to log messages
log_message() {
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] $1" | tee -a "$LOG_FILE"
}

# Cleanup function
cleanup() {
    local exit_code=$?
    if [ $exit_code -ne 0 ]; then
        log_message "ERROR: Script failed with exit code $exit_code"
        if [ -f /etc/newrelic-infra.yml.backup ]; then
            log_message "Restoring backup configuration..."
            mv /etc/newrelic-infra.yml.backup /etc/newrelic-infra.yml
        fi
        # Clean up temporary files
        rm -f /etc/apt/sources.list.d/newrelic-infra.list 2>/dev/null || true
        rm -f /etc/yum.repos.d/newrelic-infra.repo 2>/dev/null || true
        rm -f /etc/apt/trusted.gpg.d/newrelic-infra.gpg 2>/dev/null || true
    fi
    exit $exit_code
}

# Handle interrupts
trap 'log_message "Installation interrupted"; exit 1' INT
trap cleanup EXIT

# Check if script is run as root
if [ "$EUID" -ne 0 ]; then
    log_message "ERROR: Please run as root"
    exit 1
fi

# Validate license key
if [ "$NEWRELIC_LICENSE_KEY" = "YOUR_LICENSE_KEY" ]; then
    log_message "ERROR: Please set your New Relic license key in the script"
    exit 1
fi

# Check for required commands
check_requirements() {
    local cmds=("curl" "systemctl" "grep" "awk" "gpg" "lsb_release")
    for cmd in "${cmds[@]}"; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            log_message "ERROR: Required command '$cmd' not found"
            exit 1
        fi
    done
}

# Check system requirements
check_system_requirements() {
    # Check memory
    local available_memory=$(free -k | awk '/^Mem:/ {print $2}')
    if [ "$available_memory" -lt "$REQUIRED_MEMORY" ]; then
        log_message "ERROR: Insufficient memory. Required: ${REQUIRED_MEMORY}KB, Available: ${available_memory}KB"
        exit 1
    fi
}

# Check disk space
check_disk_space() {
    local available_space=$(df /var/log -k | awk 'NR==2 {print $4}')
    if [ "$available_space" -lt "$REQUIRED_SPACE" ]; then
        log_message "ERROR: Insufficient disk space. Required: ${REQUIRED_SPACE}KB, Available: ${available_space}KB"
        exit 1
    fi
}

# Check network connectivity
check_network() {
    log_message "Checking network connectivity..."
    if ! curl --max-time "$CURL_TIMEOUT" -s https://download.newrelic.com >/dev/null; then
        log_message "ERROR: Cannot reach New Relic servers"
        exit 1
    fi
}

# Check systemd
check_systemd() {
    if ! pidof systemd >/dev/null; then
        log_message "ERROR: systemd is required but not running"
        exit 1
    fi
}

# Detect the OS
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
        VERSION_ID=$VERSION_ID
        
        # Handle systems with multiple package managers
        if command -v apt-get >/dev/null 2>&1 && command -v yum >/dev/null 2>&1; then
            if [ -f /etc/debian_version ]; then
                OS="debian"
            elif [ -f /etc/redhat-release ]; then
                OS="rhel"
            fi
        fi
    else
        log_message "ERROR: OS not supported"
        exit 1
    fi
}

# Function to check command status
check_status() {
    if [ $? -eq 0 ]; then
        log_message "SUCCESS: $1"
    else
        log_message "ERROR: $1"
        exit 1
    fi
}

# Function to install required dependencies
install_dependencies() {
    log_message "Installing dependencies..."
    if [[ "$OS" == "ubuntu" || "$OS" == "debian" ]]; then
        if ! apt-get update; then
            log_message "ERROR: Failed to update package lists"
            exit 1
        fi
        if ! apt-get install -y curl systemd gpg lsb-release; then
            log_message "ERROR: Failed to install dependencies"
            exit 1
        fi
    elif [[ "$OS" == "centos" || "$OS" == "fedora" || "$OS" == "rhel" ]]; then
        if ! yum install -y curl systemd redhat-lsb-core; then
            log_message "ERROR: Failed to install dependencies"
            exit 1
        fi
    fi
    check_status "Dependencies installation"
}

# Function to install the New Relic Infrastructure Agent
install_newrelic_infra() {
    log_message "Installing New Relic Infrastructure Agent..."
    if [[ "$OS" == "ubuntu" || "$OS" == "debian" ]]; then
        # Add New Relic's APT repository
        curl --max-time "$CURL_TIMEOUT" -o /etc/apt/sources.list.d/newrelic-infra.list \
            https://download.newrelic.com/infrastructure_agent/linux/apt/$(lsb_release -cs)/infrastructure-agent.list
        
        # Add GPG key (modern method)
        curl -s https://download.newrelic.com/infrastructure_agent/gpg/newrelic-infra.gpg | \
            gpg --dearmor | tee /etc/apt/trusted.gpg.d/newrelic-infra.gpg > /dev/null
            
        # Verify GPG key fingerprint
        local actual_fingerprint=$(gpg --show-keys /etc/apt/trusted.gpg.d/newrelic-infra.gpg 2>/dev/null | grep -A1 "pub" | tail -n1 | tr -d ' ')
        if [ "$actual_fingerprint" != "$GPG_KEY_FINGERPRINT" ]; then
            log_message "ERROR: GPG key fingerprint verification failed"
            exit 1
        fi
        
        if ! apt-get update; then
            log_message "ERROR: Failed to update package lists after adding repository"
            exit 1
        fi
        if ! apt-get install newrelic-infra -y; then
            log_message "ERROR: Failed to install New Relic Infrastructure Agent"
            exit 1
        fi
    elif [[ "$OS" == "centos" || "$OS" == "fedora" || "$OS" == "rhel" ]]; then
        local major_version=${VERSION_ID%%.*}
        curl --max-time "$CURL_TIMEOUT" -o /etc/yum.repos.d/newrelic-infra.repo \
            https://download.newrelic.com/infrastructure_agent/linux/yum/el/${major_version}/x86_64/newrelic-infra.repo
            
        # Handle SELinux if enabled
        if command -v selinuxenabled >/dev/null 2>&1; then
            if selinuxenabled; then
                semanage port -a -t http_port_t -p tcp 443 || true
            fi
        fi
        
        if ! yum install newrelic-infra -y; then
            log_message "ERROR: Failed to install New Relic Infrastructure Agent"
            exit 1
        fi
    else
        log_message "ERROR: Unsupported operating system"
        exit 1
    fi
    check_status "New Relic Infrastructure Agent installation"
}

# Function to configure the agent
configure_newrelic_infra() {
    log_message "Configuring New Relic Infrastructure Agent..."
    
    # Backup existing config if it exists
    if [ -f /etc/newrelic-infra.yml ]; then
        mv /etc/newrelic-infra.yml /etc/newrelic-infra.yml.backup
        log_message "Backed up existing configuration"
    fi
    
    # Create new configuration
    cat > /etc/newrelic-infra.yml << EOF
license_key: ${NEWRELIC_LICENSE_KEY}
display_name: $(hostname)
custom_attributes:
  environment: production
EOF
    
    # Set proper permissions
    chmod 640 /etc/newrelic-infra.yml
    chown root:root /etc/newrelic-infra.yml
    check_status "Agent configuration"
}

# Function to validate configuration
validate_config() {
    log_message "Validating configuration..."
    if ! [ -f /etc/newrelic-infra.yml ]; then
        log_message "ERROR: Configuration file not found"
        exit 1
    fi
    if ! grep -q "^license_key: " /etc/newrelic-infra.yml; then
        log_message "ERROR: License key not found in configuration"
        exit 1
    fi
}

# Function to start and enable the agent
start_newrelic_infra() {
    log_message "Starting New Relic Infrastructure Agent..."
    systemctl daemon-reload
    if ! timeout 30 systemctl start newrelic-infra; then
        log_message "ERROR: Failed to start New Relic Infrastructure Agent (timeout)"
        exit 1
    fi
    if ! timeout 30 systemctl enable newrelic-infra; then
        log_message "ERROR: Failed to enable New Relic Infrastructure Agent (timeout)"
        exit 1
    fi
    check_status "Agent startup"
}

# Function to verify installation
verify_installation() {
    log_message "Verifying installation..."
    
    # Check if service is running
    if ! systemctl is-active --quiet newrelic-infra; then
        log_message "ERROR: New Relic Infrastructure Agent is not running"
        systemctl status newrelic-infra
        exit 1
    fi
    
    # Check if agent is properly configured
    if ! grep -q "license_key: ${NEWRELIC_LICENSE_KEY}" /etc/newrelic-infra.yml; then
        log_message "ERROR: License key not properly configured"
        exit 1
    fi
    
    # Check agent connectivity
    local timeout=60
    local count=0
    while [ $count -lt $timeout ]; do
        if grep -q "Connected" /var/log/newrelic-infra/newrelic-infra.log 2>/dev/null; then
            log_message "SUCCESS: Agent successfully connected to New Relic"
            break
        fi
        sleep 1
        count=$((count + 1))
    done
    
    if [ $count -eq $timeout ]; then
        log_message "WARNING: Could not verify agent connection to New Relic within ${timeout} seconds"
    fi
    
    log_message "SUCCESS: New Relic Infrastructure Agent is installed and running properly"
}

# Main execution
log_message "Starting New Relic Infrastructure Agent installation"

# Pre-installation checks
check_requirements
check_system_requirements
check_disk_space
check_network
check_systemd
detect_os

# Installation steps
install_dependencies
install_newrelic_infra
configure_newrelic_infra
validate_config
start_newrelic_infra
verify_installation

log_message "Installation completed successfully"
