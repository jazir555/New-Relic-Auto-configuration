#!/bin/bash

# Exit on any error
set -e

# Define your New Relic License Key here
NEWRELIC_LICENSE_KEY="YOUR_LICENSE_KEY"

# Check if script is run as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root"
    exit 1
fi

# Validate license key
if [ "$NEWRELIC_LICENSE_KEY" = "YOUR_LICENSE_KEY" ]; then
    echo "Please set your New Relic license key in the script"
    exit 1
fi

# Function to log messages
log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

# Detect the OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
    VERSION_ID=$VERSION_ID
else
    log_message "ERROR: OS not supported"
    exit 1
fi

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
        apt-get update
        apt-get install -y curl systemd
    elif [[ "$OS" == "centos" || "$OS" == "fedora" || "$OS" == "rhel" ]]; then
        yum install -y curl systemd
    fi
    check_status "Dependencies installation"
}

# Function to install the New Relic Infrastructure Agent
install_newrelic_infra() {
    log_message "Installing New Relic Infrastructure Agent..."
    if [[ "$OS" == "ubuntu" || "$OS" == "debian" ]]; then
        # Add New Relic's APT repository and install the agent for Debian-based distros
        curl -o /etc/apt/sources.list.d/newrelic-infra.list \
            https://download.newrelic.com/infrastructure_agent/linux/apt/$(lsb_release -cs)/infrastructure-agent.list
        curl -s https://download.newrelic.com/infrastructure_agent/gpg/newrelic-infra.gpg | apt-key add -
        apt-get update
        apt-get install newrelic-infra -y
    elif [[ "$OS" == "centos" || "$OS" == "fedora" || "$OS" == "rhel" ]]; then
        # Add New Relic's YUM repository and install the agent for RHEL-based distros
        curl -o /etc/yum.repos.d/newrelic-infra.repo \
            https://download.newrelic.com/infrastructure_agent/linux/yum/el/7/x86_64/newrelic-infra.repo
        yum install newrelic-infra -y
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
# Add any additional configuration options here
EOF
    
    # Set proper permissions
    chmod 640 /etc/newrelic-infra.yml
    check_status "Agent configuration"
}

# Function to start and enable the agent
start_newrelic_infra() {
    log_message "Starting New Relic Infrastructure Agent..."
    systemctl daemon-reload
    systemctl start newrelic-infra
    systemctl enable newrelic-infra
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
    
    log_message "SUCCESS: New Relic Infrastructure Agent is installed and running properly"
}

# Main execution
log_message "Starting New Relic Infrastructure Agent installation"

# Execute functions
install_dependencies
install_newrelic_infra
configure_newrelic_infra
start_newrelic_infra
verify_installation

log_message "Installation completed successfully"
