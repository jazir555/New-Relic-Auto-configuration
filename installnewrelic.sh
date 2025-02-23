#!/bin/bash

# Define your New Relic License Key here
NEWRELIC_LICENSE_KEY="YOUR_LICENSE_KEY"

# Detect the OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
    VERSION_ID=$VERSION_ID
else
    echo "OS not supported"
    exit 1
fi

# Function to install the New Relic Infrastructure Agent
install_newrelic_infra() {
    echo "Installing New Relic Infrastructure Agent..."

    if [[ "$OS" == "ubuntu" || "$OS" == "debian" ]]; then
        # Add New Relic's APT repository and install the agent for Debian-based distros
        curl -o /etc/apt/sources.list.d/newrelic-infra.list https://download.newrelic.com/infrastructure_agent/linux/apt/$(lsb_release -cs)/infrastructure-agent.list
        curl -s https://download.newrelic.com/infrastructure_agent/gpg/newrelic-infra.gpg | apt-key add -
        apt-get update
        apt-get install newrelic-infra -y
    elif [[ "$OS" == "centos" || "$OS" == "fedora" || "$OS" == "rhel" ]]; then
        # Add New Relic's YUM repository and install the agent for RHEL-based distros
        sudo curl -o /etc/yum.repos.d/newrelic-infra.repo https://download.newrelic.com/infrastructure_agent/linux/yum/el/7/x86_64/newrelic-infra.repo
        sudo yum install newrelic-infra -y
    else
        echo "Unsupported operating system."
        exit 1
    fi
}

# Function to configure the agent
configure_newrelic_infra() {
    echo "Configuring New Relic Infrastructure Agent..."

    # Add the New Relic license key to the configuration file
    echo "license_key: $NEWRELIC_LICENSE_KEY" | tee /etc/newrelic-infra.yml
}

# Function to start and enable the agent
start_newrelic_infra() {
    echo "Starting New Relic Infrastructure Agent..."

    systemctl start newrelic-infra
    systemctl enable newrelic-infra
}

# Run the functions
install_newrelic_infra
configure_newrelic_infra
start_newrelic_infra

# Verify installation
if systemctl status newrelic-infra | grep -q "active (running)"; then
    echo "New Relic Infrastructure Agent is installed and running."
else
    echo "Failed to install or start New Relic Infrastructure Agent."
fi
