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
MAX_LOG_SIZE=10485760  # 10MB
MAX_BACKUPS=5
# Default expected GPG key fingerprint.
GPG_KEY_FINGERPRINT="A758B3FBCD43BE8D123A3476BB29EE038ECCE87C"
# GPG key URL (used for all supported distributions)
GPG_KEY_URL="https://download.newrelic.com/infrastructure_agent/gpg/newrelic-infra.gpg"

# Supported OS versions
declare -A SUPPORTED_VERSIONS=(
  ["ubuntu"]="18.04 20.04 22.04"
  ["debian"]="10 11"
  ["rhel"]="7 8 9"
  ["centos"]="7 8"
  ["fedora"]="34 35 36"
)

# Create log directory if it doesn't exist
if [ ! -d "$(dirname "$LOG_FILE")" ]; then
  mkdir -p "$(dirname "$LOG_FILE")"
fi

# Rotate logs if necessary
rotate_logs() {
  if [ -f "$LOG_FILE" ] && [ $(stat -f%z "$LOG_FILE" 2>/dev/null || stat -c%s "$LOG_FILE") -gt $MAX_LOG_SIZE ]; then
    for i in $(seq $((MAX_BACKUPS-1)) -1 1); do
      [ -f "${LOG_FILE}.$i" ] && mv "${LOG_FILE}.$i" "${LOG_FILE}.$((i+1))"
    done
    mv "$LOG_FILE" "${LOG_FILE}.1"
    touch "$LOG_FILE"
  fi
}
rotate_logs

# Support for proxy environments
if [ -n "$http_proxy" ] || [ -n "$https_proxy" ]; then
  export HTTPS_PROXY="$https_proxy"
  export HTTP_PROXY="$http_proxy"
  export http_proxy="$http_proxy"
  export https_proxy="$https_proxy"
  export NO_PROXY="localhost,127.0.0.1"
  export no_proxy="localhost,127.0.0.1"
fi

# Function to log messages
log_message() {
  local timestamp
  timestamp=$(date '+%Y-%m-%d %H:%M:%S')
  echo "[$timestamp] $1" | tee -a "$LOG_FILE"
  rotate_logs
}

# Cleanup function
cleanup() {
  local exit_code=$?
  if [ $exit_code -ne 0 ]; then
    log_message "ERROR: Script failed with exit code $exit_code"
    if [ -f /etc/newrelic-infra.yml.backup.$(date +%Y%m%d) ]; then
      log_message "Restoring backup configuration..."
      mv /etc/newrelic-infra.yml.backup.$(date +%Y%m%d) /etc/newrelic-infra.yml
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

# Check architecture
check_architecture() {
  local arch
  arch=$(uname -m)
  if [ "$arch" != "x86_64" ]; then
    log_message "ERROR: Unsupported architecture: $arch. Only x86_64 is supported"
    exit 1
  fi
}

# Check for required commands
check_requirements() {
  local cmds=("curl" "systemctl" "grep" "awk" "gpg" "lsb_release" "rpm")
  for cmd in "${cmds[@]}"; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      log_message "ERROR: Required command '$cmd' not found"
      exit 1
    fi
  done
}

# Check system requirements
check_system_requirements() {
  local available_memory
  available_memory=$(free -k | awk '/^Mem:/ {print $7}')
  if [ "$available_memory" -lt "$REQUIRED_MEMORY" ]; then
    log_message "ERROR: Insufficient available memory. Required: ${REQUIRED_MEMORY}KB, Available: ${available_memory}KB"
    exit 1
  fi
}

# Check disk space
check_disk_space() {
  local available_space
  available_space=$(df /var/log -k | awk 'NR==2 {print $4}')
  if [ "$available_space" -lt "$REQUIRED_SPACE" ]; then
    log_message "ERROR: Insufficient disk space. Required: ${REQUIRED_SPACE}KB, Available: ${available_space}KB"
    exit 1
  fi
}

# Check network connectivity
check_network() {
  log_message "Checking network connectivity..."
  local endpoints=(
    "download.newrelic.com"
    "collector.newrelic.com"
    "infrastructure-api.newrelic.com"
  )
  for endpoint in "${endpoints[@]}"; do
    if ! curl --max-time "$CURL_TIMEOUT" -s "https://${endpoint}" >/dev/null; then
      log_message "ERROR: Cannot reach New Relic endpoint: ${endpoint}"
      exit 1
    fi
  done
}

# Check systemd
check_systemd() {
  if ! pidof systemd >/dev/null; then
    log_message "ERROR: systemd is required but not running"
    exit 1
  fi
}

# Detect and validate OS version
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

    # Validate OS version
    if [ -n "${SUPPORTED_VERSIONS[$OS]}" ]; then
      local supported=false
      for version in ${SUPPORTED_VERSIONS[$OS]}; do
        if [[ "$VERSION_ID" == "$version"* ]]; then
          supported=true
          break
        fi
      done
      if ! $supported; then
        log_message "ERROR: Unsupported $OS version: $VERSION_ID"
        log_message "Supported versions: ${SUPPORTED_VERSIONS[$OS]}"
        exit 1
      fi
    else
      log_message "ERROR: Unsupported operating system: $OS"
      exit 1
    fi
  else
    log_message "ERROR: Could not determine OS version"
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
    if ! DEBIAN_FRONTEND=noninteractive apt-get update; then
      log_message "ERROR: Failed to update package lists"
      exit 1
    fi
    if ! DEBIAN_FRONTEND=noninteractive apt-get install -y curl systemd gpg lsb-release; then
      log_message "ERROR: Failed to install dependencies"
      exit 1
    fi
  elif [[ "$OS" == "centos" || "$OS" == "fedora" || "$OS" == "rhel" ]]; then
    if ! yum install -y curl systemd redhat-lsb-core policycoreutils-python; then
      log_message "ERROR: Failed to install dependencies"
      exit 1
    fi
  fi
  check_status "Dependencies installation"
}

# Function to perform dynamic GPG key check and import for both APT and YUM based systems.
dynamic_gpg_import() {
  local temp_key
  temp_key=$(mktemp /tmp/newrelic-infra.gpg.XXXXXX)
  if ! curl --max-time "$CURL_TIMEOUT" -s "$GPG_KEY_URL" -o "$temp_key"; then
    log_message "ERROR: Failed to download GPG key from $GPG_KEY_URL"
    exit 1
  fi
  local actual_fp expected_fp
  actual_fp=$(gpg --with-colons --fingerprint "$temp_key" | awk -F: '/^fpr/ {print $10; exit}')
  if [ -z "$actual_fp" ]; then
    log_message "ERROR: Could not extract fingerprint from downloaded GPG key."
    exit 1
  fi
  if [ -n "$NEWRELIC_EXPECTED_GPG_FP" ]; then
    expected_fp="$NEWRELIC_EXPECTED_GPG_FP"
  else
    expected_fp="$GPG_KEY_FINGERPRINT"
  fi
  log_message "Actual GPG Fingerprint: $actual_fp"
  log_message "Expected GPG Fingerprint: $expected_fp"
  if [ "$actual_fp" != "$expected_fp" ]; then
    log_message "ERROR: GPG key fingerprint does not match the expected value."
    exit 1
  fi
  echo "$temp_key"
}

# Function to install the New Relic Infrastructure Agent
install_newrelic_infra() {
  log_message "Installing New Relic Infrastructure Agent..."
  if [[ "$OS" == "ubuntu" || "$OS" == "debian" ]]; then
    # Add New Relic's APT repository
    if ! curl --max-time "$CURL_TIMEOUT" -o /etc/apt/sources.list.d/newrelic-infra.list \
         https://download.newrelic.com/infrastructure_agent/linux/apt/$(lsb_release -cs)/infrastructure-agent.list; then
      log_message "ERROR: Failed to download repository configuration"
      exit 1
    fi

    # Perform dynamic GPG key check and import
    temp_key=$(dynamic_gpg_import)
    if ! gpg --dearmor < "$temp_key" | tee /etc/apt/trusted.gpg.d/newrelic-infra.gpg > /dev/null; then
      log_message "ERROR: Failed to import GPG key for APT"
      exit 1
    fi
    rm -f "$temp_key"

    if ! DEBIAN_FRONTEND=noninteractive apt-get update; then
      log_message "ERROR: Failed to update package lists after adding repository"
      exit 1
    fi
    if ! DEBIAN_FRONTEND=noninteractive apt-get install newrelic-infra -y; then
      log_message "ERROR: Failed to install New Relic Infrastructure Agent"
      exit 1
    fi

  elif [[ "$OS" == "centos" || "$OS" == "fedora" || "$OS" == "rhel" ]]; then
    local major_version=${VERSION_ID%%.*}
    if ! curl --max-time "$CURL_TIMEOUT" -o /etc/yum.repos.d/newrelic-infra.repo \
         https://download.newrelic.com/infrastructure_agent/linux/yum/el/${major_version}/x86_64/newrelic-infra.repo; then
      log_message "ERROR: Failed to download repository configuration"
      exit 1
    fi

    # Perform dynamic GPG key check and import for YUM-based systems
    temp_key=$(dynamic_gpg_import)
    if ! rpm --import "$temp_key"; then
      log_message "ERROR: Failed to import GPG key for YUM"
      exit 1
    fi
    rm -f "$temp_key"

    # Handle SELinux if enabled
    if command -v selinuxenabled >/dev/null 2>&1; then
      if selinuxenabled; then
        if ! command -v semanage >/dev/null 2>&1; then
          log_message "Installing SELinux management tools..."
          yum install -y policycoreutils-python
        fi
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

  # Backup existing config with timestamp
  if [ -f /etc/newrelic-infra.yml ]; then
    local backup_file="/etc/newrelic-infra.yml.backup.$(date +%Y%m%d)"
    mv /etc/newrelic-infra.yml "$backup_file"
    log_message "Backed up existing configuration to $backup_file"

    # Cleanup old backups (keep last 5)
    local old_backups
    old_backups=$(ls -t /etc/newrelic-infra.yml.backup.* 2>/dev/null | tail -n +6)
    if [ -n "$old_backups" ]; then
      rm -f $old_backups
    fi
  fi

  # Create new configuration
  cat > /etc/newrelic-infra.yml << EOF
license_key: ${NEWRELIC_LICENSE_KEY}
display_name: $(hostname)
custom_attributes:
  environment: production
  os_name: ${OS}
  os_version: ${VERSION_ID}
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

  # Check agent connectivity with improved timeout handling
  local timeout=60
  local count=0
  while [ $count -lt $timeout ]; do
    if grep -q "Connected" /var/log/newrelic-infra/newrelic-infra.log 2>/dev/null; then
      log_message "SUCCESS: Agent successfully connected to New Relic"
      break
    fi
    sleep 1
    count=$((count + 1))
    if [ $((count % 10)) -eq 0 ]; then
      log_message "Waiting for agent to connect... ($count/${timeout}s)"
    fi
  done

  if [ $count -eq $timeout ]; then
    log_message "WARNING: Could not verify agent connection to New Relic within ${timeout} seconds"
    log_message "Please check /var/log/newrelic-infra/newrelic-infra.log for details"
  fi

  # Verify agent data reporting
  if ! curl --max-time "$CURL_TIMEOUT" -s -X GET \
       "https://infrastructure-api.newrelic.com/v2/agents" \
       -H "Api-Key: ${NEWRELIC_LICENSE_KEY}" | grep -q "$(hostname)"; then
    log_message "WARNING: Could not verify agent data reporting to New Relic"
  else
    log_message "SUCCESS: Agent is reporting data to New Relic"
  fi

  log_message "SUCCESS: New Relic Infrastructure Agent is installed and running properly"
}

# Main execution
main() {
  log_message "Starting New Relic Infrastructure Agent installation"

  # Pre-installation checks
  check_architecture
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

  # Print final status message
  cat << EOF

==========================================================
New Relic Infrastructure Agent Installation Summary
==========================================================
Operating System: $OS $VERSION_ID
Architecture: $(uname -m)
Hostname: $(hostname)
Agent Status: $(systemctl is-active newrelic-infra)
Configuration: /etc/newrelic-infra.yml
Log File: /var/log/newrelic-infra/newrelic-infra.log
Install Log: $LOG_FILE
==========================================================

For troubleshooting, please check:
1. Installation log: $LOG_FILE
2. Agent log: /var/log/newrelic-infra/newrelic-infra.log
3. Agent status: systemctl status newrelic-infra
EOF
}

# Run main function
main
