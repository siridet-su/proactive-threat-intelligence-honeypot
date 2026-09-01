#!/usr/bin/env bash
# Setup script for honeypot-forwarder on Raspberry Pi
# This script prepares the system for running the sensor_forwarder

set -e

echo "=========================================="
echo "Honeypot Sensor Forwarder Setup"
echo "=========================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
FORWARDER_USER="honeypot-forwarder"
CONFIG_DIR="/etc/honeypot-forwarder"
SPOOL_DIR="/var/lib/honeypot-forwarder"
COWRIE_LOG_PATH="/home/cowrie/cowrie/var/log/cowrie/cowrie.json"
PRODUCTION_MODULE_DIR="/home/cpe27/dashboard-honeypot/server/plugin/production"

# Helper functions
print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

print_step() {
    echo -e "\n${YELLOW}[Step $1]${NC} $2"
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    print_error "This script must be run as root (use sudo)"
    exit 1
fi

# Step 1: Create unprivileged user
print_step "1" "Creating honeypot-forwarder system user"
if id "$FORWARDER_USER" &>/dev/null; then
    print_warning "User $FORWARDER_USER already exists"
else
    useradd -m -s /usr/sbin/nologin "$FORWARDER_USER"
    print_success "User $FORWARDER_USER created"
fi

# Step 2: Create config directory
print_step "2" "Creating configuration directory: $CONFIG_DIR"
mkdir -p "$CONFIG_DIR"
chown root:root "$CONFIG_DIR"
chmod 755 "$CONFIG_DIR"
print_success "Config directory created"

# Step 3: Copy env template to config directory
print_step "3" "Installing configuration template"
if [[ -f "$PRODUCTION_MODULE_DIR/honeypot-forwarder-main.env.example" ]]; then
    if [[ ! -f "$CONFIG_DIR/main.env" ]]; then
        cp "$PRODUCTION_MODULE_DIR/honeypot-forwarder-main.env.example" "$CONFIG_DIR/main.env"
        chown root:root "$CONFIG_DIR/main.env"
        chmod 600 "$CONFIG_DIR/main.env"
        print_success "Configuration template installed to $CONFIG_DIR/main.env"
        print_warning "EDIT THIS FILE: sudo nano $CONFIG_DIR/main.env"
    else
        print_warning "Configuration already exists at $CONFIG_DIR/main.env (not overwriting)"
    fi
else
    print_warning "Config template not found at $PRODUCTION_MODULE_DIR/honeypot-forwarder-main.env.example"
fi

# Step 4: Create and setup spool directory
print_step "4" "Creating spool directory: $SPOOL_DIR"
mkdir -p "$SPOOL_DIR"
chown "$FORWARDER_USER:$FORWARDER_USER" "$SPOOL_DIR"
chmod 700 "$SPOOL_DIR"
print_success "Spool directory created with correct permissions"

# Step 5: Check Cowrie log exists
print_step "5" "Checking Cowrie log file: $COWRIE_LOG_PATH"
if [[ ! -f "$COWRIE_LOG_PATH" ]]; then
    print_warning "Cowrie log not found at $COWRIE_LOG_PATH"
    print_warning "This is OK if Cowrie hasn't been started yet"
    print_warning "To find actual cowrie.json location, run:"
    print_warning "  sudo find / -name 'cowrie.json' 2>/dev/null"
else
    print_success "Cowrie log file found"
    
    # Step 6: Check permissions
    print_step "6" "Checking file permissions"
    
    # Get file ownership
    COWRIE_OWNER=$(stat -c "%U" "$COWRIE_LOG_PATH")
    COWRIE_GROUP=$(stat -c "%G" "$COWRIE_LOG_PATH")
    
    print_success "Cowrie log owner: $COWRIE_OWNER:$COWRIE_GROUP"
    
    # Try to read as forwarder user
    if su - "$FORWARDER_USER" -c "head -1 $COWRIE_LOG_PATH" &>/dev/null; then
        print_success "User $FORWARDER_USER can read $COWRIE_LOG_PATH"
    else
        print_warning "User $FORWARDER_USER cannot read $COWRIE_LOG_PATH"
        print_warning "Attempting to add $FORWARDER_USER to $COWRIE_GROUP group..."
        
        if [[ -n "$COWRIE_GROUP" && "$COWRIE_GROUP" != "root" ]]; then
            usermod -aG "$COWRIE_GROUP" "$FORWARDER_USER"
            print_success "Added $FORWARDER_USER to group $COWRIE_GROUP"
            print_warning "User must logout/login for group changes to take effect"
        else
            print_error "Cannot determine Cowrie group - manual permission setup needed"
            print_error "Try: sudo setfacl -m u:$FORWARDER_USER:r $COWRIE_LOG_PATH"
        fi
    fi
fi

# Step 7: Summary
print_step "7" "Setup Summary"
echo ""
echo "User created: $FORWARDER_USER"
echo "Config directory: $CONFIG_DIR"
echo "  Files: main.env"
echo "  Owner: root:root"
echo "  Permissions: 600"
echo "Spool directory: $SPOOL_DIR"
echo "  Owner: $FORWARDER_USER:$FORWARDER_USER"
echo "  Permissions: 700"
echo ""

# Step 8: Next steps
echo "=========================================="
echo "Next steps:"
echo "=========================================="
echo "1. EDIT configuration file:"
echo "   sudo nano $CONFIG_DIR/main.env"
echo ""
echo "2. Update HONEYPOT_API_TOKEN with your GCP bearer token"
echo "   and update COWRIE_LOG_PATH if not at default location"
echo ""
echo "3. Test the configuration:"
echo "   export PYTHONPATH=/home/cpe27/dashboard-honeypot/server/plugin"
echo "   sudo -u $FORWARDER_USER env \$(sudo cat $CONFIG_DIR/main.env | xargs) python3 -m production.test_connection"
echo ""
echo "4. Run --once test to verify GCP connection:"
echo "   sudo -u $FORWARDER_USER env \$(sudo cat $CONFIG_DIR/main.env | xargs) \\"
echo "     PYTHONPATH=/home/cpe27/dashboard-honeypot/server/plugin python3 -m production.sensor_forwarder --once"
echo ""
echo "5. Create systemd service file:"
echo "   sudo nano /etc/systemd/system/honeypot-sensor-forwarder-main.service"
echo ""
echo "6. Enable and start the systemd service:"
echo "   sudo systemctl daemon-reload"
echo "   sudo systemctl enable honeypot-sensor-forwarder-main.service"
echo "   sudo systemctl start honeypot-sensor-forwarder-main.service"
echo ""
echo "7. Monitor logs:"
echo "   sudo journalctl -u honeypot-sensor-forwarder-main -f"
echo ""

print_success "Setup complete!"
