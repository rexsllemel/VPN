#!/bin/bash

# Quick VPN Uninstaller - One-line uninstaller
# Usage: curl -fsSL https://your-domain.com/quick-uninstall.sh | sudo bash

set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    print_error "This script must be run as root"
    echo "Usage: curl -fsSL https://your-domain.com/quick-uninstall.sh | sudo bash"
    exit 1
fi

print_status "Starting VPN Auto Uninstaller..."

# Confirmation
echo
print_warning "This will remove ALL VPN services and the admin panel"
print_warning "Configuration backup will be created automatically"
echo
read -p "Are you sure you want to continue? (yes/no): " confirm

if [[ "$confirm" != "yes" ]]; then
    print_status "Uninstallation cancelled"
    exit 0
fi

# Create temporary directory
TEMP_DIR=$(mktemp -d)
cd "$TEMP_DIR"

# Download uninstaller
print_status "Downloading uninstaller..."

BASE_URL="https://raw.githubusercontent.com/your-repo/vpn-installer/main"
curl -fsSL "$BASE_URL/uninstall.sh" -o uninstall.sh

# Make executable
chmod +x uninstall.sh

# Run complete removal with automatic answers
print_status "Running complete VPN removal..."

# Prepare answers for interactive prompts
# Node.js removal: no, IP forwarding: no, Backup: yes, Choice: 9 (complete removal)
echo -e "n\nn\ny\n9" | ./uninstall.sh

# Cleanup
cd /
rm -rf "$TEMP_DIR"

print_status "VPN services completely removed!"
print_status "System cleaned up successfully"

# Show final information
echo
echo "Uninstallation Summary:"
echo "======================="
echo "✓ All VPN services removed"
echo "✓ Admin panel removed"
echo "✓ Configuration backup created"
echo "✓ Firewall rules cleaned"
echo "✓ System configuration cleaned"
echo
print_warning "Consider rebooting the system to ensure all changes take effect"
