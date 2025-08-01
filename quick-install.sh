#!/bin/bash

# Quick VPN Setup - One-line installer
# Usage: curl -fsSL https://your-domain.com/quick-install.sh | sudo bash

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
    echo "Usage: curl -fsSL https://your-domain.com/quick-install.sh | sudo bash"
    exit 1
fi

print_status "Starting VPN Auto Installer..."

# Create temporary directory
TEMP_DIR=$(mktemp -d)
cd "$TEMP_DIR"

# Download installer files
print_status "Downloading installer files..."

# You would replace these URLs with your actual hosting location
BASE_URL="https://raw.githubusercontent.com/your-repo/vpn-installer/main"

curl -fsSL "$BASE_URL/install.sh" -o install.sh
curl -fsSL "$BASE_URL/install-admin-panel.sh" -o install-admin-panel.sh

# Make executable
chmod +x install.sh install-admin-panel.sh

# Download admin panel files
mkdir -p admin-panel
cd admin-panel

curl -fsSL "$BASE_URL/admin-panel/package.json" -o package.json
curl -fsSL "$BASE_URL/admin-panel/server.js" -o server.js

mkdir -p views
curl -fsSL "$BASE_URL/admin-panel/views/login.ejs" -o views/login.ejs
curl -fsSL "$BASE_URL/admin-panel/views/dashboard.ejs" -o views/dashboard.ejs
curl -fsSL "$BASE_URL/admin-panel/views/users.ejs" -o views/users.ejs
curl -fsSL "$BASE_URL/admin-panel/views/connections.ejs" -o views/connections.ejs
curl -fsSL "$BASE_URL/admin-panel/views/logs.ejs" -o views/logs.ejs
curl -fsSL "$BASE_URL/admin-panel/views/404.ejs" -o views/404.ejs

cd ..

# Interactive installation
echo
echo "VPN Auto Installer & Admin Panel"
echo "================================="
echo
echo "Available VPN Types:"
echo "1) OpenVPN"
echo "2) WireGuard" 
echo "3) IPsec/IKEv2"
echo "4) SoftEther VPN"
echo "5) PPTP VPN"
echo "6) L2TP VPN"
echo "7) Install All VPNs"
echo "8) Install Admin Panel Only"
echo

read -p "Enter your choice [1-8]: " choice

case $choice in
    8)
        print_status "Installing Admin Panel only..."
        ./install-admin-panel.sh
        ;;
    *)
        print_status "Installing VPN server..."
        echo "$choice" | ./install.sh
        
        echo
        read -p "Do you want to install the Admin Panel? (y/n): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            print_status "Installing Admin Panel..."
            ./install-admin-panel.sh
        fi
        ;;
esac

# Cleanup
cd /
rm -rf "$TEMP_DIR"

print_status "Installation completed!"
print_status "Check the README.md for usage instructions"

# Show access information
SERVER_IP=$(curl -s ifconfig.me 2>/dev/null || echo "your-server-ip")
echo
echo "Access Information:"
echo "==================="
echo "Server IP: $SERVER_IP"
echo "Admin Panel: http://$SERVER_IP:3000"
echo "Default Login: admin / admin123"
echo
echo "Client configs location: /etc/vpn-config/clients/"
echo "Installation summary: /etc/vpn-config/install_info.txt"
