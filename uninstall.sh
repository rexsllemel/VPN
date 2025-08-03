#!/bin/bash

# VPN Auto Uninstaller Script
# Removes VPN services, configurations, and admin panel
# Author: VPN Auto Installer
# Version: 1.0

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="/opt/vpn-installer"
LOG_FILE="/var/log/vpn-uninstaller.log"
CONFIG_DIR="/etc/vpn-config"

# Logging function
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# Print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
    log "INFO: $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
    log "WARNING: $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
    log "ERROR: $1"
}

print_header() {
    echo -e "${BLUE}================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}================================${NC}"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

# Detect OS
detect_os() {
    if [[ -f /etc/redhat-release ]]; then
        OS="centos"
        PACKAGE_MANAGER="yum"
    elif [[ -f /etc/debian_version ]]; then
        OS="debian"
        PACKAGE_MANAGER="apt-get"
    elif [[ -f /etc/arch-release ]]; then
        OS="arch"
        PACKAGE_MANAGER="pacman"
    else
        print_error "Unsupported operating system"
        exit 1
    fi
    print_status "Detected OS: $OS"
}

# Backup configurations before removal
backup_configs() {
    print_status "Creating configuration backup..."
    
    BACKUP_DIR="/root/vpn-backup-$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$BACKUP_DIR"
    
    # Backup VPN configurations
    [[ -d /etc/openvpn ]] && cp -r /etc/openvpn "$BACKUP_DIR/" 2>/dev/null || true
    [[ -d /etc/wireguard ]] && cp -r /etc/wireguard "$BACKUP_DIR/" 2>/dev/null || true
    [[ -d /etc/ipsec.d ]] && cp -r /etc/ipsec.d "$BACKUP_DIR/" 2>/dev/null || true
    [[ -f /etc/ipsec.conf ]] && cp /etc/ipsec.conf "$BACKUP_DIR/" 2>/dev/null || true
    [[ -f /etc/ipsec.secrets ]] && cp /etc/ipsec.secrets "$BACKUP_DIR/" 2>/dev/null || true
    [[ -d /opt/vpnserver ]] && cp -r /opt/vpnserver "$BACKUP_DIR/" 2>/dev/null || true
    [[ -f /etc/pptpd.conf ]] && cp /etc/pptpd.conf "$BACKUP_DIR/" 2>/dev/null || true
    [[ -d /etc/xl2tpd ]] && cp -r /etc/xl2tpd "$BACKUP_DIR/" 2>/dev/null || true
    [[ -d /etc/ppp ]] && cp -r /etc/ppp "$BACKUP_DIR/" 2>/dev/null || true
    [[ -d "$CONFIG_DIR" ]] && cp -r "$CONFIG_DIR" "$BACKUP_DIR/" 2>/dev/null || true
    [[ -d /opt/vpn-admin ]] && cp -r /opt/vpn-admin "$BACKUP_DIR/" 2>/dev/null || true
    
    # Create backup info
    cat > "$BACKUP_DIR/backup_info.txt" << EOF
VPN Configuration Backup
========================
Backup Date: $(date)
Server IP: $(curl -s ifconfig.me 2>/dev/null || echo "unknown")
Backup Location: $BACKUP_DIR

This backup contains all VPN configurations and certificates.
You can restore them manually if needed.
EOF
    
    print_status "Backup created at: $BACKUP_DIR"
}

# Stop and disable VPN services
stop_services() {
    print_header "Stopping VPN Services"
    
    services=(
        "openvpn@server"
        "openvpn"
        "wg-quick@wg0"
        "strongswan"
        "strongswan-starter"
        "softether-vpnserver"
        "pptpd"
        "xl2tpd"
        "vpn-admin"
    )
    
    for service in "${services[@]}"; do
        if systemctl is-active --quiet "$service" 2>/dev/null; then
            print_status "Stopping $service..."
            systemctl stop "$service" 2>/dev/null || true
        fi
        
        if systemctl is-enabled --quiet "$service" 2>/dev/null; then
            print_status "Disabling $service..."
            systemctl disable "$service" 2>/dev/null || true
        fi
    done
    
    # Stop ipsec manually
    ipsec stop 2>/dev/null || true
    
    # Kill any remaining processes
    pkill -f openvpn 2>/dev/null || true
    pkill -f wg-quick 2>/dev/null || true
    pkill -f charon 2>/dev/null || true
    pkill -f starter 2>/dev/null || true
    pkill -f vpnserver 2>/dev/null || true
    pkill -f pptpd 2>/dev/null || true
    pkill -f xl2tpd 2>/dev/null || true
    pkill -f "node.*vpn-admin" 2>/dev/null || true
}

# Remove OpenVPN
remove_openvpn() {
    print_header "Removing OpenVPN"
    
    # Stop and disable service
    systemctl stop openvpn@server 2>/dev/null || true
    systemctl disable openvpn@server 2>/dev/null || true
    systemctl stop openvpn 2>/dev/null || true
    systemctl disable openvpn 2>/dev/null || true
    
    # Remove packages
    case $OS in
        "debian")
            apt-get remove --purge -y openvpn easy-rsa 2>/dev/null || true
            ;;
        "centos")
            yum remove -y openvpn easy-rsa 2>/dev/null || true
            ;;
        "arch")
            pacman -Rs --noconfirm openvpn easy-rsa 2>/dev/null || true
            ;;
    esac
    
    # Remove configuration files
    rm -rf /etc/openvpn
    rm -f /etc/systemd/system/openvpn@.service
    rm -f /var/log/openvpn*
    
    print_status "OpenVPN removed"
}

# Remove WireGuard
remove_wireguard() {
    print_header "Removing WireGuard"
    
    # Stop and disable service
    systemctl stop wg-quick@wg0 2>/dev/null || true
    systemctl disable wg-quick@wg0 2>/dev/null || true
    wg-quick down wg0 2>/dev/null || true
    
    # Remove packages
    case $OS in
        "debian")
            apt-get remove --purge -y wireguard wireguard-tools 2>/dev/null || true
            ;;
        "centos")
            yum remove -y kmod-wireguard wireguard-tools 2>/dev/null || true
            ;;
        "arch")
            pacman -Rs --noconfirm wireguard-tools 2>/dev/null || true
            ;;
    esac
    
    # Remove configuration files
    rm -rf /etc/wireguard
    
    print_status "WireGuard removed"
}

# Remove IPsec/IKEv2
remove_ipsec() {
    print_header "Removing IPsec/IKEv2"
    
    # Stop services
    systemctl stop strongswan 2>/dev/null || true
    systemctl disable strongswan 2>/dev/null || true
    systemctl stop strongswan-starter 2>/dev/null || true
    systemctl disable strongswan-starter 2>/dev/null || true
    ipsec stop 2>/dev/null || true
    
    # Remove packages
    case $OS in
        "debian")
            apt-get remove --purge -y strongswan strongswan-pki libcharon-extra-plugins libcharon-extauth-plugins 2>/dev/null || true
            ;;
        "centos")
            yum remove -y strongswan 2>/dev/null || true
            ;;
        "arch")
            pacman -Rs --noconfirm strongswan 2>/dev/null || true
            ;;
    esac
    
    # Remove configuration files
    rm -rf /etc/ipsec.d
    rm -f /etc/ipsec.conf
    rm -f /etc/ipsec.secrets
    rm -rf /etc/strongswan.d
    rm -f /etc/systemd/system/strongswan.service
    
    print_status "IPsec/IKEv2 removed"
}

# Remove SoftEther VPN
remove_softether() {
    print_header "Removing SoftEther VPN"
    
    # Stop and disable service
    systemctl stop softether-vpnserver 2>/dev/null || true
    systemctl disable softether-vpnserver 2>/dev/null || true
    
    # Kill processes
    pkill -f vpnserver 2>/dev/null || true
    
    # Remove installation
    rm -rf /opt/vpnserver
    rm -f /etc/systemd/system/softether-vpnserver.service
    
    # Remove build dependencies (optional, be careful)
    # case $OS in
    #     "debian")
    #         apt-get autoremove -y build-essential gcc make 2>/dev/null || true
    #         ;;
    # esac
    
    print_status "SoftEther VPN removed"
}

# Remove PPTP VPN
remove_pptp() {
    print_header "Removing PPTP VPN"
    
    # Stop and disable service
    systemctl stop pptpd 2>/dev/null || true
    systemctl disable pptpd 2>/dev/null || true
    
    # Remove packages
    case $OS in
        "debian")
            apt-get remove --purge -y pptpd 2>/dev/null || true
            ;;
        "centos")
            yum remove -y pptpd 2>/dev/null || true
            ;;
        "arch")
            pacman -Rs --noconfirm pptpd 2>/dev/null || true
            ;;
    esac
    
    # Remove configuration files
    rm -f /etc/pptpd.conf
    
    print_status "PPTP VPN removed"
}

# Remove L2TP VPN
remove_l2tp() {
    print_header "Removing L2TP VPN"
    
    # Stop and disable service
    systemctl stop xl2tpd 2>/dev/null || true
    systemctl disable xl2tpd 2>/dev/null || true
    
    # Remove packages
    case $OS in
        "debian")
            apt-get remove --purge -y xl2tpd 2>/dev/null || true
            ;;
        "centos")
            yum remove -y xl2tpd 2>/dev/null || true
            ;;
        "arch")
            pacman -Rs --noconfirm xl2tpd 2>/dev/null || true
            ;;
    esac
    
    # Remove configuration files
    rm -rf /etc/xl2tpd
    
    print_status "L2TP VPN removed"
}

# Remove admin panel
remove_admin_panel() {
    print_header "Removing VPN Admin Panel"
    
    # Stop and disable service
    systemctl stop vpn-admin 2>/dev/null || true
    systemctl disable vpn-admin 2>/dev/null || true
    
    # Kill any running processes
    pkill -f "node.*vpn-admin" 2>/dev/null || true
    
    # Remove installation
    rm -rf /opt/vpn-admin
    rm -f /etc/systemd/system/vpn-admin.service
    
    # Remove user
    userdel vpnadmin 2>/dev/null || true
    
    # Remove Node.js (optional, ask user)
    if [[ "$REMOVE_NODEJS" == "yes" ]]; then
        case $OS in
            "debian")
                apt-get remove --purge -y nodejs npm 2>/dev/null || true
                ;;
            "centos")
                yum remove -y nodejs npm 2>/dev/null || true
                ;;
            "arch")
                pacman -Rs --noconfirm nodejs npm 2>/dev/null || true
                ;;
        esac
        print_status "Node.js removed"
    fi
    
    print_status "VPN Admin Panel removed"
}

# Remove Nginx configuration (if exists)
remove_nginx_config() {
    print_header "Removing Nginx Configuration"
    
    # Remove VPN admin site
    rm -f /etc/nginx/sites-available/vpn-admin
    rm -f /etc/nginx/sites-enabled/vpn-admin
    rm -f /etc/nginx/conf.d/vpn-admin.conf
    
    # Restart nginx if it's running
    if systemctl is-active --quiet nginx; then
        systemctl reload nginx 2>/dev/null || true
        print_status "Nginx configuration removed and reloaded"
    fi
}

# Clean up firewall rules
cleanup_firewall() {
    print_header "Cleaning Up Firewall Rules"
    
    # Remove VPN-specific iptables rules
    iptables -D INPUT -p udp --dport 1194 -j ACCEPT 2>/dev/null || true  # OpenVPN
    iptables -D INPUT -p udp --dport 51820 -j ACCEPT 2>/dev/null || true # WireGuard
    iptables -D INPUT -p udp --dport 500 -j ACCEPT 2>/dev/null || true   # IPsec
    iptables -D INPUT -p udp --dport 4500 -j ACCEPT 2>/dev/null || true  # IPsec
    iptables -D INPUT -p udp --dport 1701 -j ACCEPT 2>/dev/null || true  # L2TP
    iptables -D INPUT -p tcp --dport 1723 -j ACCEPT 2>/dev/null || true  # PPTP
    iptables -D INPUT -p tcp --dport 3000 -j ACCEPT 2>/dev/null || true  # Admin Panel
    iptables -D INPUT -p esp -j ACCEPT 2>/dev/null || true               # IPsec ESP
    
    # Remove FORWARD rules
    iptables -D FORWARD -i tun+ -j ACCEPT 2>/dev/null || true
    iptables -D FORWARD -i wg+ -j ACCEPT 2>/dev/null || true
    iptables -D FORWARD -s 10.8.0.0/24 -j ACCEPT 2>/dev/null || true    # OpenVPN
    iptables -D FORWARD -s 10.0.0.0/24 -j ACCEPT 2>/dev/null || true    # WireGuard
    iptables -D FORWARD -s 10.10.10.0/24 -j ACCEPT 2>/dev/null || true  # IPsec
    iptables -D FORWARD -s 192.168.0.0/24 -j ACCEPT 2>/dev/null || true # PPTP
    iptables -D FORWARD -s 192.168.1.0/24 -j ACCEPT 2>/dev/null || true # L2TP
    
    # Remove NAT rules
    iptables -t nat -D POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE 2>/dev/null || true
    iptables -t nat -D POSTROUTING -s 10.0.0.0/24 -o eth0 -j MASQUERADE 2>/dev/null || true
    iptables -t nat -D POSTROUTING -s 10.10.10.0/24 -o eth0 -j MASQUERADE 2>/dev/null || true
    iptables -t nat -D POSTROUTING -s 192.168.0.0/24 -o eth0 -j MASQUERADE 2>/dev/null || true
    iptables -t nat -D POSTROUTING -s 192.168.1.0/24 -o eth0 -j MASQUERADE 2>/dev/null || true
    
    # Save iptables rules
    case $OS in
        "debian")
            iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
            ;;
        "centos")
            service iptables save 2>/dev/null || true
            ;;
    esac
    
    print_status "Firewall rules cleaned up"
}

# Remove system configurations
cleanup_system() {
    print_header "Cleaning Up System Configuration"
    
    # Remove IP forwarding (ask user)
    if [[ "$DISABLE_IP_FORWARDING" == "yes" ]]; then
        sed -i '/net.ipv4.ip_forward=1/d' /etc/sysctl.conf 2>/dev/null || true
        sed -i '/net.ipv6.conf.all.forwarding=1/d' /etc/sysctl.conf 2>/dev/null || true
        sysctl -p >/dev/null 2>&1 || true
        print_status "IP forwarding disabled"
    fi
    
    # Remove configuration directories
    rm -rf "$CONFIG_DIR"
    rm -rf "$SCRIPT_DIR"
    rm -rf /etc/vpn-config
    rm -rf /var/log/vpn
    
    # Clean up systemd
    systemctl daemon-reload
    
    print_status "System configuration cleaned up"
}

# Interactive uninstallation menu
show_uninstall_menu() {
    clear
    print_header "VPN Auto Uninstaller"
    echo "Select components to remove:"
    echo "1) Remove OpenVPN"
    echo "2) Remove WireGuard"
    echo "3) Remove IPsec/IKEv2"
    echo "4) Remove SoftEther VPN"
    echo "5) Remove PPTP VPN"
    echo "6) Remove L2TP VPN"
    echo "7) Remove Admin Panel"
    echo "8) Remove All VPN Services"
    echo "9) Complete Removal (Everything)"
    echo "0) Exit"
    echo
    read -p "Enter your choice [0-9]: " choice
}

# Main uninstallation function
main() {
    check_root
    detect_os
    
    # Ask about Node.js removal
    echo
    read -p "Do you want to remove Node.js? (y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        REMOVE_NODEJS="yes"
    else
        REMOVE_NODEJS="no"
    fi
    
    # Ask about IP forwarding
    echo
    read -p "Do you want to disable IP forwarding? (y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        DISABLE_IP_FORWARDING="yes"
    else
        DISABLE_IP_FORWARDING="no"
    fi
    
    # Ask about backup
    echo
    read -p "Do you want to backup configurations before removal? (y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        backup_configs
    fi
    
    show_uninstall_menu
    
    case $choice in
        1)
            stop_services
            remove_openvpn
            ;;
        2)
            stop_services
            remove_wireguard
            ;;
        3)
            stop_services
            remove_ipsec
            ;;
        4)
            stop_services
            remove_softether
            ;;
        5)
            stop_services
            remove_pptp
            ;;
        6)
            stop_services
            remove_l2tp
            ;;
        7)
            stop_services
            remove_admin_panel
            remove_nginx_config
            ;;
        8)
            stop_services
            remove_openvpn
            remove_wireguard
            remove_ipsec
            remove_softether
            remove_pptp
            remove_l2tp
            cleanup_firewall
            ;;
        9)
            stop_services
            remove_openvpn
            remove_wireguard
            remove_ipsec
            remove_softether
            remove_pptp
            remove_l2tp
            remove_admin_panel
            remove_nginx_config
            cleanup_firewall
            cleanup_system
            ;;
        0)
            print_status "Exiting..."
            exit 0
            ;;
        *)
            print_error "Invalid option"
            exit 1
            ;;
    esac
    
    print_header "Uninstallation Complete!"
    print_status "Selected components have been removed"
    
    if [[ -n "$BACKUP_DIR" ]]; then
        print_status "Configuration backup saved at: $BACKUP_DIR"
    fi
    
    print_warning "You may want to:"
    print_warning "  - Reboot the system to ensure all changes take effect"
    print_warning "  - Check for any remaining configuration files"
    print_warning "  - Remove unused packages with 'apt autoremove' (Debian/Ubuntu)"
    
    print_status "Uninstallation log: $LOG_FILE"
}

# Confirmation prompt
echo
print_header "VPN Auto Uninstaller"
print_warning "This script will remove VPN services and configurations"
print_warning "Make sure you have backed up any important data"
echo
read -p "Are you sure you want to continue? (yes/no): " confirm

if [[ "$confirm" != "yes" ]]; then
    print_status "Uninstallation cancelled"
    exit 0
fi

# Run main function
main "$@"
