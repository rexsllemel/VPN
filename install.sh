#!/bin/bash

# VPN Auto Installer Script
# Supports: OpenVPN, WireGuard, IPsec/IKEv2, SoftEther, PPTP, L2TP
# Author: VPN Auto Installer
# Version: 2.0

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="/opt/vpn-installer"
LOG_FILE="/var/log/vpn-installer.log"
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

# Update system
update_system() {
    print_status "Updating system packages..."
    case $OS in
        "debian")
            apt-get update && apt-get upgrade -y
            apt-get install -y curl wget unzip iptables-persistent
            ;;
        "centos")
            yum update -y
            yum install -y curl wget unzip iptables-services
            ;;
        "arch")
            pacman -Syu --noconfirm
            pacman -S --noconfirm curl wget unzip iptables
            ;;
    esac
}

# Create directories
create_directories() {
    mkdir -p "$SCRIPT_DIR"
    mkdir -p "$CONFIG_DIR"
    mkdir -p "/var/log/vpn"
}

# Configure firewall
configure_firewall() {
    print_status "Configuring firewall..."
    
    # Enable IP forwarding
    echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
    echo 'net.ipv6.conf.all.forwarding=1' >> /etc/sysctl.conf
    sysctl -p
    
    # Basic iptables rules
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A INPUT -p tcp --dport 22 -j ACCEPT
    iptables -A INPUT -p tcp --dport 80 -j ACCEPT
    iptables -A INPUT -p tcp --dport 443 -j ACCEPT
    
    # Save iptables rules
    case $OS in
        "debian")
            iptables-save > /etc/iptables/rules.v4
            ;;
        "centos")
            service iptables save
            ;;
    esac
}

# Install OpenVPN
install_openvpn() {
    print_header "Installing OpenVPN"
    
    case $OS in
        "debian")
            apt-get install -y openvpn easy-rsa
            ;;
        "centos")
            yum install -y epel-release
            yum install -y openvpn easy-rsa
            ;;
        "arch")
            pacman -S --noconfirm openvpn easy-rsa
            ;;
    esac
    
    # Setup Easy-RSA
    make-cadir /etc/openvpn/easy-rsa
    cd /etc/openvpn/easy-rsa
    
    # Generate CA
    ./easyrsa init-pki
    ./easyrsa --batch build-ca nopass
    ./easyrsa build-server-full server nopass
    ./easyrsa build-client-full client nopass
    ./easyrsa gen-dh
    openvpn --genkey --secret ta.key
    
    # Create server config
    cat > /etc/openvpn/server.conf << 'EOF'
port 1194
proto udp
dev tun
ca easy-rsa/pki/ca.crt
cert easy-rsa/pki/issued/server.crt
key easy-rsa/pki/private/server.key
dh easy-rsa/pki/dh.pem
tls-auth easy-rsa/ta.key 0
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"
keepalive 10 120
cipher AES-256-CBC
user nobody
group nogroup
persist-key
persist-tun
status openvpn-status.log
log openvpn.log
verb 3
EOF
    
    # Configure iptables for OpenVPN
    iptables -A INPUT -p udp --dport 1194 -j ACCEPT
    iptables -A FORWARD -i tun+ -j ACCEPT
    iptables -A FORWARD -i tun+ -o eth0 -m state --state RELATED,ESTABLISHED -j ACCEPT
    iptables -A FORWARD -i eth0 -o tun+ -m state --state RELATED,ESTABLISHED -j ACCEPT
    iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE
    
    # Enable and start OpenVPN
    systemctl enable openvpn@server
    systemctl start openvpn@server
    
    print_status "OpenVPN installed and configured"
}

# Install WireGuard
install_wireguard() {
    print_header "Installing WireGuard"
    
    case $OS in
        "debian")
            apt-get install -y wireguard
            ;;
        "centos")
            yum install -y elrepo-release epel-release
            yum install -y kmod-wireguard wireguard-tools
            ;;
        "arch")
            pacman -S --noconfirm wireguard-tools
            ;;
    esac
    
    # Generate keys
    wg genkey | tee /etc/wireguard/privatekey | wg pubkey > /etc/wireguard/publickey
    wg genkey | tee /etc/wireguard/client_privatekey | wg pubkey > /etc/wireguard/client_publickey
    
    SERVER_PRIVATE_KEY=$(cat /etc/wireguard/privatekey)
    CLIENT_PRIVATE_KEY=$(cat /etc/wireguard/client_privatekey)
    CLIENT_PUBLIC_KEY=$(cat /etc/wireguard/client_publickey)
    SERVER_PUBLIC_KEY=$(cat /etc/wireguard/publickey)
    
    # Create server config
    cat > /etc/wireguard/wg0.conf << EOF
[Interface]
PrivateKey = $SERVER_PRIVATE_KEY
Address = 10.0.0.1/24
ListenPort = 51820
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

[Peer]
PublicKey = $CLIENT_PUBLIC_KEY
AllowedIPs = 10.0.0.2/32
EOF
    
    # Create client config
    cat > /etc/wireguard/client.conf << EOF
[Interface]
PrivateKey = $CLIENT_PRIVATE_KEY
Address = 10.0.0.2/24
DNS = 8.8.8.8

[Peer]
PublicKey = $SERVER_PUBLIC_KEY
Endpoint = $(curl -s ifconfig.me):51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
EOF
    
    # Configure iptables for WireGuard
    iptables -A INPUT -p udp --dport 51820 -j ACCEPT
    
    # Enable and start WireGuard
    systemctl enable wg-quick@wg0
    systemctl start wg-quick@wg0
    
    print_status "WireGuard installed and configured"
}

# Install IPsec/IKEv2
install_ipsec() {
    print_header "Installing IPsec/IKEv2"
    
    case $OS in
        "debian")
            # Install StrongSwan with minimal plugins to avoid loading issues
            apt-get install -y strongswan strongswan-pki libcharon-extra-plugins libcharon-extauth-plugins
            # Disable problematic plugins
            mkdir -p /etc/strongswan.d/charon
            cat > /etc/strongswan.d/charon/disable-plugins.conf << 'EOF'
# Disable optional plugins that may cause loading errors
test-vectors {
    load = no
}
pkcs11 {
    load = no
}
tpm {
    load = no
}
rdrand {
    load = no
}
gcrypt {
    load = no
}
af-alg {
    load = no
}
curve25519 {
    load = no
}
curl {
    load = no
}
EOF
            ;;
        "centos")
            yum install -y strongswan
            ;;
        "arch")
            pacman -S --noconfirm strongswan
            ;;
    esac
    
    # Generate certificates
    mkdir -p /etc/ipsec.d/{cacerts,certs,private}
    
    # Set proper permissions
    chmod 700 /etc/ipsec.d/private
    chmod 755 /etc/ipsec.d/cacerts
    chmod 755 /etc/ipsec.d/certs
    
    # CA certificate
    ipsec pki --gen --type rsa --size 4096 --outform pem > /etc/ipsec.d/private/ca-key.pem
    ipsec pki --self --ca --lifetime 3650 --in /etc/ipsec.d/private/ca-key.pem \
        --type rsa --dn "CN=VPN CA" --outform pem > /etc/ipsec.d/cacerts/ca-cert.pem
    
    # Server certificate
    ipsec pki --gen --type rsa --size 4096 --outform pem > /etc/ipsec.d/private/server-key.pem
    ipsec pki --pub --in /etc/ipsec.d/private/server-key.pem --type rsa \
        | ipsec pki --issue --lifetime 1825 \
        --cacert /etc/ipsec.d/cacerts/ca-cert.pem \
        --cakey /etc/ipsec.d/private/ca-key.pem \
        --dn "CN=$(curl -s ifconfig.me)" --san "@$(curl -s ifconfig.me)" \
        --flag serverAuth --flag ikeIntermediate --outform pem \
        > /etc/ipsec.d/certs/server-cert.pem
    
    # Set proper permissions for certificates
    chmod 600 /etc/ipsec.d/private/*
    chmod 644 /etc/ipsec.d/cacerts/*
    chmod 644 /etc/ipsec.d/certs/*
    
    # Configure IPsec
    cat > /etc/ipsec.conf << 'EOF'
config setup
    charondebug="ike 1, knl 1, cfg 0"
    uniqueids=no
    strictcrlpolicy=no

conn ikev2-vpn
    auto=add
    compress=no
    type=tunnel
    keyexchange=ikev2
    fragmentation=yes
    forceencaps=yes
    dpdaction=clear
    dpddelay=300s
    rekey=no
    left=%any
    leftid=@vpn.example.com
    leftcert=server-cert.pem
    leftsendcert=always
    leftsubnet=0.0.0.0/0
    right=%any
    rightid=%any
    rightauth=eap-mschapv2
    rightsourceip=10.10.10.0/24
    rightdns=8.8.8.8,8.8.4.4
    rightsendcert=never
    eap_identity=%identity
EOF
    
    # Configure secrets
    cat > /etc/ipsec.secrets << 'EOF'
: RSA "server-key.pem"
user1 : EAP "password123"
user2 : EAP "password456"
EOF
    
    # Set proper permissions for secrets
    chmod 600 /etc/ipsec.secrets
    
    # Configure iptables for IPsec
    iptables -A INPUT -p udp --dport 500 -j ACCEPT
    iptables -A INPUT -p udp --dport 4500 -j ACCEPT
    iptables -A INPUT -p esp -j ACCEPT
    iptables -A FORWARD -s 10.10.10.0/24 -j ACCEPT
    iptables -A FORWARD -d 10.10.10.0/24 -j ACCEPT
    iptables -t nat -A POSTROUTING -s 10.10.10.0/24 -o eth0 -j MASQUERADE
    
    # Check if strongswan service exists, if not create it
    if [[ ! -f /lib/systemd/system/strongswan.service ]] && [[ ! -f /etc/systemd/system/strongswan.service ]]; then
        print_warning "Creating StrongSwan systemd service file..."
        cat > /etc/systemd/system/strongswan.service << 'EOF'
[Unit]
Description=strongSwan IPsec IKEv1/IKEv2 daemon using ipsec.conf
After=network-online.target
Wants=network-online.target
Documentation=man:ipsec(8) man:ipsec.conf(5)

[Service]
Type=notify
Restart=on-abnormal
ExecStart=/usr/sbin/ipsec start --nofork
ExecReload=/usr/sbin/ipsec reload
ExecReload=/usr/sbin/ipsec rereadsecrets

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
    fi
    
    # Enable and start IPsec
    systemctl enable strongswan 2>/dev/null || systemctl enable strongswan-starter 2>/dev/null || true
    systemctl start strongswan 2>/dev/null || systemctl start strongswan-starter 2>/dev/null || {
        print_warning "StrongSwan service failed to start, trying manual start..."
        ipsec start
    }
    
    # Verify installation
    sleep 5
    if ipsec status >/dev/null 2>&1; then
        print_status "IPsec/IKEv2 installed and configured successfully"
    else
        print_warning "IPsec/IKEv2 installed but may need manual configuration"
    fi
}

# Install SoftEther VPN
install_softether() {
    print_header "Installing SoftEther VPN"
    
    # Install dependencies
    case $OS in
        "debian")
            apt-get install -y build-essential wget curl gcc make
            ;;
        "centos")
            yum groupinstall -y "Development Tools"
            yum install -y wget curl gcc make
            ;;
        "arch")
            pacman -S --noconfirm base-devel wget curl gcc make
            ;;
    esac
    
    # Download and compile SoftEther
    cd /tmp
    wget https://www.softether-download.com/files/softether/v4.41-9787-rtm-2023.03.14-tree/Linux/SoftEther_VPN_Server/64bit_-_Intel_x64_or_AMD64/softether-vpnserver-v4.41-9787-rtm-2023.03.14-linux-x64-64bit.tar.gz
    tar xzf softether-vpnserver-*.tar.gz
    cd vpnserver
    make
    
    # Install SoftEther
    mv /tmp/vpnserver /opt/
    chmod 600 /opt/vpnserver/*
    chmod 700 /opt/vpnserver/vpnserver
    chmod 700 /opt/vpnserver/vpncmd
    
    # Create systemd service
    cat > /etc/systemd/system/softether-vpnserver.service << 'EOF'
[Unit]
Description=SoftEther VPN Server
After=network.target

[Service]
Type=forking
ExecStart=/opt/vpnserver/vpnserver start
ExecStop=/opt/vpnserver/vpnserver stop
KillMode=process
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF
    
    # Configure iptables for SoftEther
    iptables -A INPUT -p tcp --dport 443 -j ACCEPT
    iptables -A INPUT -p tcp --dport 992 -j ACCEPT
    iptables -A INPUT -p tcp --dport 1194 -j ACCEPT
    iptables -A INPUT -p udp --dport 1194 -j ACCEPT
    
    # Enable and start SoftEther
    systemctl daemon-reload
    systemctl enable softether-vpnserver
    systemctl start softether-vpnserver
    
    print_status "SoftEther VPN installed and configured"
}

# Install PPTP VPN
install_pptp() {
    print_header "Installing PPTP VPN"
    
    case $OS in
        "debian")
            apt-get install -y pptpd
            ;;
        "centos")
            yum install -y pptpd
            ;;
        "arch")
            pacman -S --noconfirm pptpd
            ;;
    esac
    
    # Configure PPTP
    cat > /etc/pptpd.conf << 'EOF'
option /etc/ppp/pptpd-options
logwtmp
localip 192.168.0.1
remoteip 192.168.0.100-200
EOF
    
    cat > /etc/ppp/pptpd-options << 'EOF'
name pptpd
refuse-pap
refuse-chap
refuse-mschap
require-mschap-v2
require-mppe-128
proxyarp
nodefaultroute
lock
nobsdcomp
ms-dns 8.8.8.8
ms-dns 8.8.4.4
EOF
    
    # Add user
    echo "user1 pptpd password123 *" >> /etc/ppp/chap-secrets
    
    # Configure iptables for PPTP
    iptables -A INPUT -p tcp --dport 1723 -j ACCEPT
    iptables -A INPUT -p gre -j ACCEPT
    iptables -A FORWARD -s 192.168.0.0/24 -j ACCEPT
    iptables -A FORWARD -d 192.168.0.0/24 -j ACCEPT
    iptables -t nat -A POSTROUTING -s 192.168.0.0/24 -o eth0 -j MASQUERADE
    
    # Enable and start PPTP
    systemctl enable pptpd
    systemctl start pptpd
    
    print_status "PPTP VPN installed and configured"
}

# Install L2TP VPN
install_l2tp() {
    print_header "Installing L2TP VPN"
    
    case $OS in
        "debian")
            apt-get install -y xl2tpd strongswan
            ;;
        "centos")
            yum install -y xl2tpd strongswan
            ;;
        "arch")
            pacman -S --noconfirm xl2tpd strongswan
            ;;
    esac
    
    # Configure xl2tpd
    cat > /etc/xl2tpd/xl2tpd.conf << 'EOF'
[global]
ipsec saref = yes
saref refinfo = 30

[lns default]
ip range = 192.168.1.100-192.168.1.200
local ip = 192.168.1.1
refuse chap = yes
refuse pap = yes
require authentication = yes
name = l2tpd
ppp debug = yes
pppoptfile = /etc/ppp/options.xl2tpd
length bit = yes
EOF
    
    cat > /etc/ppp/options.xl2tpd << 'EOF'
ipcp-accept-local
ipcp-accept-remote
ms-dns 8.8.8.8
ms-dns 8.8.4.4
noccp
auth
crtscts
idle 1800
mtu 1410
mru 1410
nodefaultroute
debug
proxyarp
connect-delay 5000
EOF
    
    # Configure IPsec for L2TP
    cat > /etc/ipsec.conf << 'EOF'
version 2.0

config setup
    nat_traversal=yes
    virtual_private=%v4:10.0.0.0/8,%v4:192.168.0.0/16,%v4:172.16.0.0/12,%v4:25.0.0.0/8,%v6:fd00::/8,%v6:fe80::/10

conn L2TP-PSK-NAT
    rightsubnet=vhost:%priv
    also=L2TP-PSK-noNAT

conn L2TP-PSK-noNAT
    authby=secret
    pfs=no
    auto=add
    keyingtries=3
    rekey=no
    ikelifetime=8h
    keylife=1h
    type=transport
    left=%defaultroute
    leftprotoport=17/1701
    right=%any
    rightprotoport=17/%any
EOF
    
    # Add PSK
    echo "$(curl -s ifconfig.me) %any: PSK \"your_psk_here\"" > /etc/ipsec.secrets
    
    # Add L2TP user
    echo "user1 l2tpd password123 *" >> /etc/ppp/chap-secrets
    
    # Configure iptables for L2TP
    iptables -A INPUT -p udp --dport 500 -j ACCEPT
    iptables -A INPUT -p udp --dport 4500 -j ACCEPT
    iptables -A INPUT -p udp --dport 1701 -j ACCEPT
    iptables -A FORWARD -s 192.168.1.0/24 -j ACCEPT
    iptables -A FORWARD -d 192.168.1.0/24 -j ACCEPT
    iptables -t nat -A POSTROUTING -s 192.168.1.0/24 -o eth0 -j MASQUERADE
    
    # Enable and start services
    systemctl enable strongswan
    systemctl enable xl2tpd
    systemctl start strongswan
    systemctl start xl2tpd
    
    print_status "L2TP VPN installed and configured"
}

# Generate client configs
generate_client_configs() {
    print_header "Generating Client Configuration Files"
    
    mkdir -p "$CONFIG_DIR/clients"
    
    # OpenVPN client config
    if systemctl is-active --quiet openvpn@server; then
        cat > "$CONFIG_DIR/clients/client.ovpn" << EOF
client
dev tun
proto udp
remote $(curl -s ifconfig.me) 1194
resolv-retry infinite
nobind
persist-key
persist-tun
ca ca.crt
cert client.crt
key client.key
tls-auth ta.key 1
cipher AES-256-CBC
verb 3
EOF
        
        # Copy certificates
        cp /etc/openvpn/easy-rsa/pki/ca.crt "$CONFIG_DIR/clients/"
        cp /etc/openvpn/easy-rsa/pki/issued/client.crt "$CONFIG_DIR/clients/"
        cp /etc/openvpn/easy-rsa/pki/private/client.key "$CONFIG_DIR/clients/"
        cp /etc/openvpn/easy-rsa/ta.key "$CONFIG_DIR/clients/"
    fi
    
    # WireGuard client config
    if [[ -f /etc/wireguard/client.conf ]]; then
        cp /etc/wireguard/client.conf "$CONFIG_DIR/clients/"
    fi
    
    print_status "Client configuration files generated in $CONFIG_DIR/clients/"
}

# Install admin panel dependencies
install_admin_panel() {
    print_header "Installing Admin Panel"
    
    # Install Node.js and npm
    case $OS in
        "debian")
            curl -fsSL https://deb.nodesource.com/setup_18.x | bash -
            apt-get install -y nodejs
            ;;
        "centos")
            curl -fsSL https://rpm.nodesource.com/setup_18.x | bash -
            yum install -y nodejs npm
            ;;
        "arch")
            pacman -S --noconfirm nodejs npm
            ;;
    esac
    
    # Create admin panel directory
    mkdir -p /opt/vpn-admin
    cd /opt/vpn-admin
    
    # Download admin panel files (will be created separately)
    print_status "Admin panel dependencies installed"
    print_status "Admin panel will be available at: http://$(curl -s ifconfig.me):3000"
}

# Troubleshoot and fix common VPN issues
troubleshoot_vpn() {
    print_header "VPN Troubleshooting"
    
    print_status "Checking VPN services status..."
    
    # Check OpenVPN
    if systemctl is-active --quiet openvpn@server 2>/dev/null; then
        print_status "OpenVPN: Running"
    elif [[ -f /etc/openvpn/server.conf ]]; then
        print_warning "OpenVPN: Installed but not running"
        systemctl restart openvpn@server 2>/dev/null || print_error "Failed to start OpenVPN"
    fi
    
    # Check WireGuard
    if systemctl is-active --quiet wg-quick@wg0 2>/dev/null; then
        print_status "WireGuard: Running"
    elif [[ -f /etc/wireguard/wg0.conf ]]; then
        print_warning "WireGuard: Installed but not running"
        systemctl restart wg-quick@wg0 2>/dev/null || print_error "Failed to start WireGuard"
    fi
    
    # Check StrongSwan/IPsec
    if ipsec status >/dev/null 2>&1; then
        print_status "IPsec/IKEv2: Running"
    elif [[ -f /etc/ipsec.conf ]]; then
        print_warning "IPsec/IKEv2: Installed but not running, attempting to fix..."
        
        # Try different start methods
        if systemctl restart strongswan 2>/dev/null; then
            print_status "StrongSwan started via systemctl"
        elif systemctl restart strongswan-starter 2>/dev/null; then
            print_status "StrongSwan started via strongswan-starter"
        elif ipsec restart 2>/dev/null; then
            print_status "StrongSwan started via ipsec command"
        else
            print_error "Failed to start StrongSwan, trying manual fix..."
            
            # Manual configuration fix
            print_status "Applying StrongSwan fixes..."
            
            # Ensure proper permissions
            chmod 600 /etc/ipsec.secrets
            chmod 600 /etc/ipsec.d/private/*
            chown root:root /etc/ipsec.d/private/*
            
            # Try starting manually
            if ipsec start 2>/dev/null; then
                print_status "StrongSwan started manually"
            else
                print_error "Unable to start StrongSwan. Check logs with: journalctl -u strongswan"
            fi
        fi
    fi
    
    # Check other services
    services=("softether-vpnserver" "pptpd" "xl2tpd")
    for service in "${services[@]}"; do
        if systemctl is-active --quiet "$service" 2>/dev/null; then
            print_status "$service: Running"
        elif systemctl is-enabled --quiet "$service" 2>/dev/null; then
            print_warning "$service: Installed but not running"
            systemctl restart "$service" 2>/dev/null || print_error "Failed to start $service"
        fi
    done
    
    # Check IP forwarding
    if [[ $(sysctl -n net.ipv4.ip_forward) == "1" ]]; then
        print_status "IP forwarding: Enabled"
    else
        print_warning "IP forwarding: Disabled, enabling..."
        echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
        sysctl -p
    fi
    
    # Check iptables rules
    if iptables -t nat -L POSTROUTING | grep -q MASQUERADE; then
        print_status "NAT rules: Configured"
    else
        print_warning "NAT rules: Missing, adding basic rules..."
        iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
        iptables -A FORWARD -i tun+ -j ACCEPT
        iptables -A FORWARD -i wg+ -j ACCEPT
    fi
    
    print_status "Troubleshooting completed"
}

# Main menu
show_menu() {
    clear
    print_header "VPN Auto Installer"
    echo "Select VPN type to install:"
    echo "1) OpenVPN"
    echo "2) WireGuard"
    echo "3) IPsec/IKEv2"
    echo "4) SoftEther VPN"
    echo "5) PPTP VPN"
    echo "6) L2TP VPN"
    echo "7) Install All VPNs"
    echo "8) Install Admin Panel"
    echo "9) Generate Client Configs"
    echo "10) Troubleshoot VPN Issues"
    echo "0) Exit"
    echo
    read -p "Enter your choice [0-9]: " choice
}

# Save installation info
save_install_info() {
    cat > "$CONFIG_DIR/install_info.txt" << EOF
VPN Installation Summary
========================
Installation Date: $(date)
Server IP: $(curl -s ifconfig.me)
Installed VPNs: $INSTALLED_VPNS

Connection Details:
==================
$CONNECTION_INFO

Configuration Files Location: $CONFIG_DIR/clients/

Admin Panel: http://$(curl -s ifconfig.me):3000
EOF
    
    print_status "Installation summary saved to $CONFIG_DIR/install_info.txt"
}

# Main execution
main() {
    check_root
    detect_os
    create_directories
    update_system
    configure_firewall
    
    INSTALLED_VPNS=""
    CONNECTION_INFO=""
    
    show_menu
    
    case $choice in
        1)
            install_openvpn
            INSTALLED_VPNS="OpenVPN"
            CONNECTION_INFO="OpenVPN: $(curl -s ifconfig.me):1194 (UDP)"
            ;;
        2)
            install_wireguard
            INSTALLED_VPNS="WireGuard"
            CONNECTION_INFO="WireGuard: $(curl -s ifconfig.me):51820 (UDP)"
            ;;
        3)
            install_ipsec
            INSTALLED_VPNS="IPsec/IKEv2"
            CONNECTION_INFO="IPsec/IKEv2: $(curl -s ifconfig.me):500,4500 (UDP)"
            ;;
        4)
            install_softether
            INSTALLED_VPNS="SoftEther"
            CONNECTION_INFO="SoftEther: $(curl -s ifconfig.me):443,992,1194 (TCP/UDP)"
            ;;
        5)
            install_pptp
            INSTALLED_VPNS="PPTP"
            CONNECTION_INFO="PPTP: $(curl -s ifconfig.me):1723 (TCP)"
            ;;
        6)
            install_l2tp
            INSTALLED_VPNS="L2TP"
            CONNECTION_INFO="L2TP: $(curl -s ifconfig.me):500,4500,1701 (UDP)"
            ;;
        7)
            install_openvpn
            install_wireguard
            install_ipsec
            install_softether
            install_pptp
            install_l2tp
            INSTALLED_VPNS="All VPNs"
            CONNECTION_INFO="All VPN protocols installed"
            ;;
        8)
            install_admin_panel
            ;;
        9)
            generate_client_configs
            ;;
        10)
            troubleshoot_vpn
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
    
    if [[ ! -z "$INSTALLED_VPNS" ]]; then
        generate_client_configs
        save_install_info
        
        print_header "Installation Complete!"
        print_status "VPN services installed: $INSTALLED_VPNS"
        print_status "Server IP: $(curl -s ifconfig.me)"
        print_status "Configuration files: $CONFIG_DIR/clients/"
        print_warning "Please change default passwords and PSKs!"
        print_status "Installation summary: $CONFIG_DIR/install_info.txt"
    fi
}

# Run main function
main "$@"
