#!/bin/bash

# StrongSwan IPsec/IKEv2 Fix Script
# Fixes common StrongSwan installation and plugin issues

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
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

print_header() {
    echo -e "${GREEN}================================${NC}"
    echo -e "${GREEN}$1${NC}"
    echo -e "${GREEN}================================${NC}"
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    print_error "This script must be run as root (use sudo)"
    exit 1
fi

print_header "StrongSwan IPsec/IKEv2 Fix Tool"

# Stop any running StrongSwan processes
print_status "Stopping existing StrongSwan processes..."
systemctl stop strongswan 2>/dev/null || true
systemctl stop strongswan-starter 2>/dev/null || true
ipsec stop 2>/dev/null || true
killall charon 2>/dev/null || true
killall starter 2>/dev/null || true

# Fix plugin loading issues
print_status "Fixing plugin loading issues..."
mkdir -p /etc/strongswan.d/charon

cat > /etc/strongswan.d/charon/disable-plugins.conf << 'EOF'
# Disable problematic plugins that may cause loading errors
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
ldap {
    load = no
}
mysql {
    load = no
}
sqlite {
    load = no
}
EOF

# Set correct permissions for StrongSwan files
print_status "Setting correct file permissions..."
if [[ -d /etc/ipsec.d ]]; then
    chmod 755 /etc/ipsec.d
    chmod 755 /etc/ipsec.d/cacerts
    chmod 755 /etc/ipsec.d/certs
    chmod 700 /etc/ipsec.d/private
    
    # Set permissions for certificate files
    if [[ -n "$(ls -A /etc/ipsec.d/private 2>/dev/null)" ]]; then
        chmod 600 /etc/ipsec.d/private/*
        chown root:root /etc/ipsec.d/private/*
    fi
    
    if [[ -n "$(ls -A /etc/ipsec.d/cacerts 2>/dev/null)" ]]; then
        chmod 644 /etc/ipsec.d/cacerts/*
        chown root:root /etc/ipsec.d/cacerts/*
    fi
    
    if [[ -n "$(ls -A /etc/ipsec.d/certs 2>/dev/null)" ]]; then
        chmod 644 /etc/ipsec.d/certs/*
        chown root:root /etc/ipsec.d/certs/*
    fi
fi

if [[ -f /etc/ipsec.secrets ]]; then
    chmod 600 /etc/ipsec.secrets
    chown root:root /etc/ipsec.secrets
fi

if [[ -f /etc/ipsec.conf ]]; then
    chmod 644 /etc/ipsec.conf
    chown root:root /etc/ipsec.conf
fi

# Create systemd service if it doesn't exist
if [[ ! -f /lib/systemd/system/strongswan.service ]] && [[ ! -f /etc/systemd/system/strongswan.service ]]; then
    print_status "Creating StrongSwan systemd service..."
    
    cat > /etc/systemd/system/strongswan.service << 'EOF'
[Unit]
Description=strongSwan IPsec IKEv1/IKEv2 daemon using ipsec.conf
After=network-online.target
Wants=network-online.target
Documentation=man:ipsec(8) man:ipsec.conf(5)

[Service]
Type=notify
Restart=on-abnormal
RestartSec=2
ExecStart=/usr/sbin/ipsec start --nofork
ExecReload=/usr/sbin/ipsec reload
ExecReload=/usr/sbin/ipsec rereadsecrets
KillMode=mixed

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
fi

# Update StrongSwan configuration
print_status "Updating StrongSwan configuration..."

# Backup existing config
if [[ -f /etc/ipsec.conf ]]; then
    cp /etc/ipsec.conf /etc/ipsec.conf.backup.$(date +%Y%m%d-%H%M%S)
fi

# Create a minimal working configuration if it doesn't exist
if [[ ! -f /etc/ipsec.conf ]] || [[ ! -s /etc/ipsec.conf ]]; then
    print_status "Creating basic IPsec configuration..."
    
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
    leftid=@vpn-server
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
fi

# Create basic secrets file if it doesn't exist
if [[ ! -f /etc/ipsec.secrets ]] || [[ ! -s /etc/ipsec.secrets ]]; then
    print_status "Creating basic IPsec secrets..."
    
    cat > /etc/ipsec.secrets << 'EOF'
: RSA "server-key.pem"
user1 : EAP "password123"
user2 : EAP "password456"
EOF
    chmod 600 /etc/ipsec.secrets
fi

# Generate certificates if they don't exist
if [[ ! -f /etc/ipsec.d/certs/server-cert.pem ]] || [[ ! -f /etc/ipsec.d/private/server-key.pem ]]; then
    print_status "Generating missing certificates..."
    
    mkdir -p /etc/ipsec.d/{cacerts,certs,private}
    
    # CA certificate
    if [[ ! -f /etc/ipsec.d/private/ca-key.pem ]]; then
        ipsec pki --gen --type rsa --size 4096 --outform pem > /etc/ipsec.d/private/ca-key.pem
        ipsec pki --self --ca --lifetime 3650 --in /etc/ipsec.d/private/ca-key.pem \
            --type rsa --dn "CN=VPN CA" --outform pem > /etc/ipsec.d/cacerts/ca-cert.pem
    fi
    
    # Server certificate
    if [[ ! -f /etc/ipsec.d/private/server-key.pem ]]; then
        SERVER_IP=$(curl -s ifconfig.me 2>/dev/null || echo "192.168.1.100")
        ipsec pki --gen --type rsa --size 4096 --outform pem > /etc/ipsec.d/private/server-key.pem
        ipsec pki --pub --in /etc/ipsec.d/private/server-key.pem --type rsa \
            | ipsec pki --issue --lifetime 1825 \
            --cacert /etc/ipsec.d/cacerts/ca-cert.pem \
            --cakey /etc/ipsec.d/private/ca-key.pem \
            --dn "CN=$SERVER_IP" --san "@$SERVER_IP" \
            --flag serverAuth --flag ikeIntermediate --outform pem \
            > /etc/ipsec.d/certs/server-cert.pem
    fi
fi

# Configure firewall rules
print_status "Configuring firewall rules..."
iptables -A INPUT -p udp --dport 500 -j ACCEPT 2>/dev/null || true
iptables -A INPUT -p udp --dport 4500 -j ACCEPT 2>/dev/null || true
iptables -A INPUT -p esp -j ACCEPT 2>/dev/null || true
iptables -A FORWARD -s 10.10.10.0/24 -j ACCEPT 2>/dev/null || true
iptables -A FORWARD -d 10.10.10.0/24 -j ACCEPT 2>/dev/null || true
iptables -t nat -A POSTROUTING -s 10.10.10.0/24 -o eth0 -j MASQUERADE 2>/dev/null || true

# Enable IP forwarding
echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf 2>/dev/null || true
sysctl -p >/dev/null 2>&1 || true

# Try to start StrongSwan
print_status "Starting StrongSwan..."

# Enable service
systemctl enable strongswan 2>/dev/null || systemctl enable strongswan-starter 2>/dev/null || true

# Try different start methods
if systemctl start strongswan 2>/dev/null; then
    print_status "StrongSwan started successfully via systemctl"
elif systemctl start strongswan-starter 2>/dev/null; then
    print_status "StrongSwan started successfully via strongswan-starter"
elif ipsec start 2>/dev/null; then
    print_status "StrongSwan started successfully via ipsec command"
else
    print_warning "Failed to start StrongSwan normally, trying manual start..."
    
    # Kill any remaining processes
    killall charon 2>/dev/null || true
    sleep 2
    
    # Start manually
    if /usr/lib/ipsec/starter --daemon charon --nofork &>/dev/null &; then
        sleep 3
        if ipsec status >/dev/null 2>&1; then
            print_status "StrongSwan started manually"
        else
            print_error "Failed to start StrongSwan manually"
        fi
    else
        print_error "All start methods failed"
    fi
fi

# Verify installation
sleep 5
print_status "Verifying StrongSwan status..."

if ipsec status >/dev/null 2>&1; then
    print_status "✓ StrongSwan is running"
    ipsec statusall | head -20
elif systemctl is-active strongswan >/dev/null 2>&1; then
    print_status "✓ StrongSwan service is active"
elif systemctl is-active strongswan-starter >/dev/null 2>&1; then
    print_status "✓ StrongSwan-starter service is active"
else
    print_warning "StrongSwan may not be running properly"
    print_status "Check logs with: journalctl -u strongswan -f"
    print_status "Or try manual start: ipsec start"
fi

# Show connection information
if [[ -f /etc/ipsec.conf ]]; then
    SERVER_IP=$(curl -s ifconfig.me 2>/dev/null || echo "your-server-ip")
    print_header "IPsec/IKEv2 Connection Information"
    echo "Server: $SERVER_IP"
    echo "Ports: 500/UDP, 4500/UDP"
    echo "Protocol: IKEv2"
    echo "Auth: EAP-MSCHAPv2"
    echo ""
    echo "Test users (change these passwords!):"
    grep "EAP" /etc/ipsec.secrets | while read line; do
        echo "  $line"
    done
fi

print_header "StrongSwan Fix Complete"
print_status "StrongSwan should now be working properly"
print_warning "Remember to:"
print_warning "  1. Change default user passwords"
print_warning "  2. Configure your firewall properly"
print_warning "  3. Test connections from client devices"
