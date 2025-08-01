#!/bin/bash

# VPN Admin Panel Installer
# This script installs and configures the VPN Admin Panel

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
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
    elif [[ -f /etc/debian_version ]]; then
        OS="debian"
    elif [[ -f /etc/arch-release ]]; then
        OS="arch"
    else
        print_error "Unsupported operating system"
        exit 1
    fi
    print_status "Detected OS: $OS"
}

# Install Node.js
install_nodejs() {
    print_status "Installing Node.js..."
    
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
    
    # Verify installation
    node_version=$(node --version)
    npm_version=$(npm --version)
    print_status "Node.js version: $node_version"
    print_status "NPM version: $npm_version"
}

# Create admin panel user
create_admin_user() {
    print_status "Creating admin panel user..."
    
    if ! id "vpnadmin" &>/dev/null; then
        useradd -r -s /bin/bash -d /opt/vpn-admin -m vpnadmin
        print_status "Created user: vpnadmin"
    else
        print_warning "User vpnadmin already exists"
    fi
}

# Download and setup admin panel
setup_admin_panel() {
    print_status "Setting up VPN Admin Panel..."
    
    # Create directory
    mkdir -p /opt/vpn-admin
    cd /opt/vpn-admin
    
    # Download admin panel files (assuming they're in the same directory as the script)
    if [[ -f "$(dirname "$0")/admin-panel/package.json" ]]; then
        cp -r "$(dirname "$0")/admin-panel/"* /opt/vpn-admin/
    else
        print_error "Admin panel files not found"
        exit 1
    fi
    
    # Set permissions
    chown -R vpnadmin:vpnadmin /opt/vpn-admin
    chmod +x /opt/vpn-admin/server.js
    
    # Install dependencies
    print_status "Installing Node.js dependencies..."
    sudo -u vpnadmin npm install
}

# Create systemd service
create_systemd_service() {
    print_status "Creating systemd service..."
    
    cat > /etc/systemd/system/vpn-admin.service << 'EOF'
[Unit]
Description=VPN Admin Panel
After=network.target

[Service]
Type=simple
User=vpnadmin
WorkingDirectory=/opt/vpn-admin
ExecStart=/usr/bin/node server.js
Restart=always
RestartSec=10
Environment=NODE_ENV=production

[Install]
WantedBy=multi-user.target
EOF
    
    # Reload systemd and enable service
    systemctl daemon-reload
    systemctl enable vpn-admin
    
    print_status "Systemd service created and enabled"
}

# Configure firewall
configure_firewall() {
    print_status "Configuring firewall for admin panel..."
    
    # Allow port 3000
    iptables -A INPUT -p tcp --dport 3000 -j ACCEPT
    
    # Save iptables rules
    case $OS in
        "debian")
            iptables-save > /etc/iptables/rules.v4
            ;;
        "centos")
            service iptables save
            ;;
    esac
    
    print_status "Firewall configured to allow port 3000"
}

# Create nginx configuration (optional)
setup_nginx() {
    print_status "Setting up Nginx reverse proxy..."
    
    case $OS in
        "debian")
            apt-get install -y nginx
            ;;
        "centos")
            yum install -y nginx
            ;;
        "arch")
            pacman -S --noconfirm nginx
            ;;
    esac
    
    # Create nginx configuration
    cat > /etc/nginx/sites-available/vpn-admin << 'EOF'
server {
    listen 80;
    server_name _;
    
    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
    }
}
EOF
    
    # Enable site
    if [[ -d "/etc/nginx/sites-enabled" ]]; then
        ln -sf /etc/nginx/sites-available/vpn-admin /etc/nginx/sites-enabled/
        rm -f /etc/nginx/sites-enabled/default
    else
        # CentOS/RHEL
        cp /etc/nginx/sites-available/vpn-admin /etc/nginx/conf.d/vpn-admin.conf
    fi
    
    # Test nginx configuration
    nginx -t
    
    # Enable and start nginx
    systemctl enable nginx
    systemctl restart nginx
    
    print_status "Nginx reverse proxy configured"
}

# Generate SSL certificate with Let's Encrypt (optional)
setup_ssl() {
    read -p "Do you want to setup SSL with Let's Encrypt? (y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        read -p "Enter your domain name: " domain_name
        
        case $OS in
            "debian")
                apt-get install -y certbot python3-certbot-nginx
                ;;
            "centos")
                yum install -y certbot python3-certbot-nginx
                ;;
            "arch")
                pacman -S --noconfirm certbot certbot-nginx
                ;;
        esac
        
        # Get SSL certificate
        certbot --nginx -d "$domain_name" --non-interactive --agree-tos --email admin@"$domain_name"
        
        print_status "SSL certificate installed for $domain_name"
    fi
}

# Start services
start_services() {
    print_status "Starting VPN Admin Panel..."
    
    # Start admin panel
    systemctl start vpn-admin
    
    # Check status
    if systemctl is-active --quiet vpn-admin; then
        print_status "VPN Admin Panel started successfully"
    else
        print_error "Failed to start VPN Admin Panel"
        systemctl status vpn-admin
        exit 1
    fi
}

# Main installation
main() {
    print_header "VPN Admin Panel Installer"
    
    check_root
    detect_os
    
    # Ask for nginx setup
    read -p "Do you want to setup Nginx reverse proxy? (y/n): " -n 1 -r
    echo
    setup_nginx_flag=$REPLY
    
    install_nodejs
    create_admin_user
    setup_admin_panel
    create_systemd_service
    configure_firewall
    
    if [[ $setup_nginx_flag =~ ^[Yy]$ ]]; then
        setup_nginx
        setup_ssl
    fi
    
    start_services
    
    print_header "Installation Complete!"
    
    SERVER_IP=$(curl -s ifconfig.me 2>/dev/null || echo "your-server-ip")
    
    if [[ $setup_nginx_flag =~ ^[Yy]$ ]]; then
        print_status "VPN Admin Panel is running at: http://$SERVER_IP"
    else
        print_status "VPN Admin Panel is running at: http://$SERVER_IP:3000"
    fi
    
    print_status "Default login credentials:"
    print_status "Username: admin"
    print_status "Password: admin123"
    print_warning "Please change the default password after first login!"
    
    print_status "Service commands:"
    print_status "  Start: systemctl start vpn-admin"
    print_status "  Stop: systemctl stop vpn-admin"
    print_status "  Restart: systemctl restart vpn-admin"
    print_status "  Status: systemctl status vpn-admin"
    print_status "  Logs: journalctl -u vpn-admin -f"
}

# Run main function
main "$@"
