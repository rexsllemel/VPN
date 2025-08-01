# VPN Server Deployment Guide

## Quick Start (1-Minute Setup)

### Method 1: One-Line Installation
```bash
curl -fsSL https://your-domain.com/quick-install.sh | sudo bash
```

### Method 2: Manual Download
```bash
# Download files
wget https://your-domain.com/vpn-installer.tar.gz
tar -xzf vpn-installer.tar.gz
cd vpn-installer

# Run installer
sudo ./install.sh
```

## Pre-Installation Checklist

- [ ] Fresh Linux VPS/Server (Ubuntu 20.04+ recommended)
- [ ] Root access or sudo privileges
- [ ] Public IP address
- [ ] At least 1GB RAM and 10GB storage
- [ ] Ports 22, 80, 443 accessible

## Step-by-Step Installation

### 1. Prepare Your Server
```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install curl and wget
sudo apt install curl wget -y
```

### 2. Download and Run Installer
```bash
# Make installer executable
chmod +x install.sh install-admin-panel.sh

# Install VPN server
sudo ./install.sh

# Install admin panel
sudo ./install-admin-panel.sh
```

### 3. Configure Firewall (if needed)
```bash
# Ubuntu/Debian with UFW
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw allow 1194/udp  # OpenVPN
sudo ufw allow 51820/udp # WireGuard
sudo ufw --force enable

# CentOS/RHEL with firewalld
sudo firewall-cmd --permanent --add-port=80/tcp
sudo firewall-cmd --permanent --add-port=443/tcp
sudo firewall-cmd --permanent --add-port=1194/udp
sudo firewall-cmd --permanent --add-port=51820/udp
sudo firewall-cmd --reload
```

### 4. Access Admin Panel
1. Open browser: `http://YOUR_SERVER_IP:3000`
2. Login with: `admin` / `admin123`
3. Change default password immediately

## Post-Installation Tasks

### 1. Secure Your Installation
- [ ] Change admin panel password
- [ ] Update VPN user passwords
- [ ] Configure SSL certificate
- [ ] Set up regular backups

### 2. Test VPN Connections
- [ ] Download client configurations
- [ ] Test OpenVPN connection
- [ ] Test WireGuard connection
- [ ] Verify internet access through VPN

### 3. Monitor and Maintain
- [ ] Check system logs regularly
- [ ] Monitor resource usage
- [ ] Update system packages monthly
- [ ] Backup configurations

## Production Deployment

### 1. Domain and SSL Setup
```bash
# Point your domain to server IP
# A record: vpn.yourdomain.com -> YOUR_SERVER_IP

# Install SSL certificate
sudo certbot --nginx -d vpn.yourdomain.com
```

### 2. Nginx Configuration
```bash
# Edit nginx config for your domain
sudo nano /etc/nginx/sites-available/vpn-admin

# Update server_name
server_name vpn.yourdomain.com;

# Restart nginx
sudo systemctl restart nginx
```

### 3. Advanced Security
```bash
# Disable root login
sudo sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config

# Setup fail2ban
sudo apt install fail2ban -y

# Configure automatic updates
sudo apt install unattended-upgrades -y
```

## Hosting Your Installer

### Option 1: GitHub Pages
1. Fork this repository
2. Enable GitHub Pages
3. Your installer URL: `https://username.github.io/vpn-installer/quick-install.sh`

### Option 2: Your Own Server
```bash
# On your web server
sudo mkdir -p /var/www/html/vpn
sudo cp -r * /var/www/html/vpn/
sudo chown -R www-data:www-data /var/www/html/vpn

# Access via: https://yourdomain.com/vpn/quick-install.sh
```

### Option 3: CDN/Cloud Storage
- Upload files to AWS S3, Google Cloud Storage, or similar
- Make files publicly accessible
- Use CDN URLs in installation commands

## Troubleshooting

### Installation Fails
```bash
# Check system requirements
cat /etc/os-release
free -h
df -h

# Check internet connectivity
ping -c 4 8.8.8.8
curl -I google.com

# Run installer with verbose output
sudo bash -x ./install.sh
```

### Services Not Starting
```bash
# Check service status
sudo systemctl status openvpn@server
sudo systemctl status vpn-admin

# View logs
sudo journalctl -u openvpn@server -f
sudo journalctl -u vpn-admin -f
```

### Can't Access Admin Panel
```bash
# Check if process is running
sudo netstat -tlnp | grep 3000

# Check firewall
sudo iptables -L | grep 3000
sudo ufw status

# Test local access
curl http://localhost:3000
```

## Scaling and Performance

### Multiple Servers
- Use the same installer on multiple servers
- Configure load balancer
- Sync user databases

### High Availability
- Set up server clustering
- Use external database
- Configure automatic failover

### Performance Tuning
```bash
# Increase file limits
echo "* soft nofile 65536" >> /etc/security/limits.conf
echo "* hard nofile 65536" >> /etc/security/limits.conf

# Optimize kernel parameters
echo "net.core.rmem_default = 262144" >> /etc/sysctl.conf
echo "net.core.rmem_max = 16777216" >> /etc/sysctl.conf
echo "net.core.wmem_default = 262144" >> /etc/sysctl.conf
echo "net.core.wmem_max = 16777216" >> /etc/sysctl.conf
```

## Backup and Recovery

### Backup Script
```bash
#!/bin/bash
BACKUP_DIR="/backup/vpn-$(date +%Y%m%d)"
mkdir -p "$BACKUP_DIR"

# Backup configurations
cp -r /etc/openvpn "$BACKUP_DIR/"
cp -r /etc/wireguard "$BACKUP_DIR/"
cp -r /etc/vpn-config "$BACKUP_DIR/"
cp -r /opt/vpn-admin "$BACKUP_DIR/"

# Create archive
tar -czf "$BACKUP_DIR.tar.gz" "$BACKUP_DIR"
rm -rf "$BACKUP_DIR"
```

### Automated Backups
```bash
# Add to crontab
echo "0 2 * * * /root/backup-vpn.sh" | sudo crontab -
```

## Support and Updates

### Getting Help
1. Check logs: `/var/log/vpn-installer.log`
2. Review documentation: `README.md`
3. Check GitHub issues
4. Contact support

### Updates
```bash
# Download latest version
wget https://your-domain.com/vpn-installer.tar.gz

# Backup current installation
sudo /root/backup-vpn.sh

# Run update
sudo ./install.sh
```

## Cost Optimization

### Cloud Provider Recommendations
- **DigitalOcean**: $5/month droplet
- **Vultr**: $3.50/month VPS
- **Linode**: $5/month Nanode
- **AWS**: t3.micro with free tier
- **Google Cloud**: e2-micro with free tier

### Resource Monitoring
```bash
# Monitor CPU and memory
htop

# Check disk usage
df -h

# Monitor network
iftop

# Check VPN connections
sudo wg show  # WireGuard
sudo cat /var/log/openvpn-status.log  # OpenVPN
```
