# VPN Auto Installer & Admin Panel

A comprehensive VPN server installer and web-based admin panel that supports multiple VPN protocols including OpenVPN, WireGuard, IPsec/IKEv2, SoftEther, PPTP, and L2TP.

## Features

### VPN Auto Installer
- **Multiple VPN Protocols**: OpenVPN, WireGuard, IPsec/IKEv2, SoftEther, PPTP, L2TP
- **Cross-Platform Support**: Ubuntu/Debian, CentOS/RHEL, Arch Linux
- **Automatic Configuration**: Easy-RSA, certificates, firewall rules
- **Client Config Generation**: Automatic generation of client configuration files
- **QR Code Support**: For easy mobile device setup

### Admin Panel
- **Web-Based Interface**: Modern, responsive Bootstrap UI
- **Real-Time Monitoring**: System stats, VPN status, connected users
- **User Management**: Add, remove, and manage VPN users
- **Connection Logs**: Track user connections and data usage
- **Multiple Authentication**: Support for different VPN protocols
- **System Logs**: Monitor system events and activities
- **Configuration Downloads**: Download client configs and QR codes

## Quick Installation

### Option 1: One-Line Install (Recommended)

```bash
# Install VPN server with admin panel
curl -fsSL https://raw.githubusercontent.com/your-repo/vpn-installer/main/install.sh | sudo bash

# Or download and run locally
wget https://raw.githubusercontent.com/your-repo/vpn-installer/main/install.sh
chmod +x install.sh
sudo ./install.sh
```

### Option 2: Git Clone Method

```bash
# Clone the repository
git clone https://github.com/your-repo/vpn-installer.git
cd vpn-installer

# Make scripts executable
chmod +x install.sh
chmod +x install-admin-panel.sh

# Install VPN server
sudo ./install.sh

# Install admin panel
sudo ./install-admin-panel.sh
```

## Installation Steps

### 1. VPN Server Installation

The main installer script (`install.sh`) will:

1. Detect your operating system
2. Update system packages
3. Configure firewall and IP forwarding
4. Install your chosen VPN protocol(s)
5. Generate certificates and keys
6. Create client configuration files
7. Start VPN services

**Supported VPN Protocols:**
1. OpenVPN (Port 1194/UDP)
2. WireGuard (Port 51820/UDP) 
3. IPsec/IKEv2 (Ports 500,4500/UDP)
4. SoftEther VPN (Ports 443,992,1194/TCP+UDP)
5. PPTP VPN (Port 1723/TCP)
6. L2TP VPN (Ports 500,4500,1701/UDP)

### 2. Admin Panel Installation

The admin panel installer (`install-admin-panel.sh`) will:

1. Install Node.js and dependencies
2. Create admin panel user
3. Setup the web application
4. Configure systemd service
5. Setup Nginx reverse proxy (optional)
6. Configure SSL with Let's Encrypt (optional)

## Usage

### VPN Server Management

```bash
# Check VPN service status
systemctl status openvpn@server      # OpenVPN
systemctl status wg-quick@wg0        # WireGuard
systemctl status strongswan          # IPsec/IKEv2
systemctl status softether-vpnserver # SoftEther
systemctl status pptpd               # PPTP
systemctl status xl2tpd              # L2TP

# Restart VPN services
systemctl restart openvpn@server
systemctl restart wg-quick@wg0
# ... etc
```

### Admin Panel Access

1. **Web Interface**: `http://your-server-ip:3000` (or port 80 with Nginx)
2. **Default Login**: 
   - Username: `admin`
   - Password: `admin123`
3. **Change Default Password**: Login and go to Settings

### Admin Panel Management

```bash
# Service management
systemctl start vpn-admin      # Start admin panel
systemctl stop vpn-admin       # Stop admin panel
systemctl restart vpn-admin    # Restart admin panel
systemctl status vpn-admin     # Check status

# View logs
journalctl -u vpn-admin -f     # Follow logs
journalctl -u vpn-admin --since "1 hour ago"  # Recent logs
```

## Configuration Files

### VPN Configurations
- **OpenVPN**: `/etc/openvpn/`
- **WireGuard**: `/etc/wireguard/`
- **IPsec**: `/etc/ipsec.conf`, `/etc/ipsec.secrets`
- **SoftEther**: `/opt/vpnserver/`
- **PPTP**: `/etc/pptpd.conf`, `/etc/ppp/`
- **L2TP**: `/etc/xl2tpd/`, `/etc/ppp/`

### Client Configurations
- **Location**: `/etc/vpn-config/clients/`
- **Files**: 
  - `client.ovpn` (OpenVPN)
  - `client.conf` (WireGuard)
  - Certificate files (OpenVPN)

### Admin Panel
- **Installation**: `/opt/vpn-admin/`
- **Database**: `/opt/vpn-admin/vpn_admin.db`
- **Logs**: `/var/log/vpn-installer.log`

## Security Considerations

### Default Credentials
- **Change immediately** after installation
- Use strong passwords for VPN users
- Consider implementing 2FA

### Firewall Rules
- Only necessary ports are opened
- IP forwarding is enabled for VPN traffic
- NAT masquerading is configured

### Certificates
- Strong encryption (AES-256-CBC for OpenVPN)
- 4096-bit RSA keys
- Certificate validity periods set appropriately

## Troubleshooting

### Common Issues

1. **Services won't start**
   ```bash
   # Check service status
   systemctl status service-name
   
   # View detailed logs
   journalctl -u service-name -f
   ```

2. **Can't connect to admin panel**
   ```bash
   # Check if service is running
   systemctl status vpn-admin
   
   # Check firewall
   iptables -L | grep 3000
   
   # Check port binding
   netstat -tlnp | grep 3000
   ```

3. **VPN connection issues**
   ```bash
   # Check VPN logs
   tail -f /var/log/openvpn.log
   tail -f /var/log/syslog | grep vpn
   
   # Test connectivity
   ping 10.8.0.1  # OpenVPN default gateway
   ```

### Log Locations
- **VPN Installer**: `/var/log/vpn-installer.log`
- **Admin Panel**: `journalctl -u vpn-admin`
- **OpenVPN**: `/var/log/openvpn.log`
- **System**: `/var/log/syslog`

## API Documentation

### Admin Panel API Endpoints

- `GET /api/stats` - System statistics
- `GET /api/vpn-status` - VPN service status
- `POST /api/vpn/restart/:service` - Restart VPN service
- `GET /config/:protocol` - Download client config
- `GET /qr/:protocol` - Generate QR code

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## License

This project is licensed under the MIT License.

## Support

For issues and questions:
1. Check the troubleshooting section
2. Review system logs
3. Open an issue on GitHub
4. Provide detailed error messages and system information

## System Requirements

### Minimum Requirements
- **RAM**: 512MB (1GB recommended)
- **Storage**: 2GB free space
- **OS**: Ubuntu 18.04+, Debian 9+, CentOS 7+, Arch Linux
- **Network**: Public IP address
- **Ports**: Various ports depending on VPN protocols

### Recommended Requirements
- **RAM**: 2GB+
- **Storage**: 10GB+ free space
- **CPU**: 2+ cores
- **Network**: Dedicated server or VPS

## Performance Notes

- WireGuard typically offers the best performance
- OpenVPN is most compatible across devices
- IPsec/IKEv2 offers good mobile device support
- SoftEther provides multiple protocol support
- PPTP is legacy and less secure (not recommended for production)

## Updates

To update the installation:

```bash
# Download latest scripts
wget https://raw.githubusercontent.com/your-repo/vpn-installer/main/install.sh
chmod +x install.sh

# Re-run installation (it will update existing installations)
sudo ./install.sh
```

For admin panel updates:
```bash
cd /opt/vpn-admin
sudo -u vpnadmin npm update
systemctl restart vpn-admin
```
