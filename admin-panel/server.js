const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const sqlite3 = require('sqlite3').verbose();
const multer = require('multer');
const moment = require('moment');
const WebSocket = require('ws');
const cron = require('node-cron');
const si = require('systeminformation');
const QRCode = require('qrcode');
const fs = require('fs');
const path = require('path');
const { exec, spawn } = require('child_process');

const app = express();
const PORT = process.env.PORT || 3000;

// Database setup
const db = new sqlite3.Database('vpn_admin.db');

// Initialize database tables
db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        email TEXT,
        role TEXT DEFAULT 'user',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        last_login DATETIME,
        is_active BOOLEAN DEFAULT 1
    )`);
    
    db.run(`CREATE TABLE IF NOT EXISTS vpn_users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        protocol TEXT,
        ip_address TEXT,
        data_usage INTEGER DEFAULT 0,
        last_seen DATETIME,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        is_active BOOLEAN DEFAULT 1,
        expires_at DATETIME
    )`);
    
    db.run(`CREATE TABLE IF NOT EXISTS connections (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        protocol TEXT,
        ip_address TEXT,
        connected_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        disconnected_at DATETIME,
        data_sent INTEGER DEFAULT 0,
        data_received INTEGER DEFAULT 0,
        duration INTEGER DEFAULT 0,
        FOREIGN KEY (user_id) REFERENCES vpn_users(id)
    )`);
    
    db.run(`CREATE TABLE IF NOT EXISTS system_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        level TEXT,
        message TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
    
    db.run(`CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
    
    // Create default admin user
    const defaultPassword = bcrypt.hashSync('admin123', 10);
    db.run(`INSERT OR IGNORE INTO users (username, password, role) VALUES (?, ?, ?)`, 
        ['admin', defaultPassword, 'admin']);
});

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(session({
    secret: 'vpn-admin-secret-key',
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 24 * 60 * 60 * 1000 } // 24 hours
}));

app.use(express.static('public'));
app.set('view engine', 'ejs');
app.set('views', './views');

// File upload configuration
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/');
    },
    filename: (req, file, cb) => {
        cb(null, Date.now() + '-' + file.originalname);
    }
});
const upload = multer({ storage: storage });

// Authentication middleware
const requireAuth = (req, res, next) => {
    if (req.session.userId) {
        next();
    } else {
        res.redirect('/login');
    }
};

const requireAdmin = (req, res, next) => {
    if (req.session.userId && req.session.role === 'admin') {
        next();
    } else {
        res.status(403).send('Access denied');
    }
};

// Utility functions
const logMessage = (level, message) => {
    db.run(`INSERT INTO system_logs (level, message) VALUES (?, ?)`, [level, message]);
    console.log(`[${level.toUpperCase()}] ${message}`);
};

const executeCommand = (command) => {
    return new Promise((resolve, reject) => {
        exec(command, (error, stdout, stderr) => {
            if (error) {
                reject(error);
                return;
            }
            resolve({ stdout, stderr });
        });
    });
};

// System monitoring
const getSystemStats = async () => {
    try {
        const cpu = await si.cpu();
        const mem = await si.mem();
        const fsSize = await si.fsSize();
        const networkStats = await si.networkStats();
        const currentLoad = await si.currentLoad();
        
        return {
            cpu: {
                manufacturer: cpu.manufacturer,
                brand: cpu.brand,
                cores: cpu.cores,
                speed: cpu.speed,
                usage: currentLoad.currentload
            },
            memory: {
                total: mem.total,
                free: mem.free,
                used: mem.used,
                usage: ((mem.used / mem.total) * 100)
            },
            disk: fsSize[0] ? {
                total: fsSize[0].size,
                used: fsSize[0].used,
                free: fsSize[0].available,
                usage: fsSize[0].use
            } : null,
            network: networkStats
        };
    } catch (error) {
        logMessage('error', `Failed to get system stats: ${error.message}`);
        return null;
    }
};

// VPN management functions
const getVPNStatus = async () => {
    try {
        const services = ['openvpn@server', 'wg-quick@wg0', 'strongswan', 'softether-vpnserver', 'pptpd', 'xl2tpd'];
        const status = {};
        
        for (const service of services) {
            try {
                const result = await executeCommand(`systemctl is-active ${service}`);
                status[service] = result.stdout.trim() === 'active';
            } catch (error) {
                status[service] = false;
            }
        }
        
        return status;
    } catch (error) {
        logMessage('error', `Failed to get VPN status: ${error.message}`);
        return {};
    }
};

const getConnectedUsers = async () => {
    try {
        // This would need to be customized based on the VPN protocols used
        const openvpnStatus = await executeCommand('cat /var/log/openvpn-status.log 2>/dev/null || echo "No OpenVPN status"');
        const wireguardStatus = await executeCommand('wg show 2>/dev/null || echo "No WireGuard status"');
        
        return {
            openvpn: openvpnStatus.stdout,
            wireguard: wireguardStatus.stdout
        };
    } catch (error) {
        logMessage('error', `Failed to get connected users: ${error.message}`);
        return {};
    }
};

// Routes
app.get('/', (req, res) => {
    if (req.session.userId) {
        res.redirect('/dashboard');
    } else {
        res.redirect('/login');
    }
});

app.get('/login', (req, res) => {
    res.render('login', { error: null });
});

app.post('/login', (req, res) => {
    const { username, password } = req.body;
    
    db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
        if (err) {
            logMessage('error', `Database error during login: ${err.message}`);
            res.render('login', { error: 'Database error' });
            return;
        }
        
        if (user && bcrypt.compareSync(password, user.password)) {
            req.session.userId = user.id;
            req.session.username = user.username;
            req.session.role = user.role;
            
            // Update last login
            db.run('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?', [user.id]);
            
            logMessage('info', `User ${username} logged in`);
            res.redirect('/dashboard');
        } else {
            logMessage('warning', `Failed login attempt for ${username}`);
            res.render('login', { error: 'Invalid username or password' });
        }
    });
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/login');
});

app.get('/dashboard', requireAuth, async (req, res) => {
    try {
        const systemStats = await getSystemStats();
        const vpnStatus = await getVPNStatus();
        const connectedUsers = await getConnectedUsers();
        
        // Get user counts
        const userCounts = await new Promise((resolve, reject) => {
            db.all(`
                SELECT 
                    COUNT(*) as total,
                    SUM(CASE WHEN is_active = 1 THEN 1 ELSE 0 END) as active,
                    SUM(CASE WHEN last_seen > datetime('now', '-5 minutes') THEN 1 ELSE 0 END) as online
                FROM vpn_users
            `, (err, rows) => {
                if (err) reject(err);
                else resolve(rows[0]);
            });
        });
        
        res.render('dashboard', {
            user: req.session,
            systemStats,
            vpnStatus,
            connectedUsers,
            userCounts
        });
    } catch (error) {
        logMessage('error', `Dashboard error: ${error.message}`);
        res.render('dashboard', {
            user: req.session,
            systemStats: null,
            vpnStatus: {},
            connectedUsers: {},
            userCounts: { total: 0, active: 0, online: 0 }
        });
    }
});

app.get('/users', requireAuth, (req, res) => {
    db.all('SELECT * FROM vpn_users ORDER BY created_at DESC', (err, users) => {
        if (err) {
            logMessage('error', `Error fetching users: ${err.message}`);
            users = [];
        }
        res.render('users', { user: req.session, users });
    });
});

app.post('/users/add', requireAdmin, (req, res) => {
    const { username, password, protocol, expires_at } = req.body;
    const hashedPassword = bcrypt.hashSync(password, 10);
    
    db.run(`INSERT INTO vpn_users (username, password, protocol, expires_at) VALUES (?, ?, ?, ?)`,
        [username, hashedPassword, protocol, expires_at || null], function(err) {
            if (err) {
                logMessage('error', `Error adding user: ${err.message}`);
                res.json({ success: false, message: 'Error adding user' });
            } else {
                logMessage('info', `User ${username} added by ${req.session.username}`);
                res.json({ success: true, message: 'User added successfully' });
            }
        });
});

app.post('/users/delete/:id', requireAdmin, (req, res) => {
    const userId = req.params.id;
    
    db.get('SELECT username FROM vpn_users WHERE id = ?', [userId], (err, user) => {
        if (err || !user) {
            res.json({ success: false, message: 'User not found' });
            return;
        }
        
        db.run('DELETE FROM vpn_users WHERE id = ?', [userId], (err) => {
            if (err) {
                logMessage('error', `Error deleting user: ${err.message}`);
                res.json({ success: false, message: 'Error deleting user' });
            } else {
                logMessage('info', `User ${user.username} deleted by ${req.session.username}`);
                res.json({ success: true, message: 'User deleted successfully' });
            }
        });
    });
});

app.get('/connections', requireAuth, (req, res) => {
    db.all(`
        SELECT c.*, v.username 
        FROM connections c 
        LEFT JOIN vpn_users v ON c.user_id = v.id 
        ORDER BY c.connected_at DESC 
        LIMIT 100
    `, (err, connections) => {
        if (err) {
            logMessage('error', `Error fetching connections: ${err.message}`);
            connections = [];
        }
        res.render('connections', { user: req.session, connections });
    });
});

app.get('/settings', requireAdmin, (req, res) => {
    db.all('SELECT * FROM settings', (err, settings) => {
        if (err) {
            logMessage('error', `Error fetching settings: ${err.message}`);
            settings = [];
        }
        
        const settingsObj = {};
        settings.forEach(setting => {
            settingsObj[setting.key] = setting.value;
        });
        
        res.render('settings', { user: req.session, settings: settingsObj });
    });
});

app.post('/settings', requireAdmin, (req, res) => {
    const settings = req.body;
    
    const promises = Object.keys(settings).map(key => {
        return new Promise((resolve, reject) => {
            db.run(`INSERT OR REPLACE INTO settings (key, value, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)`,
                [key, settings[key]], (err) => {
                    if (err) reject(err);
                    else resolve();
                });
        });
    });
    
    Promise.all(promises)
        .then(() => {
            logMessage('info', `Settings updated by ${req.session.username}`);
            res.json({ success: true, message: 'Settings updated successfully' });
        })
        .catch(err => {
            logMessage('error', `Error updating settings: ${err.message}`);
            res.json({ success: false, message: 'Error updating settings' });
        });
});

app.get('/logs', requireAuth, (req, res) => {
    db.all('SELECT * FROM system_logs ORDER BY timestamp DESC LIMIT 500', (err, logs) => {
        if (err) {
            logMessage('error', `Error fetching logs: ${err.message}`);
            logs = [];
        }
        res.render('logs', { user: req.session, logs });
    });
});

app.get('/config/:protocol', requireAuth, async (req, res) => {
    const protocol = req.params.protocol;
    const configPath = `/etc/vpn-config/clients/client.${protocol === 'openvpn' ? 'ovpn' : 'conf'}`;
    
    try {
        if (fs.existsSync(configPath)) {
            const config = fs.readFileSync(configPath, 'utf8');
            res.setHeader('Content-Type', 'text/plain');
            res.setHeader('Content-Disposition', `attachment; filename=client.${protocol === 'openvpn' ? 'ovpn' : 'conf'}`);
            res.send(config);
        } else {
            res.status(404).send('Configuration file not found');
        }
    } catch (error) {
        logMessage('error', `Error serving config file: ${error.message}`);
        res.status(500).send('Error serving configuration file');
    }
});

app.get('/qr/:protocol', requireAuth, async (req, res) => {
    const protocol = req.params.protocol;
    const configPath = `/etc/vpn-config/clients/client.${protocol === 'wireguard' ? 'conf' : 'ovpn'}`;
    
    try {
        if (fs.existsSync(configPath)) {
            const config = fs.readFileSync(configPath, 'utf8');
            const qrCode = await QRCode.toDataURL(config);
            res.json({ qrCode });
        } else {
            res.status(404).json({ error: 'Configuration file not found' });
        }
    } catch (error) {
        logMessage('error', `Error generating QR code: ${error.message}`);
        res.status(500).json({ error: 'Error generating QR code' });
    }
});

// API endpoints for real-time data
app.get('/api/stats', requireAuth, async (req, res) => {
    try {
        const stats = await getSystemStats();
        res.json(stats);
    } catch (error) {
        res.status(500).json({ error: 'Failed to get system stats' });
    }
});

app.get('/api/vpn-status', requireAuth, async (req, res) => {
    try {
        const status = await getVPNStatus();
        res.json(status);
    } catch (error) {
        res.status(500).json({ error: 'Failed to get VPN status' });
    }
});

app.post('/api/vpn/restart/:service', requireAdmin, async (req, res) => {
    const service = req.params.service;
    const allowedServices = ['openvpn@server', 'wg-quick@wg0', 'strongswan', 'softether-vpnserver', 'pptpd', 'xl2tpd'];
    
    if (!allowedServices.includes(service)) {
        return res.status(400).json({ error: 'Invalid service' });
    }
    
    try {
        await executeCommand(`systemctl restart ${service}`);
        logMessage('info', `Service ${service} restarted by ${req.session.username}`);
        res.json({ success: true, message: `${service} restarted successfully` });
    } catch (error) {
        logMessage('error', `Failed to restart ${service}: ${error.message}`);
        res.status(500).json({ error: `Failed to restart ${service}` });
    }
});

// WebSocket for real-time updates
const server = require('http').createServer(app);
const wss = new WebSocket.Server({ server });

wss.on('connection', (ws) => {
    console.log('WebSocket client connected');
    
    ws.on('close', () => {
        console.log('WebSocket client disconnected');
    });
});

// Broadcast real-time data every 30 seconds
setInterval(async () => {
    try {
        const stats = await getSystemStats();
        const vpnStatus = await getVPNStatus();
        
        const data = {
            type: 'update',
            stats,
            vpnStatus,
            timestamp: new Date().toISOString()
        };
        
        wss.clients.forEach(client => {
            if (client.readyState === WebSocket.OPEN) {
                client.send(JSON.stringify(data));
            }
        });
    } catch (error) {
        console.error('Error broadcasting real-time data:', error);
    }
}, 30000);

// Cleanup old logs (daily)
cron.schedule('0 0 * * *', () => {
    db.run('DELETE FROM system_logs WHERE timestamp < datetime("now", "-30 days")');
    db.run('DELETE FROM connections WHERE connected_at < datetime("now", "-90 days")');
    logMessage('info', 'Old logs cleaned up');
});

// Error handling
app.use((err, req, res, next) => {
    logMessage('error', `Express error: ${err.message}`);
    res.status(500).send('Internal Server Error');
});

app.use((req, res) => {
    res.status(404).render('404', { user: req.session || {} });
});

// Create required directories
const dirs = ['uploads', 'views', 'public', 'public/css', 'public/js'];
dirs.forEach(dir => {
    if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
    }
});

// Start server
server.listen(PORT, () => {
    console.log(`VPN Admin Panel running on http://localhost:${PORT}`);
    logMessage('info', `VPN Admin Panel started on port ${PORT}`);
    console.log('Default login: admin / admin123');
});
