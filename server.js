// ============================================================
// ── CAMS SERVER ──────────────────────────────────────────────
// ── Client Assessment Management System Backend ────────────
// ============================================================

const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');
const nodemailer = require('nodemailer');

const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'cams-super-secret-key-2026';

// ============================================================
// ── MIDDLEWARE ────────────────────────────────────────────────
// ============================================================

app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// ============================================================
// ── DATA STORAGE ──────────────────────────────────────────────
// ============================================================

const DATA_PATH = path.join(__dirname, 'data');
if (!fs.existsSync(DATA_PATH)) {
  fs.mkdirSync(DATA_PATH, { recursive: true });
}

// In-memory data store (with file persistence)
let dataStore = {
  users: [],
  clients: ['KFTL', 'KWL', 'Lasco', 'Nestle', 'NIDS', 'Nutrien'],
  clientLogos: {},
  cameras: [],
  doors: [],
  servers: [],
  switches: [],
  storage: [],
  stations: [],
  monitors: [],
  software: [],
  serviceRequests: [],
  auditLog: [],
  emails: [],
  warrantyAlerts: []
};

function loadData() {
  try {
    const dataFile = path.join(DATA_PATH, 'data.json');
    if (fs.existsSync(dataFile)) {
      const rawData = fs.readFileSync(dataFile, 'utf8');
      const loaded = JSON.parse(rawData);
      dataStore = { ...dataStore, ...loaded };
      console.log('✅ Data loaded from disk');
    }
  } catch (err) {
    console.error('⚠️ Error loading data:', err.message);
  }
}

function saveData() {
  try {
    const dataFile = path.join(DATA_PATH, 'data.json');
    fs.writeFileSync(dataFile, JSON.stringify(dataStore, null, 2), 'utf8');
  } catch (err) {
    console.error('⚠️ Error saving data:', err.message);
  }
}

// Load data on startup
loadData();

// ============================================================
// ── DEFAULT USERS ─────────────────────────────────────────────
// ============================================================

function initializeUsers() {
  if (dataStore.users.length === 0) {
    const hashedPassword = bcrypt.hashSync('admin123', 10);
    dataStore.users = [
      {
        id: 'user-1',
        username: 'admin',
        password: hashedPassword,
        role: 'Administrator',
        isAdmin: true,
        client: null,
        createdAt: new Date().toISOString()
      },
      {
        id: 'user-2',
        username: 'kftl',
        password: bcrypt.hashSync('kftl123', 10),
        role: 'Client User',
        isAdmin: false,
        client: 'KFTL',
        createdAt: new Date().toISOString()
      },
      {
        id: 'user-3',
        username: 'kwl',
        password: bcrypt.hashSync('kwl123', 10),
        role: 'Client User',
        isAdmin: false,
        client: 'KWL',
        createdAt: new Date().toISOString()
      },
      {
        id: 'user-4',
        username: 'lasco',
        password: bcrypt.hashSync('lasco123', 10),
        role: 'Client User',
        isAdmin: false,
        client: 'Lasco',
        createdAt: new Date().toISOString()
      },
      {
        id: 'user-5',
        username: 'nestle',
        password: bcrypt.hashSync('nestle123', 10),
        role: 'Client User',
        isAdmin: false,
        client: 'Nestle',
        createdAt: new Date().toISOString()
      },
      {
        id: 'user-6',
        username: 'nids',
        password: bcrypt.hashSync('nids123', 10),
        role: 'Client User',
        isAdmin: false,
        client: 'NIDS',
        createdAt: new Date().toISOString()
      },
      {
        id: 'user-7',
        username: 'nutrien',
        password: bcrypt.hashSync('nutrien123', 10),
        role: 'Client User',
        isAdmin: false,
        client: 'Nutrien',
        createdAt: new Date().toISOString()
      }
    ];
    saveData();
    console.log('✅ Default users created');
  }
}

initializeUsers();

// ============================================================
// ── EMAIL CONFIGURATION ──────────────────────────────────────
// ============================================================

// Email transporter configuration (using environment variables or defaults)
const emailTransporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST || 'smtp.gmail.com',
  port: parseInt(process.env.SMTP_PORT) || 587,
  secure: process.env.SMTP_SECURE === 'true',
  auth: {
    user: process.env.SMTP_USER || 'support@e-techsystemsja.com',
    pass: process.env.SMTP_PASS || 'your-email-password'
  }
});

// Fallback: Log emails instead of sending when in development
function sendEmail(to, subject, body) {
  const mailOptions = {
    from: process.env.SMTP_USER || 'support@e-techsystemsja.com',
    to: to,
    subject: subject,
    html: body
  };

  // For development, log the email
  if (process.env.NODE_ENV === 'development' || !process.env.SMTP_USER) {
    console.log('📧 [EMAIL] To:', to);
    console.log('📧 [EMAIL] Subject:', subject);
    console.log('📧 [EMAIL] Body:', body.substring(0, 200) + '...');
    return Promise.resolve({ messageId: 'dev-' + Date.now() });
  }

  return emailTransporter.sendMail(mailOptions);
}

// ============================================================
// ── AUTHENTICATION ────────────────────────────────────────────
// ============================================================

function generateToken(user) {
  return jwt.sign(
    { id: user.id, username: user.username, isAdmin: user.isAdmin, client: user.client },
    JWT_SECRET,
    { expiresIn: '7d' }
  );
}

function authenticate(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized - No token provided' });
  }

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Unauthorized - Invalid token' });
  }
}

function requireAdmin(req, res, next) {
  if (!req.user || !req.user.isAdmin) {
    return res.status(403).json({ error: 'Forbidden - Admin access required' });
  }
  next();
}

function requireClientAccess(req, res, next) {
  if (!req.user) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  // If user is admin, allow all access
  if (req.user.isAdmin) {
    return next();
  }
  // If user has a client association, filter data later
  // This middleware sets the client filter for the request
  req.clientFilter = req.user.client;
  next();
}

// ============================================================
// ── AUTH ROUTES ──────────────────────────────────────────────
// ============================================================

app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;
  
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }

  const user = dataStore.users.find(u => u.username === username);
  if (!user) {
    return res.status(401).json({ error: 'Invalid username or password' });
  }

  const validPassword = bcrypt.compareSync(password, user.password);
  if (!validPassword) {
    return res.status(401).json({ error: 'Invalid username or password' });
  }

  const token = generateToken(user);
  res.json({
    token,
    user: {
      id: user.id,
      username: user.username,
      role: user.role,
      isAdmin: user.isAdmin,
      client: user.client
    }
  });
});

app.post('/api/auth/microsoft', (req, res) => {
  const { code, code_verifier } = req.body;
  // For demo purposes, we'll create a user with the code
  // In production, this would validate with Microsoft
  const user = {
    id: 'ms-user-' + Date.now(),
    username: 'microsoft-user',
    role: 'Administrator',
    isAdmin: true,
    client: null
  };
  
  const token = generateToken(user);
  res.json({ access_token: token });
});

// ============================================================
// ── USER ROUTES ──────────────────────────────────────────────
// ============================================================

app.get('/api/users', authenticate, requireAdmin, (req, res) => {
  const users = dataStore.users.map(u => ({
    id: u.id,
    username: u.username,
    role: u.role,
    isAdmin: u.isAdmin,
    client: u.client,
    createdAt: u.createdAt
  }));
  res.json({ data: users });
});

app.post('/api/users', authenticate, requireAdmin, (req, res) => {
  const { username, password, role, isAdmin, client } = req.body;
  
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }
  
  if (dataStore.users.find(u => u.username === username)) {
    return res.status(400).json({ error: 'Username already exists' });
  }
  
  const newUser = {
    id: 'user-' + Date.now(),
    username,
    password: bcrypt.hashSync(password, 10),
    role: role || 'User',
    isAdmin: isAdmin || false,
    client: client || null,
    createdAt: new Date().toISOString()
  };
  
  dataStore.users.push(newUser);
  saveData();
  res.status(201).json({
    id: newUser.id,
    username: newUser.username,
    role: newUser.role,
    isAdmin: newUser.isAdmin,
    client: newUser.client
  });
});

app.delete('/api/users/:id', authenticate, requireAdmin, (req, res) => {
  const userId = req.params.id;
  const index = dataStore.users.findIndex(u => u.id === userId);
  if (index === -1) {
    return res.status(404).json({ error: 'User not found' });
  }
  dataStore.users.splice(index, 1);
  saveData();
  res.json({ success: true });
});

// ============================================================
// ── CLIENT ROUTES ────────────────────────────────────────────
// ============================================================

app.get('/api/clients', authenticate, (req, res) => {
  let clients = dataStore.clients;
  if (req.user && !req.user.isAdmin && req.user.client) {
    clients = clients.filter(c => c === req.user.client);
  }
  res.json({ data: clients });
});

app.post('/api/clients', authenticate, requireAdmin, (req, res) => {
  const { name, email, phone, address, logo } = req.body;
  if (!name) {
    return res.status(400).json({ error: 'Client name required' });
  }
  if (dataStore.clients.includes(name)) {
    return res.status(400).json({ error: 'Client already exists' });
  }
  dataStore.clients.push(name);
  if (logo) {
    dataStore.clientLogos[name] = logo;
  }
  saveData();
  res.status(201).json({ data: { name, email, phone, address } });
});

app.put('/api/clients/:name', authenticate, requireAdmin, (req, res) => {
  const oldName = req.params.name;
  const { name, email, phone, address, logo } = req.body;
  
  const index = dataStore.clients.indexOf(oldName);
  if (index === -1) {
    return res.status(404).json({ error: 'Client not found' });
  }
  
  if (name && name !== oldName) {
    if (dataStore.clients.includes(name)) {
      return res.status(400).json({ error: 'Client name already exists' });
    }
    dataStore.clients[index] = name;
    // Update all references in other data
    dataStore.cameras.forEach(c => { if (c.client === oldName) c.client = name; });
    dataStore.doors.forEach(d => { if (d.client === oldName) d.client = name; });
    dataStore.servers.forEach(s => { if (s.client === oldName) s.client = name; });
    dataStore.switches.forEach(s => { if (s.client === oldName) s.client = name; });
    dataStore.storage.forEach(s => { if (s.client === oldName) s.client = name; });
    dataStore.stations.forEach(s => { if (s.client === oldName) s.client = name; });
    dataStore.monitors.forEach(m => { if (m.client === oldName) m.client = name; });
    dataStore.software.forEach(s => { if (s.client === oldName) s.client = name; });
    dataStore.serviceRequests.forEach(sr => { if (sr.client === oldName) sr.client = name; });
    // Update logo
    if (dataStore.clientLogos[oldName]) {
      dataStore.clientLogos[name] = dataStore.clientLogos[oldName];
      delete dataStore.clientLogos[oldName];
    }
  }
  
  if (logo) {
    dataStore.clientLogos[name || oldName] = logo;
  }
  
  saveData();
  res.json({ success: true });
});

app.delete('/api/clients/:name', authenticate, requireAdmin, (req, res) => {
  const name = req.params.name;
  const index = dataStore.clients.indexOf(name);
  if (index === -1) {
    return res.status(404).json({ error: 'Client not found' });
  }
  dataStore.clients.splice(index, 1);
  delete dataStore.clientLogos[name];
  saveData();
  res.json({ success: true });
});

// ============================================================
// ── GENERIC CRUD HELPERS ─────────────────────────────────────
// ============================================================

function filterByClient(items, req) {
  if (req.user && !req.user.isAdmin && req.user.client) {
    return items.filter(item => item.client === req.user.client || item.client === undefined);
  }
  return items;
}

function createCrudRoutes(basePath, storeKey, itemFields) {
  // GET all
  app.get(`/api/${basePath}`, authenticate, (req, res) => {
    let items = dataStore[storeKey] || [];
    items = filterByClient(items, req);
    res.json({ data: items });
  });

  // GET single
  app.get(`/api/${basePath}/:id`, authenticate, (req, res) => {
    let items = dataStore[storeKey] || [];
    const item = items.find(i => i.id === req.params.id || i.name === req.params.id);
    if (!item) {
      return res.status(404).json({ error: 'Item not found' });
    }
    // Check client access
    if (req.user && !req.user.isAdmin && req.user.client && item.client !== req.user.client) {
      return res.status(403).json({ error: 'Access denied' });
    }
    res.json({ data: item });
  });

  // POST (create)
  app.post(`/api/${basePath}`, authenticate, (req, res) => {
    const newItem = {
      id: `${storeKey}-${Date.now()}`,
      ...req.body,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };
    
    // Auto-assign client if user is not admin
    if (req.user && !req.user.isAdmin && req.user.client) {
      newItem.client = req.user.client;
    }
    
    if (!dataStore[storeKey]) dataStore[storeKey] = [];
    dataStore[storeKey].push(newItem);
    saveData();
    res.status(201).json({ data: newItem });
  });

  // PUT (update)
  app.put(`/api/${basePath}/:id`, authenticate, (req, res) => {
    const id = req.params.id;
    let items = dataStore[storeKey] || [];
    const index = items.findIndex(i => i.id === id || i.name === id);
    if (index === -1) {
      return res.status(404).json({ error: 'Item not found' });
    }
    
    const item = items[index];
    // Check client access
    if (req.user && !req.user.isAdmin && req.user.client && item.client !== req.user.client) {
      return res.status(403).json({ error: 'Access denied' });
    }
    
    const updatedItem = {
      ...item,
      ...req.body,
      updatedAt: new Date().toISOString()
    };
    
    // Preserve client if not admin
    if (req.user && !req.user.isAdmin && req.user.client) {
      updatedItem.client = req.user.client;
    }
    
    items[index] = updatedItem;
    saveData();
    res.json({ data: updatedItem });
  });

  // DELETE
  app.delete(`/api/${basePath}/:id`, authenticate, (req, res) => {
    const id = req.params.id;
    let items = dataStore[storeKey] || [];
    const index = items.findIndex(i => i.id === id || i.name === id);
    if (index === -1) {
      return res.status(404).json({ error: 'Item not found' });
    }
    
    const item = items[index];
    // Check client access
    if (req.user && !req.user.isAdmin && req.user.client && item.client !== req.user.client) {
      return res.status(403).json({ error: 'Access denied' });
    }
    
    items.splice(index, 1);
    saveData();
    res.json({ success: true });
  });
}

// ============================================================
// ── REGISTER ROUTES ──────────────────────────────────────────
// ============================================================

// Create CRUD routes for all asset types
createCrudRoutes('cameras', 'cameras');
createCrudRoutes('doors', 'doors');
createCrudRoutes('servers', 'servers');
createCrudRoutes('switches', 'switches');
createCrudRoutes('storage', 'storage');
createCrudRoutes('stations', 'stations');
createCrudRoutes('monitors', 'monitors');
createCrudRoutes('software', 'software');
createCrudRoutes('tickets', 'serviceRequests');
createCrudRoutes('inbox', 'emails');

// ============================================================
// ── SERVICE REQUEST SPECIFIC ROUTES ─────────────────────────
// ============================================================

app.post('/api/tickets/:id/assign', authenticate, (req, res) => {
  const id = req.params.id;
  const { assigned } = req.body;
  const ticket = dataStore.serviceRequests.find(t => t.id === id);
  if (!ticket) {
    return res.status(404).json({ error: 'Ticket not found' });
  }
  if (req.user && !req.user.isAdmin && req.user.client && ticket.client !== req.user.client) {
    return res.status(403).json({ error: 'Access denied' });
  }
  ticket.assigned = assigned;
  ticket.updatedAt = new Date().toISOString();
  if (!ticket.history) ticket.history = [];
  ticket.history.push({
    time: new Date().toLocaleTimeString(),
    msg: 'Assigned to ' + assigned
  });
  saveData();
  res.json({ data: ticket });
});

app.post('/api/tickets/:id/status', authenticate, (req, res) => {
  const id = req.params.id;
  const { status } = req.body;
  const ticket = dataStore.serviceRequests.find(t => t.id === id);
  if (!ticket) {
    return res.status(404).json({ error: 'Ticket not found' });
  }
  if (req.user && !req.user.isAdmin && req.user.client && ticket.client !== req.user.client) {
    return res.status(403).json({ error: 'Access denied' });
  }
  ticket.status = status;
  ticket.updatedAt = new Date().toISOString();
  if (!ticket.history) ticket.history = [];
  ticket.history.push({
    time: new Date().toLocaleTimeString(),
    msg: 'Status → ' + status
  });
  saveData();
  res.json({ data: ticket });
});

// ============================================================
// ── WARRANTY ALERT SYSTEM ────────────────────────────────────
// ============================================================

function checkWarrantyExpirations() {
  const now = new Date();
  const alerts = [];
  const alertThresholds = [90, 60, 30, 21, 14, 7]; // days

  // Check all assets with warranty_expiry
  const assetTypes = [
    { name: 'Camera', items: dataStore.cameras },
    { name: 'Door', items: dataStore.doors },
    { name: 'Server', items: dataStore.servers },
    { name: 'Switch', items: dataStore.switches },
    { name: 'Storage', items: dataStore.storage },
    { name: 'Client Station', items: dataStore.stations },
    { name: 'Monitor', items: dataStore.monitors }
  ];

  assetTypes.forEach(type => {
    type.items.forEach(item => {
      if (item.warranty_expiry) {
        const expiryDate = new Date(item.warranty_expiry);
        const daysLeft = Math.ceil((expiryDate - now) / (1000 * 60 * 60 * 24));
        
        // Check if any threshold matches
        alertThresholds.forEach(threshold => {
          if (daysLeft === threshold || (threshold === 7 && daysLeft <= 7 && daysLeft > 0)) {
            // Check if alert already sent for this item at this threshold
            const alertKey = `${item.id || item.name}-${threshold}`;
            const existingAlert = dataStore.warrantyAlerts.find(a => a.key === alertKey);
            if (!existingAlert) {
              alerts.push({
                key: alertKey,
                assetType: type.name,
                assetName: item.name || item.serial || 'Unknown',
                client: item.client || 'Unknown',
                expiryDate: item.warranty_expiry,
                daysLeft: daysLeft,
                threshold: threshold,
                timestamp: new Date().toISOString()
              });
            }
          }
        });
      }
    });
  });

  // Check SMA expirations for software
  dataStore.software.forEach(item => {
    if (item.sma_expiry) {
      const expiryDate = new Date(item.sma_expiry);
      const daysLeft = Math.ceil((expiryDate - now) / (1000 * 60 * 60 * 24));
      
      alertThresholds.forEach(threshold => {
        if (daysLeft === threshold || (threshold === 7 && daysLeft <= 7 && daysLeft > 0)) {
          const alertKey = `sma-${item.id || item.vendor}-${threshold}`;
          const existingAlert = dataStore.warrantyAlerts.find(a => a.key === alertKey);
          if (!existingAlert) {
            alerts.push({
              key: alertKey,
              assetType: 'Software SMA',
              assetName: item.vendor + ' (' + item.version + ')',
              client: item.client || 'Unknown',
              expiryDate: item.sma_expiry,
              daysLeft: daysLeft,
              threshold: threshold,
              timestamp: new Date().toISOString()
            });
          }
        }
      });
    }
  });

  // Send email alerts for new alerts
  alerts.forEach(alert => {
    const subject = `[CAMS] Warranty Expiration Alert - ${alert.assetType}: ${alert.assetName}`;
    const body = `
      <h2>Warranty Expiration Alert</h2>
      <p>This is a <strong>${alert.daysLeft} day</strong> notice that the warranty for <strong>${alert.assetType}</strong> "${alert.assetName}" will expire on <strong>${alert.expiryDate}</strong>.</p>
      <ul>
        <li><strong>Client:</strong> ${alert.client}</li>
        <li><strong>Days Remaining:</strong> ${alert.daysLeft}</li>
        <li><strong>Expiry Date:</strong> ${alert.expiryDate}</li>
      </ul>
      <p>Please take appropriate action.</p>
      <hr>
      <p style="color: #666; font-size: 12px;">CAMS - Client Assessment Management System</p>
    `;
    
    sendEmail('support@e-techsystemsja.com', subject, body).catch(console.error);
    
    // Store the alert
    dataStore.warrantyAlerts.push(alert);
  });

  if (alerts.length > 0) {
    saveData();
    console.log(`📧 Sent ${alerts.length} warranty alert emails`);
  }
}

// ============================================================
// ── WARRANTY ROUTES ──────────────────────────────────────────
// ============================================================

app.post('/api/warranty/check', authenticate, (req, res) => {
  // Run warranty check
  checkWarrantyExpirations();
  res.json({ success: true, message: 'Warranty alerts checked' });
});

app.get('/api/warranty/alerts', authenticate, (req, res) => {
  const alerts = dataStore.warrantyAlerts || [];
  res.json({ data: alerts });
});

app.delete('/api/warranty/alerts/:key', authenticate, requireAdmin, (req, res) => {
  const key = req.params.key;
  dataStore.warrantyAlerts = dataStore.warrantyAlerts.filter(a => a.key !== key);
  saveData();
  res.json({ success: true });
});

// ============================================================
// ── AUDIT LOG ROUTES ─────────────────────────────────────────
// ============================================================

app.post('/api/audit', authenticate, (req, res) => {
  const { user, action, target } = req.body;
  const entry = {
    id: 'audit-' + Date.now(),
    time: new Date().toLocaleTimeString(),
    user: user || req.user?.username || 'System',
    action: action || 'unknown',
    target: target || '',
    timestamp: new Date().toISOString()
  };
  if (!dataStore.auditLog) dataStore.auditLog = [];
  dataStore.auditLog.unshift(entry);
  if (dataStore.auditLog.length > 1000) {
    dataStore.auditLog = dataStore.auditLog.slice(0, 1000);
  }
  saveData();
  res.status(201).json({ data: entry });
});

app.get('/api/audit', authenticate, (req, res) => {
  const log = dataStore.auditLog || [];
  res.json({ data: log });
});

app.delete('/api/audit', authenticate, requireAdmin, (req, res) => {
  dataStore.auditLog = [];
  saveData();
  res.json({ success: true });
});

// ============================================================
// ── FILE SYSTEM ROUTES ──────────────────────────────────────
// ============================================================

app.get('/api/files', authenticate, (req, res) => {
  // Return file system structure for the file explorer
  const fileSystem = {
    name: 'CAMS Internal Database',
    type: 'folder',
    children: [
      {
        name: 'Cameras',
        type: 'folder',
        children: [
          { name: 'Camera_Maintenance_2025.csv', type: 'csv', size: '2.4 MB', modified: 'Jun 15, 2026', status: 'synced' },
          { name: 'Camera_Inventory_Master.xlsx', type: 'xlsx', size: '5.1 MB', modified: 'Jun 12, 2026', status: 'synced' }
        ]
      },
      {
        name: 'Access Control',
        type: 'folder',
        children: [
          { name: 'Access_Control_Survey.csv', type: 'csv', size: '3.2 MB', modified: 'Jun 3, 2026', status: 'synced' },
          { name: 'Door_Inventory.xlsx', type: 'xlsx', size: '1.7 MB', modified: 'Jun 10, 2026', status: 'synced' }
        ]
      },
      {
        name: 'Servers',
        type: 'folder',
        children: [
          { name: 'Server_Maintenance.csv', type: 'csv', size: '4.6 MB', modified: 'Jun 14, 2026', status: 'synced' }
        ]
      },
      {
        name: 'Switches',
        type: 'folder',
        children: [
          { name: 'Network_Switch_List.csv', type: 'csv', size: '6.8 MB', modified: 'Jun 16, 2026', status: 'synced' }
        ]
      },
      {
        name: 'Software',
        type: 'folder',
        children: [
          { name: 'Software_SMA_Tracking.csv', type: 'csv', size: '1.2 MB', modified: 'Jun 18, 2026', status: 'synced' }
        ]
      },
      {
        name: 'Client Assets',
        type: 'folder',
        children: [
          { name: 'Storage_Inventory.csv', type: 'csv', size: '0.8 MB', modified: 'Jun 17, 2026', status: 'synced' },
          { name: 'Stations_Inventory.csv', type: 'csv', size: '0.6 MB', modified: 'Jun 17, 2026', status: 'synced' },
          { name: 'Monitors_Inventory.csv', type: 'csv', size: '0.4 MB', modified: 'Jun 17, 2026', status: 'synced' }
        ]
      }
    ]
  };
  res.json({ data: fileSystem });
});

// ============================================================
// ── EXPORT ROUTES ────────────────────────────────────────────
// ============================================================

app.get('/api/export/:type', authenticate, (req, res) => {
  const type = req.params.type;
  let data = [];
  let headers = [];

  switch (type) {
    case 'cameras':
      data = dataStore.cameras.map(c => ({
        Name: c.name,
        Zone: c.zone,
        'IP Address': c.ip_address,
        Status: c.status,
        Comments: c.comments || '',
        Model: c.model || '',
        Resolution: c.resolution || '',
        Archiver: c.archiver || '',
        Client: c.client || '',
        'Purchase Date': c.purchase_date || '',
        'Warranty Expiry': c.warranty_expiry || ''
      }));
      headers = ['Name', 'Zone', 'IP Address', 'Status', 'Comments', 'Model', 'Resolution', 'Archiver', 'Client', 'Purchase Date', 'Warranty Expiry'];
      break;
    case 'doors':
      data = dataStore.doors.map(d => ({
        Name: d.name,
        Site: d.site,
        Client: d.client,
        Reader: d.reader || '',
        'Lock Type': d.lock || '',
        Powered: d.powered || '',
        Status: d.status,
        Technician: d.tech,
        'IP Address': d.ip || '',
        Controller: d.controller || '',
        'Door Swing': d.doorSwing || '',
        'Access Type': d.accessType || '',
        'Anti-Passback': d.antiPassback || '',
        'Controller Type': d.controllerType || '',
        'Purchase Date': d.purchase_date || '',
        'Warranty Expiry': d.warranty_expiry || ''
      }));
      headers = ['Name', 'Site', 'Client', 'Reader', 'Lock Type', 'Powered', 'Status', 'Technician', 'IP Address', 'Controller', 'Door Swing', 'Access Type', 'Anti-Passback', 'Controller Type', 'Purchase Date', 'Warranty Expiry'];
      break;
    case 'servers':
      data = dataStore.servers.map(s => ({
        Location: s.location,
        Serial: s.serial,
        Make: s.make || '',
        Model: s.model || '',
        Capacity: s.capacity || '',
        'In Use': s.used || '',
        Health: s.health || '',
        Applications: s.apps || '',
        Status: s.status,
        Client: s.client || '',
        'Purchase Date': s.purchase_date || '',
        'Warranty Expiry': s.warranty_expiry || ''
      }));
      headers = ['Location', 'Serial', 'Make', 'Model', 'Capacity', 'In Use', 'Health', 'Applications', 'Status', 'Client', 'Purchase Date', 'Warranty Expiry'];
      break;
    case 'switches':
      data = dataStore.switches.map(s => ({
        Name: s.name,
        Location: s.location,
        Model: s.model,
        'IP Address': s.ip_address || '',
        Firmware: s.firmware || '',
        MAC: s.mac || '',
        Client: s.client || '',
        'Purchase Date': s.purchase_date || '',
        'Warranty Expiry': s.warranty_expiry || ''
      }));
      headers = ['Name', 'Location', 'Model', 'IP Address', 'Firmware', 'MAC', 'Client', 'Purchase Date', 'Warranty Expiry'];
      break;
    case 'storage':
      data = dataStore.storage.map(s => ({
        Name: s.name,
        Client: s.client || '',
        'Total Storage': s.total || '',
        'Usable Storage': s.usable || '',
        Health: s.health || '',
        Make: s.make || '',
        Model: s.model || '',
        'Warranty Expiry': s.warranty || ''
      }));
      headers = ['Name', 'Client', 'Total Storage', 'Usable Storage', 'Health', 'Make', 'Model', 'Warranty Expiry'];
      break;
    case 'stations':
      data = dataStore.stations.map(s => ({
        Name: s.name,
        Client: s.client || '',
        Applications: s.apps || '',
        Storage: s.storage || '',
        Health: s.health || '',
        Make: s.make || '',
        Model: s.model || '',
        'Warranty Expiry': s.warranty || ''
      }));
      headers = ['Name', 'Client', 'Applications', 'Storage', 'Health', 'Make', 'Model', 'Warranty Expiry'];
      break;
    case 'monitors':
      data = dataStore.monitors.map(m => ({
        Name: m.name,
        Client: m.client || '',
        Size: m.size || '',
        Health: m.health || '',
        Make: m.make || '',
        Model: m.model || '',
        'Warranty Expiry': m.warranty || ''
      }));
      headers = ['Name', 'Client', 'Size', 'Health', 'Make', 'Model', 'Warranty Expiry'];
      break;
    case 'software':
      data = dataStore.software.map(s => ({
        Client: s.client || '',
        Vendor: s.vendor,
        Version: s.version,
        'SMA Expiry': s.sma_expiry || '',
        'License Count': s.license_count || ''
      }));
      headers = ['Client', 'Vendor', 'Version', 'SMA Expiry', 'License Count'];
      break;
    case 'service_requests':
      data = dataStore.serviceRequests.map(sr => ({
        ID: sr.id,
        Client: sr.client || '',
        Site: sr.site || '',
        Subject: sr.subject,
        Category: sr.category || '',
        Priority: sr.priority || '',
        Status: sr.status || '',
        Assigned: sr.assigned || '',
        Received: sr.received || ''
      }));
      headers = ['ID', 'Client', 'Site', 'Subject', 'Category', 'Priority', 'Status', 'Assigned', 'Received'];
      break;
    default:
      return res.status(400).json({ error: 'Invalid export type' });
  }

  // Convert to CSV
  let csv = headers.join(',') + '\n';
  data.forEach(row => {
    const values = headers.map(h => {
      const val = row[h] || '';
      return '"' + String(val).replace(/"/g, '""') + '"';
    });
    csv += values.join(',') + '\n';
  });

  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', `attachment; filename=${type}_${new Date().toISOString().slice(0,10)}.csv`);
  res.send(csv);
});

// ============================================================
// ── SERVER START ─────────────────────────────────────────────
// ============================================================

// Run warranty check every 6 hours
setInterval(checkWarrantyExpirations, 6 * 60 * 60 * 1000);

// Also check on server start
setTimeout(checkWarrantyExpirations, 5000);

app.listen(PORT, () => {
  console.log(`🚀 CAMS Server running on port ${PORT}`);
  console.log(`📊 Data stored at: ${DATA_PATH}`);
  console.log(`📧 Email notifications configured`);
});

module.exports = app;
