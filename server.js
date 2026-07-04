const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(cors());
app.use(express.json({ limit: '50mb' })); // For photo uploads

// Serve static files from root directory
app.use(express.static(__dirname));

// ============================================================
// ── DEVICE DETECTION ──
// ============================================================

// Main route - auto-detects device
app.get('/', (req, res) => {
  const userAgent = req.headers['user-agent'] || '';
  
  // Detect phones and tablets (mobile)
  const isPhone = /Android|iPhone|iPod|BlackBerry|Opera Mini|IEMobile|webOS|Windows Phone/i.test(userAgent);
  const isTablet = /iPad|Tablet|Silk|PlayBook/i.test(userAgent);
  const isMobile = isPhone || isTablet;
  
  // Manual override
  const forceMobile = req.query.mobile === 'true';
  const forceDesktop = req.query.desktop === 'true';
  
  let serveMobile = isMobile;
  if (forceMobile) serveMobile = true;
  if (forceDesktop) serveMobile = false;
  
  const fieldAppPath = path.join(__dirname, 'field-app.html');
  const indexAppPath = path.join(__dirname, 'index.html');
  
  if (serveMobile && fs.existsSync(fieldAppPath)) {
    res.sendFile(fieldAppPath);
  } else if (fs.existsSync(indexAppPath)) {
    res.sendFile(indexAppPath);
  } else {
    res.status(404).send('No app file found');
  }
});

// Explicit routes
app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/field', (req, res) => {
  const fieldAppPath = path.join(__dirname, 'field-app.html');
  if (fs.existsSync(fieldAppPath)) {
    res.sendFile(fieldAppPath);
  } else {
    res.status(404).send('field-app.html not found');
  }
});

// ============================================================
// ── API ROUTES ── (Shared between both apps)
// ============================================================

// GET endpoints
app.get('/api/cameras', (req, res) => {
  try {
    const data = JSON.parse(fs.readFileSync('./data/cameras.json', 'utf8') || '[]');
    res.json({ success: true, data });
  } catch {
    res.json({ success: true, data: [] });
  }
});

app.get('/api/doors', (req, res) => {
  try {
    const data = JSON.parse(fs.readFileSync('./data/doors.json', 'utf8') || '[]');
    res.json({ success: true, data });
  } catch {
    res.json({ success: true, data: [] });
  }
});

app.get('/api/servers', (req, res) => {
  try {
    const data = JSON.parse(fs.readFileSync('./data/servers.json', 'utf8') || '[]');
    res.json({ success: true, data });
  } catch {
    res.json({ success: true, data: [] });
  }
});

app.get('/api/switches', (req, res) => {
  try {
    const data = JSON.parse(fs.readFileSync('./data/switches.json', 'utf8') || '[]');
    res.json({ success: true, data });
  } catch {
    res.json({ success: true, data: [] });
  }
});

app.get('/api/tickets', (req, res) => {
  try {
    const data = JSON.parse(fs.readFileSync('./data/tickets.json', 'utf8') || '[]');
    res.json({ success: true, data });
  } catch {
    res.json({ success: true, data: [] });
  }
});

app.get('/api/audit', (req, res) => {
  try {
    const data = JSON.parse(fs.readFileSync('./data/audit.json', 'utf8') || '[]');
    res.json({ success: true, data });
  } catch {
    res.json({ success: true, data: [] });
  }
});

app.get('/api/inbox', (req, res) => {
  try {
    const data = JSON.parse(fs.readFileSync('./data/inbox.json', 'utf8') || '[]');
    res.json({ success: true, data });
  } catch {
    res.json({ success: true, data: [] });
  }
});

app.get('/api/files', (req, res) => {
  res.json({ 
    success: true, 
    data: { name: 'Root', type: 'folder', children: [] } 
  });
});

// ============================================================
// ── POST / PUT endpoints ──
// ============================================================

app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;
  
  // Check credentials
  if (username === 'admin' && password === 'admin123') {
    res.json({ 
      success: true, 
      token: 'admin-token-' + Date.now(), 
      user: { username: 'admin', role: 'Administrator', isAdmin: true } 
    });
  } else if (username === 'tech' && password === 'tech123') {
    res.json({ 
      success: true, 
      token: 'tech-token-' + Date.now(), 
      user: { username: 'tech', role: 'Field Technician', isAdmin: false } 
    });
  } else {
    res.status(401).json({ success: false, message: 'Invalid credentials' });
  }
});

app.post('/api/auth/microsoft', (req, res) => {
  res.json({ access_token: 'mock-token' });
});

// Generic save endpoint for any data
app.post('/api/save', (req, res) => {
  const { type, data } = req.body;
  const fileMap = {
    cameras: './data/cameras.json',
    doors: './data/doors.json',
    servers: './data/servers.json',
    switches: './data/switches.json',
    tickets: './data/tickets.json',
    audit: './data/audit.json',
    inbox: './data/inbox.json'
  };
  
  const filePath = fileMap[type];
  if (!filePath) {
    return res.status(400).json({ success: false, message: 'Invalid data type' });
  }
  
  try {
    // Ensure data directory exists
    if (!fs.existsSync('./data')) {
      fs.mkdirSync('./data');
    }
    fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// Ticket update
app.put('/api/tickets/:id', (req, res) => {
  try {
    const tickets = JSON.parse(fs.readFileSync('./data/tickets.json', 'utf8') || '[]');
    const index = tickets.findIndex(t => t.id === req.params.id);
    if (index !== -1) {
      tickets[index] = { ...tickets[index], ...req.body };
      fs.writeFileSync('./data/tickets.json', JSON.stringify(tickets, null, 2));
      res.json({ success: true });
    } else {
      res.status(404).json({ success: false, message: 'Ticket not found' });
    }
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// Camera update
app.put('/api/cameras/:id', (req, res) => {
  try {
    const cameras = JSON.parse(fs.readFileSync('./data/cameras.json', 'utf8') || '[]');
    const index = cameras.findIndex(c => c.id === req.params.id);
    if (index !== -1) {
      cameras[index] = { ...cameras[index], ...req.body };
      fs.writeFileSync('./data/cameras.json', JSON.stringify(cameras, null, 2));
      res.json({ success: true });
    } else {
      res.status(404).json({ success: false, message: 'Camera not found' });
    }
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// Door update
app.put('/api/doors/:id', (req, res) => {
  try {
    const doors = JSON.parse(fs.readFileSync('./data/doors.json', 'utf8') || '[]');
    const index = doors.findIndex(d => d.id === req.params.id);
    if (index !== -1) {
      doors[index] = { ...doors[index], ...req.body };
      fs.writeFileSync('./data/doors.json', JSON.stringify(doors, null, 2));
      res.json({ success: true });
    } else {
      res.status(404).json({ success: false, message: 'Door not found' });
    }
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// Server update
app.put('/api/servers/:id', (req, res) => {
  try {
    const servers = JSON.parse(fs.readFileSync('./data/servers.json', 'utf8') || '[]');
    const index = servers.findIndex(s => s.id === req.params.id);
    if (index !== -1) {
      servers[index] = { ...servers[index], ...req.body };
      fs.writeFileSync('./data/servers.json', JSON.stringify(servers, null, 2));
      res.json({ success: true });
    } else {
      res.status(404).json({ success: false, message: 'Server not found' });
    }
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// Switch update
app.put('/api/switches/:id', (req, res) => {
  try {
    const switches = JSON.parse(fs.readFileSync('./data/switches.json', 'utf8') || '[]');
    const index = switches.findIndex(s => s.id === req.params.id);
    if (index !== -1) {
      switches[index] = { ...switches[index], ...req.body };
      fs.writeFileSync('./data/switches.json', JSON.stringify(switches, null, 2));
      res.json({ success: true });
    } else {
      res.status(404).json({ success: false, message: 'Switch not found' });
    }
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// ============================================================
// ── CATCH-ALL ── Device detection for deep links
// ============================================================

app.get('*', (req, res) => {
  const userAgent = req.headers['user-agent'] || '';
  const isMobile = /Android|iPhone|iPad|iPod|BlackBerry|Opera Mini|IEMobile|webOS|Windows Phone|Tablet|Silk/i.test(userAgent);
  
  const fieldAppPath = path.join(__dirname, 'field-app.html');
  
  if (isMobile && fs.existsSync(fieldAppPath)) {
    res.sendFile(fieldAppPath);
  } else {
    res.sendFile(path.join(__dirname, 'index.html'));
  }
});

// ============================================================
// ── START SERVER ──
// ============================================================

// Ensure data directory exists
if (!fs.existsSync('./data')) {
  fs.mkdirSync('./data');
  // Initialize empty data files
  ['cameras.json', 'doors.json', 'servers.json', 'switches.json', 'tickets.json', 'audit.json', 'inbox.json'].forEach(file => {
    fs.writeFileSync(`./data/${file}`, '[]');
  });
}

app.listen(PORT, () => {
  console.log('🚀 CAMS Server running on port ' + PORT);
  console.log('📱 Mobile users → field-app.html (auto-detected)');
  console.log('💻 Desktop users → index.html (auto-detected)');
  console.log('📌 Direct: /admin (desktop) or /field (mobile)');
  console.log('💾 Data stored in /data/ folder');
});
