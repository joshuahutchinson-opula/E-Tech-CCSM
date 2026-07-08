const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(cors({
  origin: '*',
  credentials: true
}));
app.use(express.json({ limit: '50mb' }));
app.use(express.static(__dirname));

// Ensure data directory exists
const DATA_DIR = './data';
if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

// Initialize data files if they don't exist
const defaultFiles = [
  'cameras.json', 'doors.json', 'servers.json', 'switches.json', 
  'tickets.json', 'audit.json', 'inbox.json', 'clients.json', 'software.json'
];
defaultFiles.forEach(file => {
  const filePath = path.join(DATA_DIR, file);
  if (!fs.existsSync(filePath)) {
    fs.writeFileSync(filePath, '[]');
  }
});

// Helpers
function readData(file) {
  try {
    const filePath = path.join(DATA_DIR, `${file}.json`);
    if (!fs.existsSync(filePath)) {
      fs.writeFileSync(filePath, '[]');
      return [];
    }
    const data = fs.readFileSync(filePath, 'utf8');
    return data ? JSON.parse(data) : [];
  } catch (error) {
    console.error(`Error reading ${file}:`, error);
    return [];
  }
}

function writeData(file, data) {
  try {
    const filePath = path.join(DATA_DIR, `${file}.json`);
    fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
    return true;
  } catch (error) {
    console.error(`Error writing ${file}:`, error);
    return false;
  }
}

function generateId() {
  return Date.now().toString(36) + Math.random().toString(36).substr(2, 5);
}

// Device Detection
const isMobileDevice = (userAgent) => {
  return /Android|iPhone|iPod|BlackBerry|Opera Mini|IEMobile|webOS|Windows Phone|iPad|Tablet|Silk|PlayBook/i.test(userAgent);
};

app.get('/', (req, res) => {
  const userAgent = req.headers['user-agent'] || '';
  const forceMobile = req.query.mobile === 'true';
  const forceDesktop = req.query.desktop === 'true';
  
  let serveMobile = isMobileDevice(userAgent);
  if (forceMobile) serveMobile = true;
  if (forceDesktop) serveMobile = false;
  
  const file = serveMobile ? 'field-app.html' : 'index.html';
  if (fs.existsSync(path.join(__dirname, file))) {
    res.sendFile(path.join(__dirname, file));
  } else {
    res.sendFile(path.join(__dirname, 'index.html'));
  }
});

app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/field', (req, res) => {
  res.sendFile(path.join(__dirname, 'field-app.html'));
});

// Auth
app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;
  
  if (username === 'admin' && password === 'admin123') {
    return res.json({ 
      success: true, 
      token: 'admin-token-' + Date.now(), 
      user: { 
        username: 'admin', 
        role: 'Administrator', 
        isAdmin: true,
        client: null
      } 
    });
  }
  
  const techs = ['tech', 'shanice', 'shavine', 'marvin', 'ackeem'];
  if (techs.includes(username.toLowerCase()) && password === 'tech123') {
    return res.json({ 
      success: true, 
      token: 'tech-token-' + Date.now(), 
      user: { 
        username: username, 
        role: 'Field Technician', 
        isAdmin: false,
        client: null
      } 
    });
  }
  
  const clients = ['kftl', 'kwl', 'lasco', 'nestle', 'nids', 'nutrien', 'fidelity'];
  if (clients.includes(username.toLowerCase()) && password === username.toLowerCase() + '123') {
    return res.json({ 
      success: true, 
      token: 'client-token-' + Date.now(), 
      user: { 
        username: username, 
        role: 'Client User', 
        isAdmin: false,
        client: username.toLowerCase()
      } 
    });
  }
  
  res.status(401).json({ success: false, message: 'Invalid credentials' });
});

app.post('/api/auth/microsoft', (req, res) => {
  res.json({ 
    success: true,
    access_token: 'mock-token-' + Date.now(),
    user: { username: 'microsoft-user', role: 'User', isAdmin: false }
  });
});

// GET endpoints
app.get('/api/cameras', (req, res) => {
  const data = readData('cameras');
  res.json({ success: true, data, count: data.length });
});

app.get('/api/doors', (req, res) => {
  const data = readData('doors');
  res.json({ success: true, data, count: data.length });
});

app.get('/api/servers', (req, res) => {
  const data = readData('servers');
  res.json({ success: true, data, count: data.length });
});

app.get('/api/switches', (req, res) => {
  const data = readData('switches');
  res.json({ success: true, data, count: data.length });
});

app.get('/api/software', (req, res) => {
  const data = readData('software');
  res.json({ success: true, data, count: data.length });
});

app.get('/api/clients', (req, res) => {
  const data = readData('clients');
  res.json({ success: true, data, count: data.length });
});

app.get('/api/tickets', (req, res) => {
  const { status, priority, assigned, client, limit = 100 } = req.query;
  let data = readData('tickets');
  
  if (status) data = data.filter(t => t.status === status);
  if (priority) data = data.filter(t => t.priority === priority);
  if (assigned) data = data.filter(t => t.assigned === assigned);
  if (client) data = data.filter(t => t.client === client);
  
  data.sort((a, b) => new Date(b.received || b.created) - new Date(a.received || a.created));
  if (limit > 0) data = data.slice(0, parseInt(limit));
  
  res.json({ success: true, data, count: data.length, total: readData('tickets').length });
});

app.get('/api/audit', (req, res) => {
  const { limit = 100, user, action } = req.query;
  let data = readData('audit');
  
  if (user) data = data.filter(a => a.user === user);
  if (action) data = data.filter(a => a.action === action);
  
  data.sort((a, b) => new Date(b.time) - new Date(a.time));
  if (limit > 0) data = data.slice(0, parseInt(limit));
  
  res.json({ success: true, data, count: data.length });
});

app.get('/api/inbox', (req, res) => {
  const data = readData('inbox');
  res.json({ success: true, data, count: data.length });
});

// GET single items
app.get('/api/cameras/:id', (req, res) => {
  const data = readData('cameras');
  const item = data.find(c => c.id === req.params.id);
  if (item) {
    res.json({ success: true, data: item });
  } else {
    res.status(404).json({ success: false, message: 'Item not found' });
  }
});

app.get('/api/tickets/:id', (req, res) => {
  const data = readData('tickets');
  const item = data.find(t => t.id === req.params.id);
  if (item) {
    res.json({ success: true, data: item });
  } else {
    res.status(404).json({ success: false, message: 'Ticket not found' });
  }
});

// POST endpoints
app.post('/api/cameras', (req, res) => {
  try {
    const data = readData('cameras');
    const newItem = { id: generateId(), ...req.body, created: new Date().toISOString() };
    data.push(newItem);
    writeData('cameras', data);
    res.status(201).json({ success: true, data: newItem });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

app.post('/api/doors', (req, res) => {
  try {
    const data = readData('doors');
    const newItem = { id: generateId(), ...req.body, created: new Date().toISOString() };
    data.push(newItem);
    writeData('doors', data);
    res.status(201).json({ success: true, data: newItem });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

app.post('/api/tickets', (req, res) => {
  try {
    const data = readData('tickets');
    const newTicket = { 
      id: 'SR-' + String(Math.floor(Math.random() * 9000) + 1000),
      ...req.body,
      created: new Date().toISOString(),
      history: [{ time: new Date().toISOString(), msg: 'Created' }],
      attachments: []
    };
    data.push(newTicket);
    writeData('tickets', data);
    res.status(201).json({ success: true, data: newTicket });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

app.post('/api/audit', (req, res) => {
  try {
    const data = readData('audit');
    const entry = { 
      ...req.body, 
      time: new Date().toISOString(),
      id: generateId()
    };
    data.push(entry);
    writeData('audit', data);
    res.status(201).json({ success: true, data: entry });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// PUT endpoints
app.put('/api/cameras/:id', (req, res) => {
  try {
    const data = readData('cameras');
    const index = data.findIndex(c => c.id === req.params.id);
    if (index === -1) {
      return res.status(404).json({ success: false, message: 'Camera not found' });
    }
    data[index] = { ...data[index], ...req.body, updated: new Date().toISOString() };
    writeData('cameras', data);
    res.json({ success: true, data: data[index] });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

app.put('/api/doors/:id', (req, res) => {
  try {
    const data = readData('doors');
    const index = data.findIndex(d => d.id === req.params.id);
    if (index === -1) {
      return res.status(404).json({ success: false, message: 'Door not found' });
    }
    data[index] = { ...data[index], ...req.body, updated: new Date().toISOString() };
    writeData('doors', data);
    res.json({ success: true, data: data[index] });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

app.put('/api/tickets/:id', (req, res) => {
  try {
    const data = readData('tickets');
    const index = data.findIndex(t => t.id === req.params.id);
    if (index === -1) {
      return res.status(404).json({ success: false, message: 'Ticket not found' });
    }
    
    if (req.body.status && data[index].status !== req.body.status) {
      if (!data[index].history) data[index].history = [];
      data[index].history.push({
        time: new Date().toISOString(),
        msg: `Status → ${req.body.status}`
      });
    }
    
    data[index] = { ...data[index], ...req.body, updated: new Date().toISOString() };
    writeData('tickets', data);
    res.json({ success: true, data: data[index] });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// Bulk save
app.post('/api/save/:type', (req, res) => {
  const { type } = req.params;
  const validTypes = ['cameras', 'doors', 'servers', 'switches', 'tickets', 'audit', 'inbox', 'software', 'clients'];
  
  if (!validTypes.includes(type)) {
    return res.status(400).json({ success: false, message: 'Invalid data type' });
  }
  
  try {
    writeData(type, req.body);
    res.json({ success: true, count: req.body.length });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// Stats
app.get('/api/stats', (req, res) => {
  const stats = {};
  const types = ['cameras', 'doors', 'servers', 'switches', 'tickets', 'audit', 'inbox', 'software', 'clients'];
  types.forEach(type => {
    const data = readData(type);
    stats[type] = data.length;
  });
  
  const tickets = readData('tickets');
  stats.openTickets = tickets.filter(t => t.status !== 'Resolved').length;
  stats.highPriorityTickets = tickets.filter(t => t.priority === 'High' && t.status !== 'Resolved').length;
  
  res.json({ success: true, data: stats });
});

// Health check
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    memory: process.memoryUsage()
  });
});

// Catch-all
app.get('*', (req, res) => {
  const userAgent = req.headers['user-agent'] || '';
  const isMobile = isMobileDevice(userAgent);
  const file = isMobile ? 'field-app.html' : 'index.html';
  
  if (fs.existsSync(path.join(__dirname, file))) {
    res.sendFile(path.join(__dirname, file));
  } else {
    res.sendFile(path.join(__dirname, 'index.html'));
  }
});

// Start
app.listen(PORT, () => {
  console.log('🚀 CAMS Server running on port ' + PORT);
  console.log('📱 Mobile users → field-app.html (auto-detected)');
  console.log('💻 Desktop users → index.html (auto-detected)');
  console.log('📌 Direct: /admin (desktop) or /field (mobile)');
  console.log('💾 Data stored in /data/ folder');
});
