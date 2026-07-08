const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(cors());
app.use(express.json({ limit: '50mb' }));

// Serve static files from root directory
app.use(express.static(__dirname));

// Ensure data directory exists
if (!fs.existsSync('./data')) {
  fs.mkdirSync('./data');
  ['cameras.json', 'doors.json', 'servers.json', 'switches.json', 'tickets.json', 'audit.json', 'inbox.json'].forEach(file => {
    if (!fs.existsSync(`./data/${file}`)) {
      fs.writeFileSync(`./data/${file}`, '[]');
    }
  });
}

// ============================================================
// ── DEVICE DETECTION ──
// ============================================================

app.get('/', (req, res) => {
  const userAgent = req.headers['user-agent'] || '';
  
  // Detect mobile devices (phones + tablets)
  const isPhone = /Android|iPhone|iPod|BlackBerry|Opera Mini|IEMobile|webOS|Windows Phone/i.test(userAgent);
  const isTablet = /iPad|Tablet|Silk|PlayBook/i.test(userAgent);
  const isMobile = isPhone || isTablet;
  
  // Manual override
  const forceMobile = req.query.mobile === 'true';
  const forceDesktop = req.query.desktop === 'true';
  
  let serveMobile = isMobile;
  if (forceMobile) serveMobile = true;
  if (forceDesktop) serveMobile = false;
  
  if (serveMobile && fs.existsSync(path.join(__dirname, 'field-app.html'))) {
    res.sendFile(path.join(__dirname, 'field-app.html'));
  } else {
    res.sendFile(path.join(__dirname, 'index.html'));
  }
});

// Explicit routes
app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/field', (req, res) => {
  res.sendFile(path.join(__dirname, 'field-app.html'));
});

// ============================================================
// ── API ROUTES (Shared between both apps) ──
// ============================================================

// Helper to read/write data
function readData(file) {
  try {
    return JSON.parse(fs.readFileSync(`./data/${file}.json`, 'utf8') || '[]');
  } catch {
    return [];
  }
}
function writeData(file, data) {
  fs.writeFileSync(`./data/${file}.json`, JSON.stringify(data, null, 2));
}

// GET endpoints
app.get('/api/cameras', (req, res) => {
  res.json({ success: true, data: readData('cameras') });
});

app.get('/api/doors', (req, res) => {
  res.json({ success: true, data: readData('doors') });
});

app.get('/api/servers', (req, res) => {
  res.json({ success: true, data: readData('servers') });
});

app.get('/api/switches', (req, res) => {
  res.json({ success: true, data: readData('switches') });
});

app.get('/api/tickets', (req, res) => {
  res.json({ success: true, data: readData('tickets') });
});

app.get('/api/audit', (req, res) => {
  res.json({ success: true, data: readData('audit') });
});

app.get('/api/inbox', (req, res) => {
  res.json({ success: true, data: readData('inbox') });
});

app.get('/api/files', (req, res) => {
  res.json({ success: true, data: { name: 'Root', type: 'folder', children: [] } });
});

// POST / PUT endpoints
app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;
  
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

// Generic save endpoint
app.post('/api/save/:type', (req, res) => {
  const { type } = req.params;
  const validTypes = ['cameras', 'doors', 'servers', 'switches', 'tickets', 'audit', 'inbox'];
  
  if (!validTypes.includes(type)) {
    return res.status(400).json({ success: false, message: 'Invalid data type' });
  }
  
  try {
    writeData(type, req.body);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// Individual update endpoints
app.put('/api/cameras/:id', (req, res) => {
  try {
    const data = readData('cameras');
    const index = data.findIndex(c => c.id === req.params.id);
    if (index !== -1) {
      data[index] = { ...data[index], ...req.body };
      writeData('cameras', data);
      res.json({ success: true });
    } else {
      res.status(404).json({ success: false, message: 'Camera not found' });
    }
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

app.put('/api/doors/:id', (req, res) => {
  try {
    const data = readData('doors');
    const index = data.findIndex(d => d.id === req.params.id);
    if (index !== -1) {
      data[index] = { ...data[index], ...req.body };
      writeData('doors', data);
      res.json({ success: true });
    } else {
      res.status(404).json({ success: false, message: 'Door not found' });
    }
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

app.put('/api/servers/:id', (req, res) => {
  try {
    const data = readData('servers');
    const index = data.findIndex(s => s.id === req.params.id);
    if (index !== -1) {
      data[index] = { ...data[index], ...req.body };
      writeData('servers', data);
      res.json({ success: true });
    } else {
      res.status(404).json({ success: false, message: 'Server not found' });
    }
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

app.put('/api/switches/:id', (req, res) => {
  try {
    const data = readData('switches');
    const index = data.findIndex(s => s.id === req.params.id);
    if (index !== -1) {
      data[index] = { ...data[index], ...req.body };
      writeData('switches', data);
      res.json({ success: true });
    } else {
      res.status(404).json({ success: false, message: 'Switch not found' });
    }
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

app.put('/api/tickets/:id', (req, res) => {
  try {
    const data = readData('tickets');
    const index = data.findIndex(t => t.id === req.params.id);
    if (index !== -1) {
      data[index] = { ...data[index], ...req.body };
      writeData('tickets', data);
      res.json({ success: true });
    } else {
      res.status(404).json({ success: false, message: 'Ticket not found' });
    }
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

app.post('/api/tickets', (req, res) => {
  try {
    const data = readData('tickets');
    data.push(req.body);
    writeData('tickets', data);
    res.status(201).json({ success: true, data: req.body });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

app.post('/api/audit', (req, res) => {
  try {
    const data = readData('audit');
    data.push(req.body);
    writeData('audit', data);
    res.status(201).json({ success: true, data: req.body });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// ============================================================
// ── CATCH-ALL ──
// ============================================================

app.get('*', (req, res) => {
  const userAgent = req.headers['user-agent'] || '';
  const isMobile = /Android|iPhone|iPad|iPod|BlackBerry|Opera Mini|IEMobile|webOS|Windows Phone|Tablet|Silk/i.test(userAgent);
  
  if (isMobile && fs.existsSync(path.join(__dirname, 'field-app.html'))) {
    res.sendFile(path.join(__dirname, 'field-app.html'));
  } else {
    res.sendFile(path.join(__dirname, 'index.html'));
  }
});

// ============================================================
// ── START ──
// ============================================================

app.listen(PORT, () => {
  console.log('🚀 CAMS Server running on port ' + PORT);
  console.log('📱 Mobile users → field-app.html (auto-detected)');
  console.log('💻 Desktop users → index.html (auto-detected)');
  console.log('📌 Direct: /admin (desktop) or /field (mobile)');
  console.log('💾 Data stored in /data/ folder');
});
