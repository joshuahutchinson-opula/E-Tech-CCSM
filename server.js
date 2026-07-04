const express = require('express');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(cors());
app.use(express.json());

// Serve static files from root directory
app.use(express.static(__dirname));

// Device detection middleware - serves appropriate version
app.get('/', (req, res) => {
  const userAgent = req.headers['user-agent'] || '';
  const isMobile = /Android|iPhone|iPad|iPod|BlackBerry|Opera Mini|IEMobile|webOS|Windows Phone/i.test(userAgent);
  
  // Allow manual override via query params
  const forceMobile = req.query.mobile === 'true';
  const forceDesktop = req.query.desktop === 'true';
  
  let serveMobile = isMobile;
  if (forceMobile) serveMobile = true;
  if (forceDesktop) serveMobile = false;
  
  if (serveMobile) {
    // Check if field-app.html exists, fallback to index.html
    const fs = require('fs');
    const fieldAppPath = path.join(__dirname, 'field-app.html');
    if (fs.existsSync(fieldAppPath)) {
      res.sendFile(fieldAppPath);
    } else {
      console.warn('⚠️ field-app.html not found, serving index.html');
      res.sendFile(path.join(__dirname, 'index.html'));
    }
  } else {
    res.sendFile(path.join(__dirname, 'index.html'));
  }
});

// Explicit route for admin dashboard (desktop)
app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Explicit route for field app (mobile)
app.get('/field', (req, res) => {
  const fs = require('fs');
  const fieldAppPath = path.join(__dirname, 'field-app.html');
  if (fs.existsSync(fieldAppPath)) {
    res.sendFile(fieldAppPath);
  } else {
    res.status(404).send('field-app.html not found. Please create the file.');
  }
});

// API routes
app.get('/api/cameras', (req, res) => {
  res.json({ data: [] });
});

app.get('/api/doors', (req, res) => {
  res.json({ data: [] });
});

app.get('/api/servers', (req, res) => {
  res.json({ data: [] });
});

app.get('/api/switches', (req, res) => {
  res.json({ data: [] });
});

app.get('/api/tickets', (req, res) => {
  res.json({ data: [] });
});

app.get('/api/audit', (req, res) => {
  res.json({ data: [] });
});

app.get('/api/inbox', (req, res) => {
  res.json({ data: [] });
});

app.post('/api/auth/login', (req, res) => {
  res.json({ token: 'mock-token', user: { username: 'admin', role: 'Administrator', isAdmin: true } });
});

app.post('/api/auth/microsoft', (req, res) => {
  res.json({ access_token: 'mock-token' });
});

app.post('/api/tickets', (req, res) => {
  res.status(201).json({ data: req.body });
});

app.put('/api/cameras/:id', (req, res) => {
  res.json({ success: true });
});

app.put('/api/doors/:id', (req, res) => {
  res.json({ success: true });
});

app.put('/api/servers/:id', (req, res) => {
  res.json({ success: true });
});

app.put('/api/switches/:id', (req, res) => {
  res.json({ success: true });
});

app.put('/api/tickets/:id', (req, res) => {
  res.json({ success: true });
});

app.post('/api/audit', (req, res) => {
  res.status(201).json({ data: req.body });
});

app.get('/api/files', (req, res) => {
  res.json({ data: { name: 'Root', type: 'folder', children: [] } });
});

// Handle all other routes - serve appropriate version based on device
app.get('*', (req, res) => {
  const userAgent = req.headers['user-agent'] || '';
  const isMobile = /Android|iPhone|iPad|iPod|BlackBerry|Opera Mini|IEMobile|webOS|Windows Phone/i.test(userAgent);
  
  const fs = require('fs');
  const fieldAppPath = path.join(__dirname, 'field-app.html');
  
  if (isMobile && fs.existsSync(fieldAppPath)) {
    res.sendFile(fieldAppPath);
  } else {
    res.sendFile(path.join(__dirname, 'index.html'));
  }
});

app.listen(PORT, () => {
  console.log('🚀 Server running on port ' + PORT);
  console.log('📱 Mobile users → field-app.html (auto-detected)');
  console.log('💻 Desktop users → index.html (auto-detected)');
  console.log('🔗 Override: ?mobile=true or ?desktop=true');
  console.log('📌 Direct: /admin (desktop) or /field (mobile)');
});
