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

// Serve index.html for root route
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
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

// Handle all other routes - send index.html
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, () => {
  console.log('🚀 Server running on port ' + PORT);
});
