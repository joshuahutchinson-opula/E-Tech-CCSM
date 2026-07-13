const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const path = require('path');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 3000;

// ============================================================
// DATABASE CONNECTION
// ============================================================

const pool = new Pool({
  connectionString: 'postgresql://postgres:UCQFilnOQPdfXfvIKdUeXfMdaGYeCDaU@hayabusa.proxy.rlwy.net:13542/railway',
  ssl: { rejectUnauthorized: false },
  connectionTimeoutMillis: 10000,
});

let dbConnected = false;

pool.connect((err, client, release) => {
  if (err) {
    console.error('❌ DB Error:', err.message);
  } else {
    console.log('✅ DB Connected');
    dbConnected = true;
    release();
  }
});

// ============================================================
// MIDDLEWARE
// ============================================================

app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.static(__dirname));

// ============================================================
// LOGGING HELPER
// ============================================================

async function logActivity(clientId, username, action, detail) {
  if (!dbConnected) return;
  try {
    await pool.query(
      'INSERT INTO activity_log (client_id, username, action, detail) VALUES ($1, $2, $3, $4)',
      [clientId || 1, username || 'system', action, detail]
    );
  } catch (err) {
    console.error('Failed to log activity:', err.message);
  }
}

// ============================================================
// AUTH MIDDLEWARE
// ============================================================

function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    return res.status(401).json({ error: 'No token provided' });
  }
  
  const token = authHeader.split(' ')[1];
  if (!token) {
    return res.status(401).json({ error: 'Invalid token format' });
  }
  
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'secret');
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// ============================================================
// HEALTH CHECK
// ============================================================

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', db: dbConnected ? 'connected' : 'disconnected' });
});

// ============================================================
// AUTH
// ============================================================

app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;

  if (username === 'admin' && password === 'admin123') {
    const token = jwt.sign({ id: 1, username: 'admin', client_id: null, role: 'admin' }, process.env.JWT_SECRET || 'secret', { expiresIn: '24h' });
    await logActivity(1, 'admin', 'Login', 'Admin logged in');
    return res.json({ token, user: { id: 1, username: 'admin', client_id: null, role: 'admin' } });
  }

  if (username === 'kftl' && password === 'kftl123') {
    const token = jwt.sign({ id: 2, username: 'kftl', client_id: 1, role: 'client' }, process.env.JWT_SECRET || 'secret', { expiresIn: '24h' });
    await logActivity(1, 'kftl', 'Login', 'Client logged in');
    return res.json({ token, user: { id: 2, username: 'kftl', client_id: 1, role: 'client' } });
  }

  res.status(401).json({ error: 'Invalid credentials' });
});

// ============================================================
// DASHBOARD STATS
// ============================================================

app.get('/api/dashboard/stats', authMiddleware, async (req, res) => {
  if (!dbConnected) {
    return res.json({ health: 100, alerts: 0, offline_devices: 0, open_srs: 0, total_devices: 0, online_devices: 0 });
  }
  
  try {
    let cameras, doors, servers, switches, srs;
    
    if (req.user.role === 'admin') {
      cameras = await pool.query('SELECT status FROM cameras');
      doors = await pool.query('SELECT status FROM doors');
      servers = await pool.query('SELECT status FROM servers');
      switches = await pool.query('SELECT status FROM switches');
      srs = await pool.query("SELECT status FROM service_requests WHERE status != 'Resolved'");
    } else {
      const clientId = req.user.client_id;
      cameras = await pool.query('SELECT status FROM cameras WHERE client_id = $1', [clientId]);
      doors = await pool.query('SELECT status FROM doors WHERE client_id = $1', [clientId]);
      servers = await pool.query('SELECT status FROM servers WHERE client_id = $1', [clientId]);
      switches = await pool.query('SELECT status FROM switches WHERE client_id = $1', [clientId]);
      srs = await pool.query("SELECT status FROM service_requests WHERE client_id = $1 AND status != 'Resolved'", [clientId]);
    }

    const totalDevices = cameras.rowCount + doors.rowCount + servers.rowCount + switches.rowCount;
    const offline = cameras.rows.filter(c => c.status !== 'Online' && c.status !== 'Working').length +
                    doors.rows.filter(d => d.status !== 'Online' && d.status !== 'Working').length +
                    servers.rows.filter(s => s.status !== 'ONLINE').length +
                    switches.rows.filter(s => s.status !== 'Online').length;
    const online = totalDevices - offline;
    const health = totalDevices > 0 ? Math.round((online / totalDevices) * 100) : 100;

    res.json({ 
      health, 
      alerts: offline, 
      offline_devices: offline, 
      open_srs: srs.rowCount, 
      total_devices: totalDevices, 
      online_devices: online 
    });
  } catch (err) {
    console.error('Dashboard stats error:', err);
    res.json({ health: 100, alerts: 0, offline_devices: 0, open_srs: 0, total_devices: 0, online_devices: 0 });
  }
});

// ============================================================
// CAMERAS
// ============================================================

app.get('/api/cameras', authMiddleware, async (req, res) => {
  if (!dbConnected) return res.json([]);
  try {
    const clientId = req.user.role === 'admin' ? null : req.user.client_id;
    const query = clientId ? 'SELECT * FROM cameras WHERE client_id = $1 ORDER BY zone, name' : 'SELECT * FROM cameras ORDER BY zone, name';
    const params = clientId ? [clientId] : [];
    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (err) {
    res.json([]);
  }
});

app.put('/api/cameras/:id', authMiddleware, async (req, res) => {
  if (!dbConnected) return res.status(503).json({ error: 'DB not connected' });
  const { id } = req.params;
  const { status, comments } = req.body;
  try {
    const clientId = req.user.role === 'admin' ? null : req.user.client_id;
    const query = clientId ? 
      'UPDATE cameras SET status = COALESCE($1, status), comments = COALESCE($2, comments), updated_at = CURRENT_TIMESTAMP WHERE id = $3 AND client_id = $4' :
      'UPDATE cameras SET status = COALESCE($1, status), comments = COALESCE($2, comments), updated_at = CURRENT_TIMESTAMP WHERE id = $3';
    const params = clientId ? [status, comments, id, clientId] : [status, comments, id];
    await pool.query(query, params);
    
    const logClientId = clientId || 1;
    await logActivity(logClientId, req.user.username, 'Updated', 'Camera ' + id + ' updated');
    
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/cameras/:id/comment', authMiddleware, async (req, res) => {
  if (!dbConnected) return res.status(503).json({ error: 'DB not connected' });
  const { id } = req.params;
  const { comments } = req.body;
  try {
    const clientId = req.user.role === 'admin' ? null : req.user.client_id;
    const query = clientId ? 'UPDATE cameras SET comments = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2 AND client_id = $3' : 'UPDATE cameras SET comments = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2';
    const params = clientId ? [comments, id, clientId] : [comments, id];
    await pool.query(query, params);
    
    const logClientId = clientId || 1;
    await logActivity(logClientId, req.user.username, 'Updated', 'Camera ' + id + ' comment updated');
    
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/cameras/export', authMiddleware, async (req, res) => {
  if (!dbConnected) return res.json([]);
  try {
    const clientId = req.user.role === 'admin' ? null : req.user.client_id;
    const query = clientId ? 'SELECT * FROM cameras WHERE client_id = $1 ORDER BY zone, name' : 'SELECT * FROM cameras ORDER BY zone, name';
    const params = clientId ? [clientId] : [];
    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (err) {
    res.json([]);
  }
});

app.post('/api/import/cameras', authMiddleware, async (req, res) => {
  if (!dbConnected) return res.status(503).json({ error: 'DB not connected' });
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });

  const cameras = req.body;
  let imported = 0;

  try {
    for (const cam of cameras) {
      await pool.query(
        `INSERT INTO cameras (client_id, name, zone, status, comments, model, manufacturer, resolution, archiver, ip_address, mac_address, warranty, date_cleaned) 
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
        [cam.client_id || 1, cam.name || '', cam.zone || '', cam.status || 'Working', cam.comments || '', cam.model || '', cam.manufacturer || '', cam.resolution || '', cam.archiver || '', cam.ip_address || '', cam.mac_address || '', cam.warranty || '', cam.date_cleaned || null]
      );
      imported++;
    }
    
    await logActivity(1, req.user.username, 'Import', 'Imported ' + imported + ' cameras');
    res.json({ success: true, imported });
  } catch (err) {
    res.status(500).json({ error: err.message, imported });
  }
});

// ============================================================
// DOORS
// ============================================================

app.get('/api/doors', authMiddleware, async (req, res) => {
  if (!dbConnected) return res.json([]);
  try {
    const clientId = req.user.role === 'admin' ? null : req.user.client_id;
    const query = clientId ? 'SELECT * FROM doors WHERE client_id = $1 ORDER BY zone, name' : 'SELECT * FROM doors ORDER BY zone, name';
    const params = clientId ? [clientId] : [];
    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (err) {
    res.json([]);
  }
});

app.put('/api/doors/:id', authMiddleware, async (req, res) => {
  if (!dbConnected) return res.status(503).json({ error: 'DB not connected' });
  const { id } = req.params;
  const { status, comments } = req.body;
  try {
    const clientId = req.user.role === 'admin' ? null : req.user.client_id;
    const query = clientId ? 
      'UPDATE doors SET status = COALESCE($1, status), comments = COALESCE($2, comments), updated_at = CURRENT_TIMESTAMP WHERE id = $3 AND client_id = $4' :
      'UPDATE doors SET status = COALESCE($1, status), comments = COALESCE($2, comments), updated_at = CURRENT_TIMESTAMP WHERE id = $3';
    const params = clientId ? [status, comments, id, clientId] : [status, comments, id];
    await pool.query(query, params);
    
    const logClientId = clientId || 1;
    await logActivity(logClientId, req.user.username, 'Updated', 'Door ' + id + ' updated');
    
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================
// SERVERS
// ============================================================

app.get('/api/servers', authMiddleware, async (req, res) => {
  if (!dbConnected) return res.json([]);
  try {
    const clientId = req.user.role === 'admin' ? null : req.user.client_id;
    const query = clientId ? 'SELECT * FROM servers WHERE client_id = $1 ORDER BY zone, name' : 'SELECT * FROM servers ORDER BY zone, name';
    const params = clientId ? [clientId] : [];
    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (err) {
    res.json([]);
  }
});

app.put('/api/servers/:id', authMiddleware, async (req, res) => {
  if (!dbConnected) return res.status(503).json({ error: 'DB not connected' });
  const { id } = req.params;
  const { status, comments } = req.body;
  try {
    const clientId = req.user.role === 'admin' ? null : req.user.client_id;
    const query = clientId ? 
      'UPDATE servers SET status = COALESCE($1, status), comments = COALESCE($2, comments), updated_at = CURRENT_TIMESTAMP WHERE id = $3 AND client_id = $4' :
      'UPDATE servers SET status = COALESCE($1, status), comments = COALESCE($2, comments), updated_at = CURRENT_TIMESTAMP WHERE id = $3';
    const params = clientId ? [status, comments, id, clientId] : [status, comments, id];
    await pool.query(query, params);
    
    const logClientId = clientId || 1;
    await logActivity(logClientId, req.user.username, 'Updated', 'Server ' + id + ' updated');
    
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================
// SWITCHES
// ============================================================

app.get('/api/switches', authMiddleware, async (req, res) => {
  if (!dbConnected) return res.json([]);
  try {
    const clientId = req.user.role === 'admin' ? null : req.user.client_id;
    const query = clientId ? 'SELECT * FROM switches WHERE client_id = $1 ORDER BY zone, name' : 'SELECT * FROM switches ORDER BY zone, name';
    const params = clientId ? [clientId] : [];
    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (err) {
    res.json([]);
  }
});

app.put('/api/switches/:id', authMiddleware, async (req, res) => {
  if (!dbConnected) return res.status(503).json({ error: 'DB not connected' });
  const { id } = req.params;
  const { status, comments } = req.body;
  try {
    const clientId = req.user.role === 'admin' ? null : req.user.client_id;
    const query = clientId ? 
      'UPDATE switches SET status = COALESCE($1, status), comments = COALESCE($2, comments), updated_at = CURRENT_TIMESTAMP WHERE id = $3 AND client_id = $4' :
      'UPDATE switches SET status = COALESCE($1, status), comments = COALESCE($2, comments), updated_at = CURRENT_TIMESTAMP WHERE id = $3';
    const params = clientId ? [status, comments, id, clientId] : [status, comments, id];
    await pool.query(query, params);
    
    const logClientId = clientId || 1;
    await logActivity(logClientId, req.user.username, 'Updated', 'Switch ' + id + ' updated');
    
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================
// SOFTWARE
// ============================================================

app.get('/api/software', authMiddleware, async (req, res) => {
  if (!dbConnected) return res.json([]);
  try {
    const clientId = req.user.role === 'admin' ? null : req.user.client_id;
    const query = clientId ? 'SELECT * FROM software WHERE client_id = $1 ORDER BY name' : 'SELECT * FROM software ORDER BY name';
    const params = clientId ? [clientId] : [];
    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (err) {
    res.json([]);
  }
});

// ============================================================
// INTRUSION
// ============================================================

app.get('/api/intrusion', authMiddleware, async (req, res) => {
  if (!dbConnected) return res.json([]);
  try {
    const clientId = req.user.role === 'admin' ? null : req.user.client_id;
    const query = clientId ? 'SELECT * FROM intrusion WHERE client_id = $1 ORDER BY zone, name' : 'SELECT * FROM intrusion ORDER BY zone, name';
    const params = clientId ? [clientId] : [];
    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (err) {
    res.json([]);
  }
});

app.put('/api/intrusion/:id', authMiddleware, async (req, res) => {
  if (!dbConnected) return res.status(503).json({ error: 'DB not connected' });
  const { id } = req.params;
  const { status, comments } = req.body;
  try {
    const clientId = req.user.role === 'admin' ? null : req.user.client_id;
    const query = clientId ? 
      'UPDATE intrusion SET status = COALESCE($1, status), comments = COALESCE($2, comments), updated_at = CURRENT_TIMESTAMP WHERE id = $3 AND client_id = $4' :
      'UPDATE intrusion SET status = COALESCE($1, status), comments = COALESCE($2, comments), updated_at = CURRENT_TIMESTAMP WHERE id = $3';
    const params = clientId ? [status, comments, id, clientId] : [status, comments, id];
    await pool.query(query, params);
    
    const logClientId = clientId || 1;
    await logActivity(logClientId, req.user.username, 'Updated', 'Intrusion point ' + id + ' updated');
    
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================
// SERVICE REQUESTS
// ============================================================

app.get('/api/service-requests', authMiddleware, async (req, res) => {
  if (!dbConnected) return res.json([]);
  try {
    const clientId = req.user.role === 'admin' ? null : req.user.client_id;
    const query = clientId ? 'SELECT * FROM service_requests WHERE client_id = $1 ORDER BY created_at DESC' : 'SELECT * FROM service_requests ORDER BY created_at DESC';
    const params = clientId ? [clientId] : [];
    const result = await pool.query(query, params);
    for (const sr of result.rows) {
      const history = await pool.query('SELECT * FROM sr_history WHERE sr_id = $1 ORDER BY created_at', [sr.id]);
      sr.history = history.rows;
    }
    res.json(result.rows);
  } catch (err) {
    res.json([]);
  }
});

app.post('/api/service-requests', authMiddleware, async (req, res) => {
  if (!dbConnected) return res.status(503).json({ error: 'DB not connected' });

  const { subject, client, site, category, priority, assigned_to, body } = req.body;
  const srId = `SR-${String(Math.floor(Math.random() * 9000) + 1000)}`;
  const clientId = req.user.role === 'admin' ? 1 : req.user.client_id;

  try {
    const result = await pool.query(
      `INSERT INTO service_requests (client_id, sr_id, subject, client, site, category, priority, assigned_to, body, received, created_by) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, CURRENT_DATE, $10) RETURNING *`,
      [clientId, srId, subject, client, site, category, priority, assigned_to, body, req.user.username]
    );
    await pool.query('INSERT INTO sr_history (sr_id, time, msg) VALUES ($1, $2, $3)', [result.rows[0].id, new Date().toLocaleTimeString(), 'Created']);
    
    await logActivity(clientId, req.user.username, 'Created', 'SR ' + srId + ' created for ' + client);
    
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/service-requests/:id', authMiddleware, async (req, res) => {
  if (!dbConnected) return res.status(503).json({ error: 'DB not connected' });

  const { id } = req.params;
  const { priority, assigned_to, status, notes } = req.body;
  const clientId = req.user.role === 'admin' ? null : req.user.client_id;

  try {
    const query = clientId ? 
      `UPDATE service_requests SET priority = $1, assigned_to = $2, status = $3, notes = $4, updated_at = CURRENT_TIMESTAMP WHERE id = $5 AND client_id = $6` :
      `UPDATE service_requests SET priority = $1, assigned_to = $2, status = $3, notes = $4, updated_at = CURRENT_TIMESTAMP WHERE id = $5`;
    const params = clientId ? [priority, assigned_to, status, notes, id, clientId] : [priority, assigned_to, status, notes, id];
    await pool.query(query, params);
    await pool.query('INSERT INTO sr_history (sr_id, time, msg) VALUES ($1, $2, $3)', [id, new Date().toLocaleTimeString(), `Updated: ${status}`]);
    
    const logClientId = clientId || 1;
    await logActivity(logClientId, req.user.username, 'Updated', 'SR ' + id + ' updated to ' + status);
    
    const updated = await pool.query('SELECT * FROM service_requests WHERE id = $1', [id]);
    res.json({ success: true, data: updated.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================
// CLIENTS
// ============================================================

app.get('/api/clients', authMiddleware, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  if (!dbConnected) return res.json([]);
  try {
    const result = await pool.query('SELECT id, name, email, phone, address, logo_url FROM clients');
    res.json(result.rows);
  } catch (err) {
    res.json([]);
  }
});

app.post('/api/clients', authMiddleware, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  if (!dbConnected) return res.status(503).json({ error: 'DB not connected' });

  const { name, email, phone, address, logo_url } = req.body;
  try {
    const result = await pool.query(
      'INSERT INTO clients (name, email, phone, address, logo_url) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [name, email, phone, address, logo_url]
    );
    
    await logActivity(1, req.user.username, 'Created', 'Client ' + name + ' added');
    
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// UPDATE CLIENT
app.put('/api/clients/:name', authMiddleware, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  if (!dbConnected) return res.status(503).json({ error: 'DB not connected' });

  const { name } = req.params;
  const { email, phone, address, logo_url } = req.body;
  
  try {
    const result = await pool.query(
      'UPDATE clients SET email = $1, phone = $2, address = $3, logo_url = $4, updated_at = CURRENT_TIMESTAMP WHERE name = $5 RETURNING *',
      [email || '', phone || '', address || '', logo_url || '', name]
    );
    
    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'Client not found' });
    }
    
    await logActivity(1, req.user.username, 'Updated', 'Client ' + name + ' updated');
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// DELETE CLIENT
app.delete('/api/clients/:name', authMiddleware, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  if (!dbConnected) return res.status(503).json({ error: 'DB not connected' });

  const { name } = req.params;
  
  try {
    const result = await pool.query('DELETE FROM clients WHERE name = $1', [name]);
    
    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'Client not found' });
    }
    
    await logActivity(1, req.user.username, 'Deleted', 'Client ' + name + ' deleted');
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================
// ACTIVITY LOG
// ============================================================

app.get('/api/activity-log', authMiddleware, async (req, res) => {
  if (!dbConnected) return res.json([]);
  try {
    const limit = parseInt(req.query.limit) || 100;
    const clientId = req.user.role === 'admin' ? null : req.user.client_id;
    const query = clientId ? 
      'SELECT id, client_id, username, action, detail, created_at FROM activity_log WHERE client_id = $1 ORDER BY created_at DESC LIMIT $2' :
      'SELECT id, client_id, username, action, detail, created_at FROM activity_log ORDER BY created_at DESC LIMIT $1';
    const params = clientId ? [clientId, limit] : [limit];
    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (err) {
    res.json([]);
  }
});

app.post('/api/activity-log', authMiddleware, async (req, res) => {
  if (!dbConnected) return res.status(503).json({ error: 'DB not connected' });

  const { action, detail } = req.body;
  const clientId = req.user.role === 'admin' ? 1 : req.user.client_id;
  try {
    await pool.query('INSERT INTO activity_log (client_id, username, action, detail) VALUES ($1, $2, $3, $4)', [clientId, req.user.username, action, detail]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================
// EMAILS
// ============================================================

app.get('/api/emails', authMiddleware, async (req, res) => {
  if (!dbConnected) return res.json([]);
  try {
    const folder = req.query.folder || 'inbox';
    const clientId = req.user.role === 'admin' ? null : req.user.client_id;
    const query = clientId ? 
      'SELECT * FROM emails WHERE client_id = $1 AND folder = $2 ORDER BY created_at DESC' :
      'SELECT * FROM emails WHERE folder = $1 ORDER BY created_at DESC';
    const params = clientId ? [clientId, folder] : [folder];
    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (err) {
    res.json([]);
  }
});

app.post('/api/emails', authMiddleware, async (req, res) => {
  if (!dbConnected) return res.status(503).json({ error: 'DB not connected' });

  const { sender, recipient, subject, body, folder } = req.body;
  const clientId = req.user.role === 'admin' ? 1 : req.user.client_id;
  try {
    const result = await pool.query(
      'INSERT INTO emails (client_id, sender, recipient, subject, body, folder) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *',
      [clientId, sender, recipient, subject, body, folder || 'inbox']
    );
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================
// SERVE HTML
// ============================================================

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// ============================================================
// START
// ============================================================

app.listen(port, () => {
  console.log(`🚀 Running on port ${port}`);
  console.log(`📊 DB: ${dbConnected ? '✅ Connected' : '❌ Disconnected'}`);
});
