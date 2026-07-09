const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const path = require('path');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 3000;

// ============================================================
// DATABASE CONNECTION - USING YOUR EXACT STRING
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

// ============================================================
// HEALTH CHECK
// ============================================================

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', db: dbConnected ? 'connected' : 'disconnected' });
});

// ============================================================
// AUTH
// ============================================================

app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;

  if (username === 'admin' && password === 'admin123') {
    const token = jwt.sign({ id: 1, username: 'admin', client_id: 1, role: 'admin' }, process.env.JWT_SECRET || 'secret', { expiresIn: '24h' });
    return res.json({ token, user: { id: 1, username: 'admin', client_id: 1, role: 'admin' } });
  }

  if (username === 'kftl' && password === 'kftl123') {
    const token = jwt.sign({ id: 2, username: 'kftl', client_id: 1, role: 'client' }, process.env.JWT_SECRET || 'secret', { expiresIn: '24h' });
    return res.json({ token, user: { id: 2, username: 'kftl', client_id: 1, role: 'client' } });
  }

  res.status(401).json({ error: 'Invalid credentials' });
});

// ============================================================
// DASHBOARD STATS
// ============================================================

app.get('/api/dashboard/stats', async (req, res) => {
  if (!dbConnected) {
    return res.json({ health: 100, alerts: 0, offline_devices: 0, open_srs: 0, total_devices: 0, online_devices: 0 });
  }
  try {
    const cameras = await pool.query('SELECT status FROM cameras WHERE client_id = $1', [1]);
    const doors = await pool.query('SELECT status FROM doors WHERE client_id = $1', [1]);
    const servers = await pool.query('SELECT status FROM servers WHERE client_id = $1', [1]);
    const switches = await pool.query('SELECT status FROM switches WHERE client_id = $1', [1]);
    const srs = await pool.query("SELECT status FROM service_requests WHERE client_id = $1 AND status != 'Resolved'", [1]);

    const totalDevices = cameras.rowCount + doors.rowCount + servers.rowCount + switches.rowCount;
    const offline = cameras.rows.filter(c => c.status !== 'Online' && c.status !== 'Working').length +
                    doors.rows.filter(d => d.status !== 'Online' && d.status !== 'Working').length +
                    servers.rows.filter(s => s.status !== 'ONLINE').length +
                    switches.rows.filter(s => s.status !== 'Online').length;
    const online = totalDevices - offline;
    const health = totalDevices > 0 ? Math.round((online / totalDevices) * 100) : 100;

    res.json({ health, alerts: offline, offline_devices: offline, open_srs: srs.rowCount, total_devices: totalDevices, online_devices: online });
  } catch (err) {
    res.json({ health: 100, alerts: 0, offline_devices: 0, open_srs: 0, total_devices: 0, online_devices: 0 });
  }
});

// ============================================================
// CAMERAS
// ============================================================

app.get('/api/cameras', async (req, res) => {
  if (!dbConnected) return res.json([]);
  try {
    const result = await pool.query('SELECT * FROM cameras WHERE client_id = $1 ORDER BY zone, name', [1]);
    res.json(result.rows);
  } catch (err) {
    res.json([]);
  }
});

app.put('/api/cameras/:id/comment', async (req, res) => {
  if (!dbConnected) return res.status(503).json({ error: 'DB not connected' });
  const { id } = req.params;
  const { comments } = req.body;
  try {
    await pool.query('UPDATE cameras SET comments = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2 AND client_id = $3', [comments, id, 1]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/cameras/export', async (req, res) => {
  if (!dbConnected) return res.json([]);
  try {
    const result = await pool.query('SELECT * FROM cameras WHERE client_id = $1 ORDER BY zone, name', [1]);
    res.json(result.rows);
  } catch (err) {
    res.json([]);
  }
});

app.post('/api/import/cameras', async (req, res) => {
  if (!dbConnected) return res.status(503).json({ error: 'DB not connected' });

  const cameras = req.body;
  let imported = 0;

  try {
    for (const cam of cameras) {
      await pool.query(
        `INSERT INTO cameras (client_id, name, zone, status, comments, model, manufacturer, resolution, archiver, ip_address, mac_address, warranty, date_cleaned) 
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
        [1, cam.name, cam.zone, cam.status, cam.comments, cam.model, cam.manufacturer, cam.resolution, cam.archiver, cam.ip_address, cam.mac_address, cam.warranty, cam.date_cleaned]
      );
      imported++;
    }
    res.json({ success: true, imported });
  } catch (err) {
    res.status(500).json({ error: err.message, imported });
  }
});

// ============================================================
// DOORS
// ============================================================

app.get('/api/doors', async (req, res) => {
  if (!dbConnected) return res.json([]);
  try {
    const result = await pool.query('SELECT * FROM doors WHERE client_id = $1 ORDER BY zone, name', [1]);
    res.json(result.rows);
  } catch (err) {
    res.json([]);
  }
});

// ============================================================
// SERVERS
// ============================================================

app.get('/api/servers', async (req, res) => {
  if (!dbConnected) return res.json([]);
  try {
    const result = await pool.query('SELECT * FROM servers WHERE client_id = $1 ORDER BY zone, name', [1]);
    res.json(result.rows);
  } catch (err) {
    res.json([]);
  }
});

// ============================================================
// SWITCHES
// ============================================================

app.get('/api/switches', async (req, res) => {
  if (!dbConnected) return res.json([]);
  try {
    const result = await pool.query('SELECT * FROM switches WHERE client_id = $1 ORDER BY zone, name', [1]);
    res.json(result.rows);
  } catch (err) {
    res.json([]);
  }
});

// ============================================================
// SOFTWARE
// ============================================================

app.get('/api/software', async (req, res) => {
  if (!dbConnected) return res.json([]);
  try {
    const result = await pool.query('SELECT * FROM software WHERE client_id = $1 ORDER BY name', [1]);
    res.json(result.rows);
  } catch (err) {
    res.json([]);
  }
});

// ============================================================
// INTRUSION
// ============================================================

app.get('/api/intrusion', async (req, res) => {
  if (!dbConnected) return res.json([]);
  try {
    const result = await pool.query('SELECT * FROM intrusion WHERE client_id = $1 ORDER BY zone, name', [1]);
    res.json(result.rows);
  } catch (err) {
    res.json([]);
  }
});

// ============================================================
// SERVICE REQUESTS
// ============================================================

app.get('/api/service-requests', async (req, res) => {
  if (!dbConnected) return res.json([]);
  try {
    const result = await pool.query('SELECT * FROM service_requests WHERE client_id = $1 ORDER BY created_at DESC', [1]);
    for (const sr of result.rows) {
      const history = await pool.query('SELECT * FROM sr_history WHERE sr_id = $1 ORDER BY created_at', [sr.id]);
      sr.history = history.rows;
    }
    res.json(result.rows);
  } catch (err) {
    res.json([]);
  }
});

app.post('/api/service-requests', async (req, res) => {
  if (!dbConnected) return res.status(503).json({ error: 'DB not connected' });

  const { subject, category, priority, assigned_to, body } = req.body;
  const srId = `SR-${String(Math.floor(Math.random() * 9000) + 1000)}`;

  try {
    const result = await pool.query(
      `INSERT INTO service_requests (client_id, sr_id, subject, category, priority, assigned_to, body, received, created_by) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, CURRENT_DATE, $8) RETURNING *`,
      [1, srId, subject, category, priority, assigned_to, body, 'admin']
    );
    await pool.query('INSERT INTO sr_history (sr_id, time, msg) VALUES ($1, $2, $3)', [result.rows[0].id, new Date().toLocaleTimeString(), 'Created']);
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/service-requests/:id', async (req, res) => {
  if (!dbConnected) return res.status(503).json({ error: 'DB not connected' });

  const { id } = req.params;
  const { priority, assigned_to, status, notes } = req.body;

  try {
    await pool.query(
      `UPDATE service_requests SET priority = $1, assigned_to = $2, status = $3, notes = $4, updated_at = CURRENT_TIMESTAMP WHERE id = $5 AND client_id = $6`,
      [priority, assigned_to, status, notes, id, 1]
    );
    await pool.query('INSERT INTO sr_history (sr_id, time, msg) VALUES ($1, $2, $3)', [id, new Date().toLocaleTimeString(), `Updated: ${status}`]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================
// CLIENTS
// ============================================================

app.get('/api/clients', async (req, res) => {
  if (!dbConnected) return res.json([]);
  try {
    const result = await pool.query('SELECT id, name, email, phone, address, logo_url FROM clients');
    res.json(result.rows);
  } catch (err) {
    res.json([]);
  }
});

app.post('/api/clients', async (req, res) => {
  if (!dbConnected) return res.status(503).json({ error: 'DB not connected' });

  const { name, email, phone, address, logo_url } = req.body;
  try {
    const result = await pool.query(
      'INSERT INTO clients (name, email, phone, address, logo_url) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [name, email, phone, address, logo_url]
    );
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================
// ACTIVITY LOG
// ============================================================

app.get('/api/activity-log', async (req, res) => {
  if (!dbConnected) return res.json([]);
  try {
    const limit = parseInt(req.query.limit) || 100;
    const result = await pool.query('SELECT * FROM activity_log WHERE client_id = $1 ORDER BY created_at DESC LIMIT $2', [1, limit]);
    res.json(result.rows);
  } catch (err) {
    res.json([]);
  }
});

app.post('/api/activity-log', async (req, res) => {
  if (!dbConnected) return res.status(503).json({ error: 'DB not connected' });

  const { user, action, detail } = req.body;
  try {
    await pool.query('INSERT INTO activity_log (client_id, user, action, detail) VALUES ($1, $2, $3, $4)', [1, user || 'system', action, detail]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================
// EMAILS
// ============================================================

app.get('/api/emails', async (req, res) => {
  if (!dbConnected) return res.json([]);
  try {
    const folder = req.query.folder || 'inbox';
    const result = await pool.query('SELECT * FROM emails WHERE client_id = $1 AND folder = $2 ORDER BY created_at DESC', [1, folder]);
    res.json(result.rows);
  } catch (err) {
    res.json([]);
  }
});

app.post('/api/emails', async (req, res) => {
  if (!dbConnected) return res.status(503).json({ error: 'DB not connected' });

  const { sender, recipient, subject, body, folder } = req.body;
  try {
    const result = await pool.query(
      'INSERT INTO emails (client_id, sender, recipient, subject, body, folder) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *',
      [1, sender, recipient, subject, body, folder || 'inbox']
    );
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================
// SERVE HTML - index.html in SAME folder as server.js
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
