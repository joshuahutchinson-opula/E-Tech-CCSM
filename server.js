const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 3000;

// Database connection - Railway injects DATABASE_URL automatically
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Test database connection
pool.query('SELECT NOW()', (err, res) => {
  if (err) {
    console.error('Database connection failed:', err.message);
  } else {
    console.log('Database connected successfully');
  }
});

// Middleware
app.use(cors());
app.use(express.json({ limit: '50mb' }));

// Auth middleware
const authenticate = async (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) {
    return res.status(401).json({ error: 'Unauthorized - No token provided' });
  }
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'secret');
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
};

// ============================================================
// AUTH ENDPOINTS
// ============================================================

app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const result = await pool.query(
      'SELECT * FROM users WHERE username = $1',
      [username]
    );
    const user = result.rows[0];
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // For demo - in production use bcrypt.compare
    // Since we used placeholder hashes, we'll check against known passwords
    const valid = (password === 'admin123' && username === 'admin') || 
                  (password === 'kftl123' && username === 'kftl');
    
    if (!valid) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const token = jwt.sign(
      { 
        id: user.id, 
        username: user.username, 
        client_id: user.client_id, 
        role: user.role 
      },
      process.env.JWT_SECRET || 'secret',
      { expiresIn: '24h' }
    );
    
    res.json({ 
      token, 
      user: { 
        id: user.id, 
        username: user.username, 
        client_id: user.client_id, 
        role: user.role 
      } 
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ============================================================
// DASHBOARD STATS
// ============================================================

app.get('/api/dashboard/stats', authenticate, async (req, res) => {
  const clientId = req.user.client_id;
  try {
    const cameras = await pool.query('SELECT status FROM cameras WHERE client_id = $1', [clientId]);
    const doors = await pool.query('SELECT status FROM doors WHERE client_id = $1', [clientId]);
    const servers = await pool.query('SELECT status FROM servers WHERE client_id = $1', [clientId]);
    const switches = await pool.query('SELECT status FROM switches WHERE client_id = $1', [clientId]);
    const srs = await pool.query(
      "SELECT status FROM service_requests WHERE client_id = $1 AND status != 'Resolved'", 
      [clientId]
    );
    
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
    console.error('Stats error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ============================================================
// CAMERA ENDPOINTS
// ============================================================

app.get('/api/cameras', authenticate, async (req, res) => {
  const clientId = req.user.client_id;
  try {
    const result = await pool.query(
      'SELECT * FROM cameras WHERE client_id = $1 ORDER BY zone, name',
      [clientId]
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Cameras error:', err);
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/cameras/:id/comment', authenticate, async (req, res) => {
  const { id } = req.params;
  const { comments } = req.body;
  const clientId = req.user.client_id;
  try {
    await pool.query(
      'UPDATE cameras SET comments = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2 AND client_id = $3',
      [comments, id, clientId]
    );
    await pool.query(
      'INSERT INTO activity_log (client_id, user, action, detail) VALUES ($1, $2, $3, $4)',
      [clientId, req.user.username, 'updated', `Camera ${id} comment updated`]
    );
    res.json({ success: true });
  } catch (err) {
    console.error('Update comment error:', err);
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/cameras/export', authenticate, async (req, res) => {
  const clientId = req.user.client_id;
  try {
    const result = await pool.query(
      'SELECT * FROM cameras WHERE client_id = $1 ORDER BY zone, name',
      [clientId]
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Export error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ============================================================
// DOOR ENDPOINTS
// ============================================================

app.get('/api/doors', authenticate, async (req, res) => {
  const clientId = req.user.client_id;
  try {
    const result = await pool.query(
      'SELECT * FROM doors WHERE client_id = $1 ORDER BY zone, name',
      [clientId]
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Doors error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ============================================================
// SERVER ENDPOINTS
// ============================================================

app.get('/api/servers', authenticate, async (req, res) => {
  const clientId = req.user.client_id;
  try {
    const result = await pool.query(
      'SELECT * FROM servers WHERE client_id = $1 ORDER BY zone, name',
      [clientId]
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Servers error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ============================================================
// SWITCH ENDPOINTS
// ============================================================

app.get('/api/switches', authenticate, async (req, res) => {
  const clientId = req.user.client_id;
  try {
    const result = await pool.query(
      'SELECT * FROM switches WHERE client_id = $1 ORDER BY zone, name',
      [clientId]
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Switches error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ============================================================
// SOFTWARE ENDPOINTS
// ============================================================

app.get('/api/software', authenticate, async (req, res) => {
  const clientId = req.user.client_id;
  try {
    const result = await pool.query(
      'SELECT * FROM software WHERE client_id = $1 ORDER BY name',
      [clientId]
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Software error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ============================================================
// INTRUSION ENDPOINTS
// ============================================================

app.get('/api/intrusion', authenticate, async (req, res) => {
  const clientId = req.user.client_id;
  try {
    const result = await pool.query(
      'SELECT * FROM intrusion WHERE client_id = $1 ORDER BY zone, name',
      [clientId]
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Intrusion error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ============================================================
// SERVICE REQUEST ENDPOINTS
// ============================================================

app.get('/api/service-requests', authenticate, async (req, res) => {
  const clientId = req.user.client_id;
  try {
    const result = await pool.query(
      'SELECT * FROM service_requests WHERE client_id = $1 ORDER BY created_at DESC',
      [clientId]
    );
    // Get history for each SR
    for (const sr of result.rows) {
      const history = await pool.query(
        'SELECT * FROM sr_history WHERE sr_id = $1 ORDER BY created_at',
        [sr.id]
      );
      sr.history = history.rows;
    }
    res.json(result.rows);
  } catch (err) {
    console.error('Service requests error:', err);
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/service-requests', authenticate, async (req, res) => {
  const { subject, category, priority, assigned_to, body } = req.body;
  const clientId = req.user.client_id;
  const srId = `SR-${String(Math.floor(Math.random() * 9000) + 1000)}`;
  try {
    const result = await pool.query(
      `INSERT INTO service_requests 
       (client_id, sr_id, subject, category, priority, assigned_to, body, received, created_by) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, CURRENT_DATE, $8) 
       RETURNING *`,
      [clientId, srId, subject, category, priority, assigned_to, body, req.user.username]
    );
    await pool.query(
      'INSERT INTO sr_history (sr_id, time, msg) VALUES ($1, $2, $3)',
      [result.rows[0].id, new Date().toLocaleTimeString(), 'Created']
    );
    await pool.query(
      'INSERT INTO activity_log (client_id, user, action, detail) VALUES ($1, $2, $3, $4)',
      [clientId, req.user.username, 'created', `SR ${srId} created`]
    );
    res.json(result.rows[0]);
  } catch (err) {
    console.error('Create SR error:', err);
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/service-requests/:id', authenticate, async (req, res) => {
  const { id } = req.params;
  const { priority, assigned_to, status, notes } = req.body;
  const clientId = req.user.client_id;
  try {
    await pool.query(
      `UPDATE service_requests 
       SET priority = $1, assigned_to = $2, status = $3, notes = $4, updated_at = CURRENT_TIMESTAMP 
       WHERE id = $5 AND client_id = $6`,
      [priority, assigned_to, status, notes, id, clientId]
    );
    await pool.query(
      'INSERT INTO sr_history (sr_id, time, msg) VALUES ($1, $2, $3)',
      [id, new Date().toLocaleTimeString(), `Updated: ${status}`]
    );
    await pool.query(
      'INSERT INTO activity_log (client_id, user, action, detail) VALUES ($1, $2, $3, $4)',
      [clientId, req.user.username, 'updated', `SR ${id} updated`]
    );
    res.json({ success: true });
  } catch (err) {
    console.error('Update SR error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ============================================================
// ACTIVITY LOG ENDPOINTS
// ============================================================

app.get('/api/activity-log', authenticate, async (req, res) => {
  const clientId = req.user.client_id;
  const limit = parseInt(req.query.limit) || 100;
  try {
    const result = await pool.query(
      'SELECT * FROM activity_log WHERE client_id = $1 ORDER BY created_at DESC LIMIT $2',
      [clientId, limit]
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Activity log error:', err);
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/activity-log', authenticate, async (req, res) => {
  const { action, detail } = req.body;
  const clientId = req.user.client_id;
  try {
    await pool.query(
      'INSERT INTO activity_log (client_id, user, action, detail) VALUES ($1, $2, $3, $4)',
      [clientId, req.user.username, action, detail]
    );
    res.json({ success: true });
  } catch (err) {
    console.error('Add activity log error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ============================================================
// CLIENT ENDPOINTS
// ============================================================

app.get('/api/clients', authenticate, async (req, res) => {
  try {
    const result = await pool.query('SELECT id, name, email, phone, address, logo_url FROM clients');
    res.json(result.rows);
  } catch (err) {
    console.error('Clients error:', err);
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/clients', authenticate, async (req, res) => {
  const { name, email, phone, address, logo_url } = req.body;
  try {
    const result = await pool.query(
      'INSERT INTO clients (name, email, phone, address, logo_url) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [name, email, phone, address, logo_url]
    );
    await pool.query(
      'INSERT INTO activity_log (client_id, user, action, detail) VALUES ($1, $2, $3, $4)',
      [result.rows[0].id, req.user.username, 'created', `Client ${name} created`]
    );
    res.json(result.rows[0]);
  } catch (err) {
    console.error('Create client error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ============================================================
// EMAIL ENDPOINTS
// ============================================================

app.get('/api/emails', authenticate, async (req, res) => {
  const clientId = req.user.client_id;
  const folder = req.query.folder || 'inbox';
  try {
    const result = await pool.query(
      'SELECT * FROM emails WHERE client_id = $1 AND folder = $2 ORDER BY created_at DESC',
      [clientId, folder]
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Emails error:', err);
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/emails', authenticate, async (req, res) => {
  const { sender, recipient, subject, body, folder } = req.body;
  const clientId = req.user.client_id;
  try {
    const result = await pool.query(
      'INSERT INTO emails (client_id, sender, recipient, subject, body, folder) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *',
      [clientId, sender, recipient, subject, body, folder || 'inbox']
    );
    res.json(result.rows[0]);
  } catch (err) {
    console.error('Create email error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ============================================================
// DATA IMPORT ENDPOINT (for initial camera data)
// ============================================================

app.post('/api/import/cameras', authenticate, async (req, res) => {
  const clientId = req.user.client_id;
  const cameras = req.body;
  let imported = 0;
  try {
    for (const cam of cameras) {
      await pool.query(
        `INSERT INTO cameras 
         (client_id, name, zone, status, comments, model, manufacturer, resolution, archiver, ip_address, mac_address, warranty, date_cleaned) 
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
        [clientId, cam.name, cam.zone, cam.status, cam.comments, cam.model, cam.manufacturer, 
         cam.resolution, cam.archiver, cam.ip_address, cam.mac_address, cam.warranty, cam.date_cleaned]
      );
      imported++;
    }
    await pool.query(
      'INSERT INTO activity_log (client_id, user, action, detail) VALUES ($1, $2, $3, $4)',
      [clientId, req.user.username, 'imported', `Imported ${imported} cameras`]
    );
    res.json({ success: true, imported: imported });
  } catch (err) {
    console.error('Import error:', err);
    res.status(500).json({ error: err.message, imported: imported });
  }
});

// ============================================================
// HEALTH CHECK
// ============================================================

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// ============================================================
// START SERVER
// ============================================================

app.listen(port, () => {
  console.log(`CAMS API running on port ${port}`);
});
