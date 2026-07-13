const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const path = require('path');
const axios = require('axios');
const multer = require('multer');
const upload = multer({ dest: 'uploads/' });
const fs = require('fs');
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
// EMAIL NOTIFICATION HELPER
// ============================================================

async function sendEmailNotification(to, subject, body, authHeader) {
  try {
    const emailData = {
      message: {
        subject: subject,
        body: { contentType: 'HTML', content: body },
        toRecipients: to.split(',').map(email => ({ emailAddress: { address: email.trim() } }))
      }
    };
    await axios.post('https://graph.microsoft.com/v1.0/me/sendMail', emailData, {
      headers: { Authorization: authHeader, 'Content-Type': 'application/json' }
    });
    return true;
  } catch (err) {
    console.error('Email notification failed:', err.message);
    return false;
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

  if (username === 'Admin' && password === 'Ad@E-Tech07') {
    const token = jwt.sign({ id: 1, username: 'Admin', client_id: null, role: 'admin' }, process.env.JWT_SECRET || 'secret', { expiresIn: '24h' });
    await logActivity(1, 'Admin', 'Login', 'Admin logged in');
    return res.json({ token, user: { id: 1, username: 'Admin', client_id: null, role: 'admin' } });
  }

  if (username === 'KFTL' && password === 'KFTL@E-Tech0151') {
    const token = jwt.sign({ id: 2, username: 'KFTL', client_id: 1, role: 'client' }, process.env.JWT_SECRET || 'secret', { expiresIn: '24h' });
    await logActivity(1, 'KFTL', 'Login', 'Client logged in');
    return res.json({ token, user: { id: 2, username: 'KFTL', client_id: 1, role: 'client' } });
  }

  if (username === 'tech' && password === 'tech123') {
    const token = jwt.sign({ id: 3, username: 'tech', client_id: null, role: 'technician' }, process.env.JWT_SECRET || 'secret', { expiresIn: '24h' });
    await logActivity(1, 'tech', 'Login', 'Technician logged in');
    return res.json({ token, user: { id: 3, username: 'tech', client_id: null, role: 'technician' } });
  }

  res.status(401).json({ error: 'Invalid credentials' });
});

// ============================================================
// MICROSOFT LOGIN — AZURE AD
// ============================================================

const MS_CLIENT_ID = process.env.MS_CLIENT_ID || 'e87a6592-aaa5-4a13-9c85-8dbc8e9cd7b2';
const MS_TENANT_ID = process.env.MS_TENANT_ID || '799ae988-9d3d-40d3-bf5c-93197f5d8d44';
const MS_CLIENT_SECRET = process.env.MS_CLIENT_SECRET || '';

app.post('/api/auth/microsoft', async (req, res) => {
  const { code, code_verifier } = req.body;
  
  if (!code) {
    return res.status(400).json({ error: 'No authorization code provided' });
  }

  try {
    const tokenResponse = await axios.post(
      `https://login.microsoftonline.com/${MS_TENANT_ID}/oauth2/v2.0/token`,
      new URLSearchParams({
        client_id: MS_CLIENT_ID,
        client_secret: MS_CLIENT_SECRET,
        grant_type: 'authorization_code',
        code: code,
        redirect_uri: 'https://e-tech-ccsm-production.up.railway.app/',
        code_verifier: code_verifier || ''
      }),
      { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
    );

    const accessToken = tokenResponse.data.access_token;

    const userResponse = await axios.get('https://graph.microsoft.com/v1.0/me', {
      headers: { Authorization: `Bearer ${accessToken}` }
    });

    const msUser = userResponse.data;
    const email = msUser.mail || msUser.userPrincipalName || '';
    const displayName = msUser.displayName || 'User';
    
    const emailName = email.split('@')[0] || '';
    const username = emailName.charAt(0).toUpperCase() + emailName.slice(1);

    const isETechUser = email.toLowerCase().endsWith('@e-techsystemsja.com');
    const role = isETechUser ? 'admin' : 'client';
    const clientId = isETechUser ? null : 1;

    const jwtToken = jwt.sign(
      { 
        id: msUser.id, 
        username: username, 
        email: email, 
        client_id: clientId, 
        role: role,
        msToken: accessToken 
      },
      process.env.JWT_SECRET || 'secret',
      { expiresIn: '24h' }
    );

    const logClientId = clientId || 1;
    await logActivity(logClientId, username, 'Login', `Microsoft login — ${email} (${role})`);

    res.json({
      token: jwtToken,
      user: { 
        id: msUser.id, 
        username: username, 
        email: email, 
        client_id: clientId, 
        role: role 
      }
    });

    console.log(`✅ Microsoft login: ${username} (${email}) — Role: ${role}`);
  } catch (err) {
    console.error('Microsoft auth error:', err.response?.data || err.message);
    res.status(401).json({ error: 'Microsoft authentication failed. ' + (err.response?.data?.error_description || err.message) });
  }
});

// ============================================================
// DASHBOARD STATS
// ============================================================

app.get('/api/dashboard/stats', authMiddleware, async (req, res) => {
  if (!dbConnected) {
    return res.json({ health: 100, alarms: 0, offline_devices: 0, open_srs: 0, total_devices: 0, online_devices: 0 });
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
      alarms: 0, 
      offline_devices: offline, 
      open_srs: srs.rowCount, 
      total_devices: totalDevices, 
      online_devices: online 
    });
  } catch (err) {
    console.error('Dashboard stats error:', err);
    res.json({ health: 100, alarms: 0, offline_devices: 0, open_srs: 0, total_devices: 0, online_devices: 0 });
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
  const { status, comments, name, zone, model, manufacturer, resolution, archiver, ip_address, mac_address, warranty, purchase_date } = req.body;
  try {
    const clientId = req.user.role === 'admin' ? null : req.user.client_id;
    
    // For admins, allow editing all fields. For clients, only status and comments.
    if (req.user.role === 'admin') {
      const query = clientId ? 
        `UPDATE cameras SET name = COALESCE($1, name), zone = COALESCE($2, zone), status = COALESCE($3, status), 
         model = COALESCE($4, model), manufacturer = COALESCE($5, manufacturer), resolution = COALESCE($6, resolution),
         archiver = COALESCE($7, archiver), ip_address = COALESCE($8, ip_address), mac_address = COALESCE($9, mac_address),
         warranty = COALESCE($10, warranty), purchase_date = COALESCE($11, purchase_date), comments = COALESCE($12, comments),
         updated_at = CURRENT_TIMESTAMP WHERE id = $13 AND client_id = $14` :
        `UPDATE cameras SET name = COALESCE($1, name), zone = COALESCE($2, zone), status = COALESCE($3, status), 
         model = COALESCE($4, model), manufacturer = COALESCE($5, manufacturer), resolution = COALESCE($6, resolution),
         archiver = COALESCE($7, archiver), ip_address = COALESCE($8, ip_address), mac_address = COALESCE($9, mac_address),
         warranty = COALESCE($10, warranty), purchase_date = COALESCE($11, purchase_date), comments = COALESCE($12, comments),
         updated_at = CURRENT_TIMESTAMP WHERE id = $13`;
      const params = clientId ? 
        [name, zone, status, model, manufacturer, resolution, archiver, ip_address, mac_address, warranty, purchase_date, comments, id, clientId] :
        [name, zone, status, model, manufacturer, resolution, archiver, ip_address, mac_address, warranty, purchase_date, comments, id];
      await pool.query(query, params);
    } else {
      const query = clientId ? 
        'UPDATE cameras SET status = COALESCE($1, status), comments = COALESCE($2, comments), updated_at = CURRENT_TIMESTAMP WHERE id = $3 AND client_id = $4' :
        'UPDATE cameras SET status = COALESCE($1, status), comments = COALESCE($2, comments), updated_at = CURRENT_TIMESTAMP WHERE id = $3';
      const params = clientId ? [status, comments, id, clientId] : [status, comments, id];
      await pool.query(query, params);
    }
    
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
        `INSERT INTO cameras (client_id, name, zone, status, comments, model, manufacturer, resolution, archiver, ip_address, mac_address, warranty, purchase_date, date_cleaned) 
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`,
        [cam.client_id || 1, cam.name || '', cam.zone || '', cam.status || 'Working', cam.comments || '', cam.model || '', cam.manufacturer || '', cam.resolution || '', cam.archiver || '', cam.ip_address || '', cam.mac_address || '', cam.warranty || '', cam.purchase_date || null, cam.date_cleaned || null]
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
// CSV IMPORT — DOORS, SERVERS, SWITCHES
// ============================================================

app.post('/api/import/doors', authMiddleware, async (req, res) => {
  if (!dbConnected) return res.status(503).json({ error: 'DB not connected' });
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  const doors = req.body;
  let imported = 0;
  try {
    for (const door of doors) {
      await pool.query(
        `INSERT INTO doors (client_id, name, zone, status, tech, reader, lock_type, ip, controllerType, doorSwing, accessType, antiPassback, powered, purchase_date, warranty_expiry, comments) 
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)`,
        [door.client_id || 1, door.name || '', door.zone || door.site || '', door.status || 'Online', door.tech || '', door.reader || '', door.lock_type || '', door.ip || '', door.controllerType || '', door.doorSwing || '', door.accessType || '', door.antiPassback || '', door.powered || '', door.purchase_date || null, door.warranty_expiry || null, door.comments || '']
      );
      imported++;
    }
    await logActivity(1, req.user.username, 'Import', 'Imported ' + imported + ' doors');
    res.json({ success: true, imported });
  } catch (err) {
    res.status(500).json({ error: err.message, imported });
  }
});

app.post('/api/import/servers', authMiddleware, async (req, res) => {
  if (!dbConnected) return res.status(503).json({ error: 'DB not connected' });
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  const servers = req.body;
  let imported = 0;
  try {
    for (const srv of servers) {
      await pool.query(
        `INSERT INTO servers (client_id, name, zone, status, make, model, capacity, used, health, apps, ip_address, serial, purchase_date, warranty_expiry, comments) 
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)`,
        [srv.client_id || 1, srv.name || srv.serial || '', srv.zone || srv.location || '', srv.status || 'ONLINE', srv.make || '', srv.model || '', srv.capacity || '', srv.used || '', srv.health || '', srv.apps || '', srv.ip_address || '', srv.serial || '', srv.purchase_date || null, srv.warranty_expiry || null, srv.comments || '']
      );
      imported++;
    }
    await logActivity(1, req.user.username, 'Import', 'Imported ' + imported + ' servers');
    res.json({ success: true, imported });
  } catch (err) {
    res.status(500).json({ error: err.message, imported });
  }
});

app.post('/api/import/switches', authMiddleware, async (req, res) => {
  if (!dbConnected) return res.status(503).json({ error: 'DB not connected' });
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  const switches = req.body;
  let imported = 0;
  try {
    for (const sw of switches) {
      await pool.query(
        `INSERT INTO switches (client_id, name, zone, status, model, firmware, ip_address, mac, purchase_date, warranty_expiry, comments) 
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
        [sw.client_id || 1, sw.name || '', sw.zone || sw.location || '', sw.status || 'Online', sw.model || '', sw.firmware || '', sw.ip_address || '', sw.mac || '', sw.purchase_date || null, sw.warranty_expiry || null, sw.comments || '']
      );
      imported++;
    }
    await logActivity(1, req.user.username, 'Import', 'Imported ' + imported + ' switches');
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
  const { status, comments, name, zone, tech, reader, lock_type, ip, controllerType, doorSwing, accessType, antiPassback, powered, purchase_date, warranty_expiry } = req.body;
  try {
    const clientId = req.user.role === 'admin' ? null : req.user.client_id;
    
    if (req.user.role === 'admin') {
      const query = clientId ? 
        `UPDATE doors SET name = COALESCE($1, name), zone = COALESCE($2, zone), status = COALESCE($3, status),
         tech = COALESCE($4, tech), reader = COALESCE($5, reader), lock_type = COALESCE($6, lock_type),
         ip = COALESCE($7, ip), controllerType = COALESCE($8, controllerType), doorSwing = COALESCE($9, doorSwing),
         accessType = COALESCE($10, accessType), antiPassback = COALESCE($11, antiPassback), powered = COALESCE($12, powered),
         purchase_date = COALESCE($13, purchase_date), warranty_expiry = COALESCE($14, warranty_expiry),
         comments = COALESCE($15, comments), updated_at = CURRENT_TIMESTAMP WHERE id = $16 AND client_id = $17` :
        `UPDATE doors SET name = COALESCE($1, name), zone = COALESCE($2, zone), status = COALESCE($3, status),
         tech = COALESCE($4, tech), reader = COALESCE($5, reader), lock_type = COALESCE($6, lock_type),
         ip = COALESCE($7, ip), controllerType = COALESCE($8, controllerType), doorSwing = COALESCE($9, doorSwing),
         accessType = COALESCE($10, accessType), antiPassback = COALESCE($11, antiPassback), powered = COALESCE($12, powered),
         purchase_date = COALESCE($13, purchase_date), warranty_expiry = COALESCE($14, warranty_expiry),
         comments = COALESCE($15, comments), updated_at = CURRENT_TIMESTAMP WHERE id = $16`;
      const params = clientId ? 
        [name, zone, status, tech, reader, lock_type, ip, controllerType, doorSwing, accessType, antiPassback, powered, purchase_date, warranty_expiry, comments, id, clientId] :
        [name, zone, status, tech, reader, lock_type, ip, controllerType, doorSwing, accessType, antiPassback, powered, purchase_date, warranty_expiry, comments, id];
      await pool.query(query, params);
    } else {
      const query = clientId ? 
        'UPDATE doors SET status = COALESCE($1, status), comments = COALESCE($2, comments), updated_at = CURRENT_TIMESTAMP WHERE id = $3 AND client_id = $4' :
        'UPDATE doors SET status = COALESCE($1, status), comments = COALESCE($2, comments), updated_at = CURRENT_TIMESTAMP WHERE id = $3';
      const params = clientId ? [status, comments, id, clientId] : [status, comments, id];
      await pool.query(query, params);
    }
    
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
  const { status, comments, name, zone, make, model, capacity, used, health, apps, ip_address, serial, purchase_date, warranty_expiry } = req.body;
  try {
    const clientId = req.user.role === 'admin' ? null : req.user.client_id;
    
    if (req.user.role === 'admin') {
      const query = clientId ? 
        `UPDATE servers SET name = COALESCE($1, name), zone = COALESCE($2, zone), status = COALESCE($3, status),
         make = COALESCE($4, make), model = COALESCE($5, model), capacity = COALESCE($6, capacity),
         used = COALESCE($7, used), health = COALESCE($8, health), apps = COALESCE($9, apps),
         ip_address = COALESCE($10, ip_address), serial = COALESCE($11, serial),
         purchase_date = COALESCE($12, purchase_date), warranty_expiry = COALESCE($13, warranty_expiry),
         comments = COALESCE($14, comments), updated_at = CURRENT_TIMESTAMP WHERE id = $15 AND client_id = $16` :
        `UPDATE servers SET name = COALESCE($1, name), zone = COALESCE($2, zone), status = COALESCE($3, status),
         make = COALESCE($4, make), model = COALESCE($5, model), capacity = COALESCE($6, capacity),
         used = COALESCE($7, used), health = COALESCE($8, health), apps = COALESCE($9, apps),
         ip_address = COALESCE($10, ip_address), serial = COALESCE($11, serial),
         purchase_date = COALESCE($12, purchase_date), warranty_expiry = COALESCE($13, warranty_expiry),
         comments = COALESCE($14, comments), updated_at = CURRENT_TIMESTAMP WHERE id = $15`;
      const params = clientId ? 
        [name, zone, status, make, model, capacity, used, health, apps, ip_address, serial, purchase_date, warranty_expiry, comments, id, clientId] :
        [name, zone, status, make, model, capacity, used, health, apps, ip_address, serial, purchase_date, warranty_expiry, comments, id];
      await pool.query(query, params);
    } else {
      const query = clientId ? 
        'UPDATE servers SET status = COALESCE($1, status), comments = COALESCE($2, comments), updated_at = CURRENT_TIMESTAMP WHERE id = $3 AND client_id = $4' :
        'UPDATE servers SET status = COALESCE($1, status), comments = COALESCE($2, comments), updated_at = CURRENT_TIMESTAMP WHERE id = $3';
      const params = clientId ? [status, comments, id, clientId] : [status, comments, id];
      await pool.query(query, params);
    }
    
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
  const { status, comments, name, zone, model, firmware, ip_address, mac, purchase_date, warranty_expiry } = req.body;
  try {
    const clientId = req.user.role === 'admin' ? null : req.user.client_id;
    
    if (req.user.role === 'admin') {
      const query = clientId ? 
        `UPDATE switches SET name = COALESCE($1, name), zone = COALESCE($2, zone), status = COALESCE($3, status),
         model = COALESCE($4, model), firmware = COALESCE($5, firmware), ip_address = COALESCE($6, ip_address),
         mac = COALESCE($7, mac), purchase_date = COALESCE($8, purchase_date), warranty_expiry = COALESCE($9, warranty_expiry),
         comments = COALESCE($10, comments), updated_at = CURRENT_TIMESTAMP WHERE id = $11 AND client_id = $12` :
        `UPDATE switches SET name = COALESCE($1, name), zone = COALESCE($2, zone), status = COALESCE($3, status),
         model = COALESCE($4, model), firmware = COALESCE($5, firmware), ip_address = COALESCE($6, ip_address),
         mac = COALESCE($7, mac), purchase_date = COALESCE($8, purchase_date), warranty_expiry = COALESCE($9, warranty_expiry),
         comments = COALESCE($10, comments), updated_at = CURRENT_TIMESTAMP WHERE id = $11`;
      const params = clientId ? 
        [name, zone, status, model, firmware, ip_address, mac, purchase_date, warranty_expiry, comments, id, clientId] :
        [name, zone, status, model, firmware, ip_address, mac, purchase_date, warranty_expiry, comments, id];
      await pool.query(query, params);
    } else {
      const query = clientId ? 
        'UPDATE switches SET status = COALESCE($1, status), comments = COALESCE($2, comments), updated_at = CURRENT_TIMESTAMP WHERE id = $3 AND client_id = $4' :
        'UPDATE switches SET status = COALESCE($1, status), comments = COALESCE($2, comments), updated_at = CURRENT_TIMESTAMP WHERE id = $3';
      const params = clientId ? [status, comments, id, clientId] : [status, comments, id];
      await pool.query(query, params);
    }
    
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
// SERVICE REQUESTS — WITH RELATED HARDWARE
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
      // Parse related_hardware JSON
      if (sr.related_hardware && typeof sr.related_hardware === 'string') {
        try { sr.related_hardware = JSON.parse(sr.related_hardware); } catch (e) { sr.related_hardware = []; }
      }
      if (!sr.related_hardware) sr.related_hardware = [];
    }
    res.json(result.rows);
  } catch (err) {
    res.json([]);
  }
});

app.post('/api/service-requests', authMiddleware, async (req, res) => {
  if (!dbConnected) return res.status(503).json({ error: 'DB not connected' });
  const { subject, client, site, category, priority, assigned_to, body, related_hardware } = req.body;
  const srId = `SR-${String(Math.floor(Math.random() * 9000) + 1000)}`;
  const clientId = req.user.role === 'admin' ? 1 : req.user.client_id;
  try {
    const result = await pool.query(
      `INSERT INTO service_requests (client_id, sr_id, subject, client, site, category, priority, assigned_to, body, received, created_by, related_hardware) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, CURRENT_DATE, $10, $11) RETURNING *`,
      [clientId, srId, subject, client, site, category, priority, assigned_to, body, req.user.username, JSON.stringify(related_hardware || [])]
    );
    await pool.query('INSERT INTO sr_history (sr_id, time, msg) VALUES ($1, $2, $3)', [result.rows[0].id, new Date().toLocaleTimeString(), 'Created by ' + req.user.username]);
    await logActivity(clientId, req.user.username, 'Created', 'SR ' + srId + ' created for ' + client);

    // Send email notification
    const emailBody = `<h2>New Service Request: ${srId}</h2><p><strong>Client:</strong> ${client}</p><p><strong>Site:</strong> ${site}</p><p><strong>Category:</strong> ${category}</p><p><strong>Priority:</strong> ${priority}</p><p><strong>Assigned To:</strong> ${assigned_to}</p><p><strong>Subject:</strong> ${subject}</p><p><strong>Description:</strong> ${body || 'No description'}</p><hr><p>View in CAMS: <a href="https://e-tech-ccsm-production.up.railway.app">Open Dashboard</a></p>`;
    await sendEmailNotification('support@e-techsystemsja.com', `[CAMS] New SR: ${srId} — ${subject}`, emailBody, req.headers.authorization);

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
    const current = await pool.query('SELECT * FROM service_requests WHERE id = $1', [id]);
    const oldSr = current.rows[0];
    const oldAssigned = oldSr?.assigned_to;
    const oldStatus = oldSr?.status;

    const query = clientId ? 
      `UPDATE service_requests SET priority = $1, assigned_to = $2, status = $3, notes = $4, updated_at = CURRENT_TIMESTAMP WHERE id = $5 AND client_id = $6` :
      `UPDATE service_requests SET priority = $1, assigned_to = $2, status = $3, notes = $4, updated_at = CURRENT_TIMESTAMP WHERE id = $5`;
    const params = clientId ? [priority, assigned_to, status, notes, id, clientId] : [priority, assigned_to, status, notes, id];
    await pool.query(query, params);

    if (assigned_to && assigned_to !== oldAssigned) {
      await pool.query('INSERT INTO sr_history (sr_id, time, msg) VALUES ($1, $2, $3)', 
        [id, new Date().toLocaleTimeString(), `Transferred from ${oldAssigned || 'Unassigned'} to ${assigned_to} by ${req.user.username}`]);
    }

    await pool.query('INSERT INTO sr_history (sr_id, time, msg) VALUES ($1, $2, $3)', 
      [id, new Date().toLocaleTimeString(), `Updated: ${status} by ${req.user.username}`]);

    const logClientId = clientId || 1;
    await logActivity(logClientId, req.user.username, 'Updated', 'SR ' + id + ' updated to ' + status);

    if (status === 'Resolved' && oldStatus !== 'Resolved') {
      const updated = await pool.query('SELECT * FROM service_requests WHERE id = $1', [id]);
      const sr = updated.rows[0];
      const history = await pool.query('SELECT * FROM sr_history WHERE sr_id = $1 ORDER BY created_at', [id]);
      
      const reportBody = `<h2>Service Request Resolved: ${sr.sr_id}</h2><p><strong>Client:</strong> ${sr.client}</p><p><strong>Site:</strong> ${sr.site}</p><p><strong>Category:</strong> ${sr.category}</p><p><strong>Priority:</strong> ${sr.priority}</p><p><strong>Subject:</strong> ${sr.subject}</p><p><strong>Created By:</strong> ${sr.created_by}</p><p><strong>Resolved By:</strong> ${req.user.username}</p><p><strong>Resolution Notes:</strong> ${notes || 'No notes'}</p><hr><h3>Timeline</h3><ul>${history.rows.map(h => `<li>${h.time} — ${h.msg}</li>`).join('')}</ul><hr><p>View in CAMS: <a href="https://e-tech-ccsm-production.up.railway.app">Open Dashboard</a></p>`;
      await sendEmailNotification('support@e-techsystemsja.com', `[CAMS] RESOLVED: ${sr.sr_id} — ${sr.subject}`, reportBody, req.headers.authorization);
    }

    const updated = await pool.query('SELECT * FROM service_requests WHERE id = $1', [id]);
    res.json({ success: true, data: updated.rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/service-requests/:id/transfer', authMiddleware, async (req, res) => {
  if (!dbConnected) return res.status(503).json({ error: 'DB not connected' });
  const { id } = req.params;
  const { assigned_to } = req.body;
  try {
    const current = await pool.query('SELECT * FROM service_requests WHERE id = $1', [id]);
    const oldAssigned = current.rows[0]?.assigned_to;

    await pool.query('UPDATE service_requests SET assigned_to = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2', [assigned_to, id]);
    await pool.query('INSERT INTO sr_history (sr_id, time, msg) VALUES ($1, $2, $3)', 
      [id, new Date().toLocaleTimeString(), `Transferred from ${oldAssigned || 'Unassigned'} to ${assigned_to} by ${req.user.username}`]);

    await logActivity(1, req.user.username, 'Assigned', 'SR ' + id + ' transferred to ' + assigned_to);

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
// OUTLOOK / MICROSOFT GRAPH INBOX INTEGRATION
// ============================================================

app.get('/api/outlook/emails', authMiddleware, async (req, res) => {
  try {
    const folder = req.query.folder || 'inbox';
    let endpoint;
    switch(folder) {
      case 'sent': endpoint = 'https://graph.microsoft.com/v1.0/me/mailFolders/sentitems/messages'; break;
      case 'drafts': endpoint = 'https://graph.microsoft.com/v1.0/me/mailFolders/drafts/messages'; break;
      case 'deleted': endpoint = 'https://graph.microsoft.com/v1.0/me/mailFolders/deleteditems/messages'; break;
      default: endpoint = 'https://graph.microsoft.com/v1.0/me/mailFolders/inbox/messages';
    }
    const response = await axios.get(endpoint, {
      headers: { Authorization: req.headers.authorization },
      params: { $top: 100, $orderby: 'receivedDateTime desc', $select: 'id,subject,from,toRecipients,receivedDateTime,bodyPreview,body,isRead,flag,hasAttachments,webLink' }
    });
    const emails = response.data.value.map(msg => ({
      id: msg.id, sender: msg.from?.emailAddress?.name || 'Unknown', sender_email: msg.from?.emailAddress?.address || '',
      recipient: msg.toRecipients?.map(r => r.emailAddress?.name).join(', ') || '', subject: msg.subject || '(no subject)',
      body: msg.bodyPreview || '', fullBody: msg.body?.content || '', is_read: msg.isRead, is_flagged: !!msg.flag?.flagStatus,
      folder: folder, created_at: msg.receivedDateTime, has_attachments: msg.hasAttachments, webLink: msg.webLink
    }));
    res.json(emails);
  } catch (err) {
    console.error('Outlook fetch error:', err.message);
    try {
      const folder = req.query.folder || 'inbox';
      const result = await pool.query('SELECT * FROM emails WHERE folder = $1 ORDER BY created_at DESC LIMIT 100', [folder]);
      return res.json(result.rows);
    } catch (dbErr) { res.json([]); }
  }
});

app.post('/api/outlook/send', authMiddleware, async (req, res) => {
  const { to, cc, subject, body } = req.body;
  try {
    const emailData = { message: { subject, body: { contentType: 'HTML', content: body }, toRecipients: to.split(',').map(email => ({ emailAddress: { address: email.trim() } })) } };
    if (cc) { emailData.message.ccRecipients = cc.split(',').map(email => ({ emailAddress: { address: email.trim() } })); }
    await axios.post('https://graph.microsoft.com/v1.0/me/sendMail', emailData, {
      headers: { Authorization: req.headers.authorization, 'Content-Type': 'application/json' }
    });
    try {
      await pool.query('INSERT INTO emails (client_id, sender, recipient, subject, body, folder) VALUES ($1, $2, $3, $4, $5, $6)',
        [req.user.client_id || 1, req.user.username, to, subject, body, 'sent']);
    } catch (dbErr) { console.error('Failed to save sent email locally:', dbErr.message); }
    res.json({ success: true });
  } catch (err) {
    console.error('Outlook send error:', err.message);
    try {
      await pool.query('INSERT INTO emails (client_id, sender, recipient, subject, body, folder) VALUES ($1, $2, $3, $4, $5, $6)',
        [req.user.client_id || 1, req.user.username, to, subject, body, 'sent']);
      res.json({ success: true, local_only: true });
    } catch (dbErr) { res.status(500).json({ error: 'Failed to send email' }); }
  }
});

app.post('/api/outlook/read/:id', authMiddleware, async (req, res) => {
  try { await axios.patch(`https://graph.microsoft.com/v1.0/me/messages/${req.params.id}`, { isRead: true }, { headers: { Authorization: req.headers.authorization, 'Content-Type': 'application/json' } }); res.json({ success: true }); }
  catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/outlook/flag/:id', authMiddleware, async (req, res) => {
  const { flagged } = req.body;
  try { await axios.patch(`https://graph.microsoft.com/v1.0/me/messages/${req.params.id}`, { flag: flagged ? { flagStatus: 'flagged' } : { flagStatus: 'notFlagged' } }, { headers: { Authorization: req.headers.authorization, 'Content-Type': 'application/json' } }); res.json({ success: true }); }
  catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/outlook/delete/:id', authMiddleware, async (req, res) => {
  try { await axios.post(`https://graph.microsoft.com/v1.0/me/messages/${req.params.id}/move`, { destinationId: 'deleteditems' }, { headers: { Authorization: req.headers.authorization, 'Content-Type': 'application/json' } }); res.json({ success: true }); }
  catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/outlook/convert-to-sr/:id', authMiddleware, async (req, res) => {
  try {
    const response = await axios.get(`https://graph.microsoft.com/v1.0/me/messages/${req.params.id}`, {
      headers: { Authorization: req.headers.authorization }
    });
    const msg = response.data;
    const srId = `SR-${String(Math.floor(Math.random() * 9000) + 1000)}`;
    const subject = msg.subject || 'Converted from email';
    const body = msg.bodyPreview || msg.body?.content || '';
    const sender = msg.from?.emailAddress?.name || 'Unknown';

    await pool.query(
      `INSERT INTO service_requests (client_id, sr_id, subject, client, site, category, priority, assigned_to, body, received, created_by) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, CURRENT_DATE, $10)`,
      [req.user.client_id || 1, srId, subject, 'KFTL', 'Unknown', 'Other', 'Medium', 'Unassigned', `From: ${sender}\n\n${body}`, req.user.username]
    );
    await logActivity(1, req.user.username, 'Converted', 'Email converted to SR ' + srId);
    res.json({ success: true, sr_id: srId });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================
// FILES — MICROSOFT GRAPH SHAREPOINT / ONEDRIVE
// ============================================================

app.get('/api/files/graph', authMiddleware, async (req, res) => {
  try {
    const folder = req.query.folder || '';
    const endpoint = folder ? `https://graph.microsoft.com/v1.0/me/drive/root:/${folder}:/children` : 'https://graph.microsoft.com/v1.0/me/drive/root/children';
    const response = await axios.get(endpoint, { headers: { Authorization: req.headers.authorization } });
    const files = response.data.value.map(item => ({ 
      id: item.id, name: item.name, type: item.folder ? 'folder' : (item.file?.mimeType || 'file'), 
      size: item.size, modified: item.lastModifiedDateTime, webUrl: item.webUrl, 
      downloadUrl: item['@microsoft.graph.downloadUrl'], isFolder: !!item.folder 
    }));
    res.json(files);
  } catch (err) { console.error('Files fetch error:', err.message); res.json([]); }
});

app.get('/api/files/download/:id', authMiddleware, async (req, res) => {
  try { 
    const response = await axios.get(`https://graph.microsoft.com/v1.0/me/drive/items/${req.params.id}`, { headers: { Authorization: req.headers.authorization } }); 
    res.redirect(response.data['@microsoft.graph.downloadUrl']); 
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ============================================================
// DATABASE EMAILS (local fallback)
// ============================================================

app.get('/api/emails', authMiddleware, async (req, res) => {
  if (!dbConnected) return res.json([]);
  try {
    const folder = req.query.folder || 'inbox';
    const clientId = req.user.role === 'admin' ? null : req.user.client_id;
    const query = clientId ? 'SELECT * FROM emails WHERE client_id = $1 AND folder = $2 ORDER BY created_at DESC' : 'SELECT * FROM emails WHERE folder = $1 ORDER BY created_at DESC';
    const params = clientId ? [clientId, folder] : [folder];
    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (err) { res.json([]); }
});

app.post('/api/emails', authMiddleware, async (req, res) => {
  if (!dbConnected) return res.status(503).json({ error: 'DB not connected' });
  const { sender, recipient, subject, body, folder } = req.body;
  const clientId = req.user.role === 'admin' ? 1 : req.user.client_id;
  try {
    const result = await pool.query('INSERT INTO emails (client_id, sender, recipient, subject, body, folder) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *',
      [clientId, sender, recipient, subject, body, folder || 'inbox']);
    res.json(result.rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ============================================================
// SERVE HTML
// ============================================================

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/mobile', (req, res) => {
  res.sendFile(path.join(__dirname, 'field-app.html'));
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
