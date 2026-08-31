const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const path = require('path');
const axios = require('axios');
const multer = require('multer');
const upload = multer({ dest: 'uploads/' });
const fs = require('fs');
const cron = require('node-cron');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 3000;

// Shared mailbox
const SHARED_MAILBOX = 'support@e-techsystemsja.com';

// Technician email mapping
const TECH_EMAILS = {
  'Shanice': 'shanice@e-techsystemsja.com',
  'Roger': 'roger@e-techsystemsja.com',
  'Joshua': 'joshua@e-techsystemsja.com',
  'Rochelle': 'rochelle@e-techsystemsja.com',
  'Akeem': 'akeem@e-techsystemsja.com',
  'Marvin': 'marvin@e-techsystemsja.com',
  'Shavene': 'shavene@e-techsystemsja.com',
  'Venessa': 'venessa@e-techsystemsja.com'
};

// Admin email for reports
const ADMIN_EMAIL = 'support@e-techsystemsja.com';

// ============================================================
// REQUIRED ENVIRONMENT VARIABLES
// ============================================================
// These must be set in Railway (or your .env locally). The app refuses to
// start without them rather than silently falling back to insecure defaults.
const REQUIRED_ENV_VARS = [
  'DATABASE_URL',
  'JWT_SECRET',
  'ADMIN_USERNAME', 'ADMIN_PASSWORD',
  'KFTL_USERNAME', 'KFTL_PASSWORD',
  'KWL_USERNAME', 'KWL_PASSWORD',
  'TECH_USERNAME', 'TECH_PASSWORD',
  'PAJ_USERNAME', 'PAJ_PASSWORD',
];
const missingEnvVars = REQUIRED_ENV_VARS.filter(name => !process.env[name]);
if (missingEnvVars.length > 0) {
  console.error('❌ Missing required environment variables: ' + missingEnvVars.join(', '));
  console.error('   Set these in Railway → Variables (or a local .env file) before starting the server.');
  console.error('   See .env.example for the full list.');
  process.exit(1);
}

// ============================================================
// DATABASE CONNECTION
// ============================================================

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
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

// Resolves a client_id to its real name from the clients table, instead of the
// old hardcoded id===1?'KFTL':id===2?'KWL':'Unknown' check that every edit-route
// activity log used — which meant any client besides KFTL/KWL always logged as
// "Unknown" in the activity feed.
async function getClientNameById(clientId) {
  if (clientId == null) return 'Unknown';
  try {
    const result = await pool.query('SELECT name FROM clients WHERE id=$1', [clientId]);
    return result.rows[0]?.name || 'Unknown';
  } catch (err) {
    return 'Unknown';
  }
}

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

// Builds a client-aware activity log entry for an asset import/add. Import
// routes used to always log client_id=1 (KFTL) regardless of which client the
// assets actually belonged to, and never named the client in the log text at
// all — this fixes both.
async function describeClientsForLog(rows) {
  const ids = [...new Set(rows.map(r => r.client_id).filter(id => id != null))];
  if (ids.length === 0) return { clientIdForLog: 1, clientLabel: '' };
  try {
    const result = await pool.query('SELECT id, name FROM clients WHERE id = ANY($1)', [ids]);
    const nameById = {};
    result.rows.forEach(c => { nameById[c.id] = c.name; });
    const names = ids.map(id => nameById[id] || `client #${id}`);
    const label = names.length === 1 ? ` for ${names[0]}` : ` across ${names.length} clients (${names.join(', ')})`;
    return { clientIdForLog: ids[0], clientLabel: label };
  } catch (err) {
    return { clientIdForLog: ids[0], clientLabel: '' };
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
    await axios.post(`https://graph.microsoft.com/v1.0/users/${SHARED_MAILBOX}/sendMail`, emailData, {
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
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
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

  if (username === process.env.ADMIN_USERNAME && password === process.env.ADMIN_PASSWORD) {
    const token = jwt.sign({ id: 1, username: process.env.ADMIN_USERNAME, client_id: null, role: 'admin' }, process.env.JWT_SECRET, { expiresIn: '24h' });
    await logActivity(1, process.env.ADMIN_USERNAME, 'Login', 'Admin logged in');
    return res.json({ token, user: { id: 1, username: process.env.ADMIN_USERNAME, client_id: null, client_name: null, role: 'admin', photo_url: null } });
  }

  if (username === process.env.KFTL_USERNAME && password === process.env.KFTL_PASSWORD) {
    const token = jwt.sign({ id: 2, username: process.env.KFTL_USERNAME, client_id: 1, role: 'client' }, process.env.JWT_SECRET, { expiresIn: '24h' });
    await logActivity(1, process.env.KFTL_USERNAME, 'Login', 'KFTL client logged in');
    return res.json({ token, user: { id: 2, username: process.env.KFTL_USERNAME, client_id: 1, client_name: 'KFTL', role: 'client', photo_url: null } });
  }

  if (username === process.env.KWL_USERNAME && password === process.env.KWL_PASSWORD) {
    const token = jwt.sign({ id: 4, username: process.env.KWL_USERNAME, client_id: 3, role: 'client' }, process.env.JWT_SECRET, { expiresIn: '24h' });
    await logActivity(3, process.env.KWL_USERNAME, 'Login', 'KWL client logged in');
    return res.json({ token, user: { id: 4, username: process.env.KWL_USERNAME, client_id: 3, client_name: 'KWL', role: 'client', photo_url: null } });
  }

  if (username === process.env.PAJ_USERNAME && password === process.env.PAJ_PASSWORD) {
    let clientId = null;
    try {
      const result = await pool.query("SELECT id FROM clients WHERE name = 'PAJ'");
      clientId = result.rows[0]?.id || null;
    } catch (err) { clientId = null; }
    if (!clientId) return res.status(500).json({ error: "No client named 'PAJ' found in the clients table — create it first." });
    const token = jwt.sign({ id: 5, username: process.env.PAJ_USERNAME, client_id: clientId, role: 'client' }, process.env.JWT_SECRET, { expiresIn: '24h' });
    await logActivity(clientId, process.env.PAJ_USERNAME, 'Login', 'PAJ client logged in');
    return res.json({ token, user: { id: 5, username: process.env.PAJ_USERNAME, client_id: clientId, client_name: 'PAJ', role: 'client', photo_url: null } });
  }

  if (username === process.env.TECH_USERNAME && password === process.env.TECH_PASSWORD) {
    const token = jwt.sign({ id: 3, username: process.env.TECH_USERNAME, client_id: null, role: 'technician' }, process.env.JWT_SECRET, { expiresIn: '24h' });
    await logActivity(1, process.env.TECH_USERNAME, 'Login', 'Technician logged in');
    return res.json({ token, user: { id: 3, username: process.env.TECH_USERNAME, client_id: null, client_name: null, role: 'technician', photo_url: null } });
  }

  res.status(401).json({ error: 'Invalid credentials' });
});

// ============================================================
// MICROSOFT LOGIN CALLBACK
// ============================================================

app.post('/api/auth/microsoft-callback', async (req, res) => {
  const { msId, displayName, email, msToken } = req.body;
  
  if (!email) {
    return res.status(400).json({ error: 'No email provided' });
  }

  // Microsoft login is restricted to E-Tech staff — clients always use their
  // manual username/password. Anyone outside the E-Tech domain is rejected
  // here rather than being silently logged in as a client.
  const isETechUser = email.toLowerCase().endsWith('@e-techsystemsja.com');
  if (!isETechUser) {
    return res.status(403).json({ error: 'Microsoft login is only available for E-Tech staff. Clients should use their username and password.' });
  }

  const emailName = email.split('@')[0] || '';
  const username = emailName.charAt(0).toUpperCase() + emailName.slice(1);
  // Every E-Tech staff member gets the same access on both the main dashboard
  // and the field app, via their own Microsoft account — no separate
  // "technician" role tier. Simpler than branching access by which app they
  // signed in from.
  const role = 'admin';

  let photoUrl = null;
  try {
    const photoResponse = await axios.get('https://graph.microsoft.com/v1.0/me/photo/$value', {
      headers: { Authorization: `Bearer ${msToken}` },
      responseType: 'arraybuffer'
    });
    const base64 = Buffer.from(photoResponse.data, 'binary').toString('base64');
    const contentType = photoResponse.headers['content-type'] || 'image/jpeg';
    photoUrl = `data:${contentType};base64,${base64}`;
  } catch (photoErr) {
    console.log('No profile photo available for ' + email + ' — Graph error: ' + (photoErr.response?.status || '') + ' ' + (photoErr.response?.data?.error?.message || photoErr.message));
  }

  const jwtToken = jwt.sign(
    { id: msId, username: username, email: email, client_id: null, role: role, msToken: msToken },
    process.env.JWT_SECRET,
    { expiresIn: '24h' }
  );

  await logActivity(1, username, 'Login', `Microsoft login — ${email} (${role})`);

  res.json({
    token: jwtToken,
    user: { id: msId, username: username, email: email, client_id: null, client_name: null, role: role, photo_url: photoUrl }
  });

  console.log(`✅ Microsoft login: ${username} (${email}) — Role: ${role}, Client ID: ${clientId}`);
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
  const { status, comments, name, zone, model, manufacturer, resolution, archiver, ip_address, mac_address, warranty, purchase_date, date_cleaned } = req.body;
  try {
    const userClientId = req.user.role === 'admin' ? null : req.user.client_id;
    const asset = await pool.query('SELECT name, client_id FROM cameras WHERE id=$1', [id]);
    const assetName = asset.rows[0]?.name || id;
    const assetClientId = asset.rows[0]?.client_id;
    const assetClient = await getClientNameById(assetClientId);
    
    if (req.user.role === 'admin') {
      const query = userClientId ? 
        `UPDATE cameras SET name=COALESCE($1,name),zone=COALESCE($2,zone),status=COALESCE($3,status),model=COALESCE($4,model),manufacturer=COALESCE($5,manufacturer),resolution=COALESCE($6,resolution),archiver=COALESCE($7,archiver),ip_address=COALESCE($8,ip_address),mac_address=COALESCE($9,mac_address),warranty=$10,purchase_date=$11,date_cleaned=$12,comments=COALESCE($13,comments),updated_at=CURRENT_TIMESTAMP WHERE id=$14 AND client_id=$15` :
        `UPDATE cameras SET name=COALESCE($1,name),zone=COALESCE($2,zone),status=COALESCE($3,status),model=COALESCE($4,model),manufacturer=COALESCE($5,manufacturer),resolution=COALESCE($6,resolution),archiver=COALESCE($7,archiver),ip_address=COALESCE($8,ip_address),mac_address=COALESCE($9,mac_address),warranty=$10,purchase_date=$11,date_cleaned=$12,comments=COALESCE($13,comments),updated_at=CURRENT_TIMESTAMP WHERE id=$14`;
      const params = userClientId ? [name,zone,status,model,manufacturer,resolution,archiver,ip_address,mac_address,warranty,purchase_date,date_cleaned,comments,id,userClientId] : [name,zone,status,model,manufacturer,resolution,archiver,ip_address,mac_address,warranty,purchase_date,date_cleaned,comments,id];
      await pool.query(query, params);
    } else {
      const query = userClientId ? 'UPDATE cameras SET status=COALESCE($1,status),comments=COALESCE($2,comments),updated_at=CURRENT_TIMESTAMP WHERE id=$3 AND client_id=$4' : 'UPDATE cameras SET status=COALESCE($1,status),comments=COALESCE($2,comments),updated_at=CURRENT_TIMESTAMP WHERE id=$3';
      const params = userClientId ? [status,comments,id,userClientId] : [status,comments,id];
      await pool.query(query, params);
    }
    await logActivity(assetClientId || userClientId || 1, req.user.username, 'Updated', `Camera ${assetName} updated (${assetClient})`);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/cameras/:id/comment', authMiddleware, async (req, res) => {
  if (!dbConnected) return res.status(503).json({ error: 'DB not connected' });
  const { id } = req.params;
  const { comments } = req.body;
  try {
    const userClientId = req.user.role === 'admin' ? null : req.user.client_id;
    const asset = await pool.query('SELECT name, client_id FROM cameras WHERE id=$1', [id]);
    const assetName = asset.rows[0]?.name || id;
    const assetClientId = asset.rows[0]?.client_id;
    const assetClient = await getClientNameById(assetClientId);
    const query = userClientId ? 'UPDATE cameras SET comments=$1,updated_at=CURRENT_TIMESTAMP WHERE id=$2 AND client_id=$3' : 'UPDATE cameras SET comments=$1,updated_at=CURRENT_TIMESTAMP WHERE id=$2';
    const params = userClientId ? [comments,id,userClientId] : [comments,id];
    await pool.query(query, params);
    await logActivity(assetClientId || userClientId || 1, req.user.username, 'Updated', `Camera ${assetName} comment updated (${assetClient})`);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/cameras/export', authMiddleware, async (req, res) => {
  if (!dbConnected) return res.json([]);
  try {
    const clientId = req.user.role === 'admin' ? null : req.user.client_id;
    const query = clientId ? 'SELECT * FROM cameras WHERE client_id=$1 ORDER BY zone,name' : 'SELECT * FROM cameras ORDER BY zone,name';
    const params = clientId ? [clientId] : [];
    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (err) { res.json([]); }
});

app.post('/api/import/cameras', authMiddleware, async (req, res) => {
  if (!dbConnected) return res.status(503).json({ error: 'DB not connected' });
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  const cameras = req.body;
  let imported = 0;
  try {
    for (const cam of cameras) {
      await pool.query(`INSERT INTO cameras (client_id,name,zone,status,comments,model,manufacturer,resolution,archiver,ip_address,mac_address,warranty,purchase_date,date_cleaned) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
        [cam.client_id||1,cam.name||'',cam.zone||'',cam.status||'Working',cam.comments||'',cam.model||'',cam.manufacturer||'',cam.resolution||'',cam.archiver||'',cam.ip_address||'',cam.mac_address||'',cam.warranty||null,cam.purchase_date||null,cam.date_cleaned||null]);
      imported++;
    }
    const { clientIdForLog, clientLabel } = await describeClientsForLog(cameras);
    await logActivity(clientIdForLog, req.user.username, 'Import', 'Imported ' + imported + ' camera' + (imported === 1 ? '' : 's') + clientLabel);
    res.json({ success: true, imported });
  } catch (err) { res.status(500).json({ error: err.message, imported }); }
});

app.post('/api/import/doors', authMiddleware, async (req, res) => {
  if (!dbConnected) return res.status(503).json({ error: 'DB not connected' });
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  const doors = req.body;
  let imported = 0;
  try {
    for (const door of doors) {
      await pool.query(`INSERT INTO doors (client_id,name,zone,status,tech,reader,lock_type,ip_address,controller_type,door_swing,access_type,anti_passback,install_date,warranty_expiry,comments) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`,
        [door.client_id||1, door.name||'', door.zone||door.site||'', door.status||'Online', door.tech||'', door.reader||'', door.lock_type||'', door.ip_address||'', door.controller_type||'', door.door_swing||'', door.access_type||'', door.anti_passback||'', door.install_date||null, door.warranty_expiry||null, door.comments||'']);
      imported++;
    }
    const { clientIdForLog, clientLabel } = await describeClientsForLog(doors);
    await logActivity(clientIdForLog, req.user.username, 'Import', 'Imported ' + imported + ' door' + (imported === 1 ? '' : 's') + clientLabel);
    res.json({ success: true, imported });
  } catch (err) { res.status(500).json({ error: err.message, imported }); }
});

app.post('/api/import/servers', authMiddleware, async (req, res) => {
  if (!dbConnected) return res.status(503).json({ error: 'DB not connected' });
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  const servers = req.body;
  let imported = 0;
  try {
    for (const srv of servers) {
      await pool.query(`INSERT INTO servers (client_id,name,zone,status,make,model,capacity,used,health,apps,serial,purchase_date,warranty_expiry,comments) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
        [srv.client_id||1,srv.name||srv.serial||'',srv.zone||srv.location||'',srv.status||'Online',srv.make||'',srv.model||'',srv.capacity||'',srv.used||'',srv.health||'',srv.apps||'',srv.serial||'',srv.purchase_date||null,srv.warranty_expiry||null,srv.comments||'']);
      imported++;
    }
    const { clientIdForLog, clientLabel } = await describeClientsForLog(servers);
    await logActivity(clientIdForLog, req.user.username, 'Import', 'Imported ' + imported + ' server' + (imported === 1 ? '' : 's') + clientLabel);
    res.json({ success: true, imported });
  } catch (err) { res.status(500).json({ error: err.message, imported }); }
});

app.post('/api/import/switches', authMiddleware, async (req, res) => {
  if (!dbConnected) return res.status(503).json({ error: 'DB not connected' });
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  const switches = req.body;
  let imported = 0;
  try {
    for (const sw of switches) {
      await pool.query(`INSERT INTO switches (client_id,name,zone,status,model,firmware,ip_address,mac_address,purchase_date,warranty_expiry,comments) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
        [sw.client_id||1,sw.name||'',sw.zone||sw.location||'',sw.status||'Online',sw.model||'',sw.firmware||'',sw.ip_address||'',sw.mac||'',sw.purchase_date||null,sw.warranty_expiry||null,sw.comments||'']);
      imported++;
    }
    const { clientIdForLog, clientLabel } = await describeClientsForLog(switches);
    await logActivity(clientIdForLog, req.user.username, 'Import', 'Imported ' + imported + ' switch' + (imported === 1 ? '' : 'es') + clientLabel);
    res.json({ success: true, imported });
  } catch (err) { res.status(500).json({ error: err.message, imported }); }
});

app.post('/api/import/software', authMiddleware, async (req, res) => {
  if (!dbConnected) return res.status(503).json({ error: 'DB not connected' });
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  const software = req.body;
  let imported = 0;
  try {
    for (const sw of software) {
      await pool.query(`INSERT INTO software (client_id, name, vendor, version, license_type, status, expiry_date, purchase_date, warranty_expiry, comments) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
        [sw.client_id||1, sw.name||'', sw.vendor||'', sw.version||'', sw.license_type||'', sw.status||'Good', sw.expiry_date||null, sw.purchase_date||null, sw.warranty_expiry||null, sw.comments||'']);
      imported++;
    }
    const { clientIdForLog, clientLabel } = await describeClientsForLog(software);
    await logActivity(clientIdForLog, req.user.username, 'Import', 'Imported ' + imported + ' software' + clientLabel);
    res.json({ success: true, imported });
  } catch (err) { res.status(500).json({ error: err.message, imported }); }
});

app.post('/api/import/stations', authMiddleware, async (req, res) => {
  if (!dbConnected) return res.status(503).json({ error: 'DB not connected' });
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  const stations = req.body;
  let imported = 0;
  try {
    for (const s of stations) {
      await pool.query(`INSERT INTO stations (client_id,name,zone,status,make,model,apps,ip_address,install_date,purchase_date,warranty_expiry) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
        [s.client_id||1, s.name||'', s.zone||'', s.status||'Online', s.make||'', s.model||'', s.apps||'', s.ip_address||'', s.install_date||null, s.purchase_date||null, s.warranty_expiry||null]);
      imported++;
    }
    const { clientIdForLog, clientLabel } = await describeClientsForLog(stations);
    await logActivity(clientIdForLog, req.user.username, 'Import', 'Imported ' + imported + ' station' + (imported === 1 ? '' : 's') + clientLabel);
    res.json({ success: true, imported });
  } catch (err) { res.status(500).json({ error: err.message, imported }); }
});

app.post('/api/import/monitors', authMiddleware, async (req, res) => {
  if (!dbConnected) return res.status(503).json({ error: 'DB not connected' });
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  const monitors = req.body;
  let imported = 0;
  try {
    for (const m of monitors) {
      await pool.query(`INSERT INTO monitors (client_id,name,zone,status,make,model,size,install_date,purchase_date,warranty_expiry) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
        [m.client_id||1, m.name||'', m.zone||'', m.status||'Online', m.make||'', m.model||'', m.size||'', m.install_date||null, m.purchase_date||null, m.warranty_expiry||null]);
      imported++;
    }
    const { clientIdForLog, clientLabel } = await describeClientsForLog(monitors);
    await logActivity(clientIdForLog, req.user.username, 'Import', 'Imported ' + imported + ' monitor' + (imported === 1 ? '' : 's') + clientLabel);
    res.json({ success: true, imported });
  } catch (err) { res.status(500).json({ error: err.message, imported }); }
});

app.post('/api/import/intrusion', authMiddleware, async (req, res) => {
  if (!dbConnected) return res.status(503).json({ error: 'DB not connected' });
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  const points = req.body;
  let imported = 0;
  try {
    for (const i of points) {
      await pool.query(`INSERT INTO intrusion (client_id,name,zone,status,module,sensor_type,ip_address,purchase_date,warranty_expiry,comments) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
        [i.client_id||1, i.name||'', i.zone||'', i.status||'Online', i.module||'', i.sensor_type||'', i.ip_address||'', i.purchase_date||null, i.warranty_expiry||null, i.comments||'']);
      imported++;
    }
    const { clientIdForLog, clientLabel } = await describeClientsForLog(points);
    await logActivity(clientIdForLog, req.user.username, 'Import', 'Imported ' + imported + ' intrusion point' + (imported === 1 ? '' : 's') + clientLabel);
    res.json({ success: true, imported });
  } catch (err) { res.status(500).json({ error: err.message, imported }); }
});

app.post('/api/import/storage', authMiddleware, async (req, res) => {
  if (!dbConnected) return res.status(503).json({ error: 'DB not connected' });
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  const devices = req.body;
  let imported = 0;
  try {
    for (const s of devices) {
      await pool.query(`INSERT INTO storage (client_id,name,zone,status,type,make,model,capacity,used,serial,purchase_date,warranty_expiry,comments) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
        [s.client_id||1, s.name||'', s.zone||'', s.status||'Online', s.type||'', s.make||'', s.model||'', s.capacity||'', s.used||'', s.serial||'', s.purchase_date||null, s.warranty_expiry||null, s.comments||'']);
      imported++;
    }
    const { clientIdForLog, clientLabel } = await describeClientsForLog(devices);
    await logActivity(clientIdForLog, req.user.username, 'Import', 'Imported ' + imported + ' storage device' + (imported === 1 ? '' : 's') + clientLabel);
    res.json({ success: true, imported });
  } catch (err) { res.status(500).json({ error: err.message, imported }); }
});

// ============================================================
// DOORS
// ============================================================

app.get('/api/doors', authMiddleware, async (req, res) => {
  if (!dbConnected) return res.json([]);
  try {
    const clientId = req.user.role === 'admin' ? null : req.user.client_id;
    const query = clientId ? 'SELECT * FROM doors WHERE client_id=$1 ORDER BY zone,name' : 'SELECT * FROM doors ORDER BY zone,name';
    const params = clientId ? [clientId] : [];
    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (err) { res.json([]); }
});

app.put('/api/doors/:id', authMiddleware, async (req, res) => {
  if (!dbConnected) return res.status(503).json({ error: 'DB not connected' });
  const { id } = req.params;
  const { status, comments, name, zone, tech, reader, lock_type, ip_address, controller_type, door_swing, access_type, anti_passback, install_date, warranty_expiry } = req.body;
  try {
    const userClientId = req.user.role === 'admin' ? null : req.user.client_id;
    const asset = await pool.query('SELECT name, client_id FROM doors WHERE id=$1', [id]);
    const assetName = asset.rows[0]?.name || id;
    const assetClientId = asset.rows[0]?.client_id;
    const assetClient = await getClientNameById(assetClientId);
    if (req.user.role === 'admin') {
      const query = userClientId ? `UPDATE doors SET name=COALESCE($1,name),zone=COALESCE($2,zone),status=COALESCE($3,status),tech=COALESCE($4,tech),reader=COALESCE($5,reader),lock_type=COALESCE($6,lock_type),ip_address=COALESCE($7,ip_address),controller_type=COALESCE($8,controller_type),door_swing=COALESCE($9,door_swing),access_type=COALESCE($10,access_type),anti_passback=COALESCE($11,anti_passback),install_date=$12,warranty_expiry=$13,comments=COALESCE($14,comments),updated_at=CURRENT_TIMESTAMP WHERE id=$15 AND client_id=$16` : `UPDATE doors SET name=COALESCE($1,name),zone=COALESCE($2,zone),status=COALESCE($3,status),tech=COALESCE($4,tech),reader=COALESCE($5,reader),lock_type=COALESCE($6,lock_type),ip_address=COALESCE($7,ip_address),controller_type=COALESCE($8,controller_type),door_swing=COALESCE($9,door_swing),access_type=COALESCE($10,access_type),anti_passback=COALESCE($11,anti_passback),install_date=$12,warranty_expiry=$13,comments=COALESCE($14,comments),updated_at=CURRENT_TIMESTAMP WHERE id=$15`;
      const params = userClientId ? [name,zone,status,tech,reader,lock_type,ip_address,controller_type,door_swing,access_type,anti_passback,install_date,warranty_expiry,comments,id,userClientId] : [name,zone,status,tech,reader,lock_type,ip_address,controller_type,door_swing,access_type,anti_passback,install_date,warranty_expiry,comments,id];
      await pool.query(query, params);
    } else {
      const query = userClientId ? 'UPDATE doors SET status=COALESCE($1,status),comments=COALESCE($2,comments),updated_at=CURRENT_TIMESTAMP WHERE id=$3 AND client_id=$4' : 'UPDATE doors SET status=COALESCE($1,status),comments=COALESCE($2,comments),updated_at=CURRENT_TIMESTAMP WHERE id=$3';
      const params = userClientId ? [status,comments,id,userClientId] : [status,comments,id];
      await pool.query(query, params);
    }
    await logActivity(assetClientId || userClientId || 1, req.user.username, 'Updated', `Door ${assetName} updated (${assetClient})`);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ============================================================
// SERVERS
// ============================================================

app.get('/api/servers', authMiddleware, async (req, res) => {
  if (!dbConnected) return res.json([]);
  try {
    const clientId = req.user.role === 'admin' ? null : req.user.client_id;
    const query = clientId ? 'SELECT * FROM servers WHERE client_id=$1 ORDER BY zone,name' : 'SELECT * FROM servers ORDER BY zone,name';
    const params = clientId ? [clientId] : [];
    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (err) { res.json([]); }
});

app.put('/api/servers/:id', authMiddleware, async (req, res) => {
  if (!dbConnected) return res.status(503).json({ error: 'DB not connected' });
  const { id } = req.params;
  const { status, comments, name, zone, make, model, capacity, used, health, apps, serial, purchase_date, warranty_expiry } = req.body;
  try {
    const userClientId = req.user.role === 'admin' ? null : req.user.client_id;
    const asset = await pool.query('SELECT name, client_id FROM servers WHERE id=$1', [id]);
    const assetName = asset.rows[0]?.name || id;
    const assetClientId = asset.rows[0]?.client_id;
    const assetClient = await getClientNameById(assetClientId);
    if (req.user.role === 'admin') {
      const query = userClientId ? 
        `UPDATE servers SET name=COALESCE($1,name),zone=COALESCE($2,zone),status=COALESCE($3,status),make=COALESCE($4,make),model=COALESCE($5,model),capacity=COALESCE($6,capacity),used=COALESCE($7,used),health=COALESCE($8,health),apps=COALESCE($9,apps),serial=COALESCE($10,serial),purchase_date=$11,warranty_expiry=$12,comments=COALESCE($13,comments),updated_at=CURRENT_TIMESTAMP WHERE id=$14 AND client_id=$15` :
        `UPDATE servers SET name=COALESCE($1,name),zone=COALESCE($2,zone),status=COALESCE($3,status),make=COALESCE($4,make),model=COALESCE($5,model),capacity=COALESCE($6,capacity),used=COALESCE($7,used),health=COALESCE($8,health),apps=COALESCE($9,apps),serial=COALESCE($10,serial),purchase_date=$11,warranty_expiry=$12,comments=COALESCE($13,comments),updated_at=CURRENT_TIMESTAMP WHERE id=$14`;
      const params = userClientId ? 
        [name,zone,status,make,model,capacity,used,health,apps,serial,purchase_date,warranty_expiry,comments,id,userClientId] : 
        [name,zone,status,make,model,capacity,used,health,apps,serial,purchase_date,warranty_expiry,comments,id];
      await pool.query(query, params);
    } else {
      const query = userClientId ? 'UPDATE servers SET status=COALESCE($1,status),comments=COALESCE($2,comments),updated_at=CURRENT_TIMESTAMP WHERE id=$3 AND client_id=$4' : 'UPDATE servers SET status=COALESCE($1,status),comments=COALESCE($2,comments),updated_at=CURRENT_TIMESTAMP WHERE id=$3';
      const params = userClientId ? [status,comments,id,userClientId] : [status,comments,id];
      await pool.query(query, params);
    }
    await logActivity(assetClientId || userClientId || 1, req.user.username, 'Updated', `Server ${assetName} updated (${assetClient})`);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ============================================================
// STORAGE
// ============================================================

app.get('/api/storage', authMiddleware, async (req, res) => {
  if (!dbConnected) return res.json([]);
  try {
    const clientId = req.user.role === 'admin' ? null : req.user.client_id;
    const query = clientId ? 'SELECT * FROM storage WHERE client_id=$1 ORDER BY zone,name' : 'SELECT * FROM storage ORDER BY zone,name';
    const params = clientId ? [clientId] : [];
    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (err) { res.json([]); }
});

app.put('/api/storage/:id', authMiddleware, async (req, res) => {
  if (!dbConnected) return res.status(503).json({ error: 'DB not connected' });
  const { id } = req.params;
  const { status, comments, name, zone, type, make, model, capacity, used, serial, purchase_date, warranty_expiry } = req.body;
  try {
    const userClientId = req.user.role === 'admin' ? null : req.user.client_id;
    const asset = await pool.query('SELECT name, client_id FROM storage WHERE id=$1', [id]);
    const assetName = asset.rows[0]?.name || id;
    const assetClientId = asset.rows[0]?.client_id;
    const assetClient = await getClientNameById(assetClientId);
    if (req.user.role === 'admin') {
      const query = userClientId ?
        `UPDATE storage SET name=COALESCE($1,name),zone=COALESCE($2,zone),status=COALESCE($3,status),type=COALESCE($4,type),make=COALESCE($5,make),model=COALESCE($6,model),capacity=COALESCE($7,capacity),used=COALESCE($8,used),serial=COALESCE($9,serial),purchase_date=$10,warranty_expiry=$11,comments=COALESCE($12,comments),updated_at=CURRENT_TIMESTAMP WHERE id=$13 AND client_id=$14` :
        `UPDATE storage SET name=COALESCE($1,name),zone=COALESCE($2,zone),status=COALESCE($3,status),type=COALESCE($4,type),make=COALESCE($5,make),model=COALESCE($6,model),capacity=COALESCE($7,capacity),used=COALESCE($8,used),serial=COALESCE($9,serial),purchase_date=$10,warranty_expiry=$11,comments=COALESCE($12,comments),updated_at=CURRENT_TIMESTAMP WHERE id=$13`;
      const params = userClientId ?
        [name,zone,status,type,make,model,capacity,used,serial,purchase_date,warranty_expiry,comments,id,userClientId] :
        [name,zone,status,type,make,model,capacity,used,serial,purchase_date,warranty_expiry,comments,id];
      await pool.query(query, params);
    } else {
      const query = userClientId ? 'UPDATE storage SET status=COALESCE($1,status),comments=COALESCE($2,comments),updated_at=CURRENT_TIMESTAMP WHERE id=$3 AND client_id=$4' : 'UPDATE storage SET status=COALESCE($1,status),comments=COALESCE($2,comments),updated_at=CURRENT_TIMESTAMP WHERE id=$3';
      const params = userClientId ? [status,comments,id,userClientId] : [status,comments,id];
      await pool.query(query, params);
    }
    await logActivity(assetClientId || userClientId || 1, req.user.username, 'Updated', `Storage device ${assetName} updated (${assetClient})`);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ============================================================
// SWITCHES
// ============================================================

app.get('/api/switches', authMiddleware, async (req, res) => {
  if (!dbConnected) return res.json([]);
  try {
    const clientId = req.user.role === 'admin' ? null : req.user.client_id;
    const query = clientId ? 'SELECT * FROM switches WHERE client_id=$1 ORDER BY zone,name' : 'SELECT * FROM switches ORDER BY zone,name';
    const params = clientId ? [clientId] : [];
    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (err) { res.json([]); }
});

app.put('/api/switches/:id', authMiddleware, async (req, res) => {
  if (!dbConnected) return res.status(503).json({ error: 'DB not connected' });
  const { id } = req.params;
  const { status, comments, name, zone, model, firmware, ip_address, mac, purchase_date, warranty_expiry } = req.body;
  try {
    const userClientId = req.user.role === 'admin' ? null : req.user.client_id;
    const asset = await pool.query('SELECT name, client_id FROM switches WHERE id=$1', [id]);
    const assetName = asset.rows[0]?.name || id;
    const assetClientId = asset.rows[0]?.client_id;
    const assetClient = await getClientNameById(assetClientId);
    if (req.user.role === 'admin') {
      const query = userClientId ? `UPDATE switches SET name=COALESCE($1,name),zone=COALESCE($2,zone),status=COALESCE($3,status),model=COALESCE($4,model),firmware=COALESCE($5,firmware),ip_address=COALESCE($6,ip_address),mac_address=COALESCE($7,mac_address),purchase_date=$8,warranty_expiry=$9,comments=COALESCE($10,comments),updated_at=CURRENT_TIMESTAMP WHERE id=$11 AND client_id=$12` : `UPDATE switches SET name=COALESCE($1,name),zone=COALESCE($2,zone),status=COALESCE($3,status),model=COALESCE($4,model),firmware=COALESCE($5,firmware),ip_address=COALESCE($6,ip_address),mac_address=COALESCE($7,mac_address),purchase_date=$8,warranty_expiry=$9,comments=COALESCE($10,comments),updated_at=CURRENT_TIMESTAMP WHERE id=$11`;
      const params = userClientId ? [name,zone,status,model,firmware,ip_address,mac,purchase_date,warranty_expiry,comments,id,userClientId] : [name,zone,status,model,firmware,ip_address,mac,purchase_date,warranty_expiry,comments,id];
      await pool.query(query, params);
    } else {
      const query = userClientId ? 'UPDATE switches SET status=COALESCE($1,status),comments=COALESCE($2,comments),updated_at=CURRENT_TIMESTAMP WHERE id=$3 AND client_id=$4' : 'UPDATE switches SET status=COALESCE($1,status),comments=COALESCE($2,comments),updated_at=CURRENT_TIMESTAMP WHERE id=$3';
      const params = userClientId ? [status,comments,id,userClientId] : [status,comments,id];
      await pool.query(query, params);
    }
    await logActivity(assetClientId || userClientId || 1, req.user.username, 'Updated', `Switch ${assetName} updated (${assetClient})`);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ============================================================
// SOFTWARE
// ============================================================

app.get('/api/software', authMiddleware, async (req, res) => {
  if (!dbConnected) return res.json([]);
  try {
    const clientId = req.user.role === 'admin' ? null : req.user.client_id;
    const query = clientId ? 'SELECT * FROM software WHERE client_id=$1 ORDER BY name' : 'SELECT * FROM software ORDER BY name';
    const params = clientId ? [clientId] : [];
    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (err) { res.json([]); }
});

// ============================================================
// INTRUSION
// ============================================================

app.get('/api/intrusion', authMiddleware, async (req, res) => {
  if (!dbConnected) return res.json([]);
  try {
    const clientId = req.user.role === 'admin' ? null : req.user.client_id;
    const query = clientId ? 'SELECT * FROM intrusion WHERE client_id=$1 ORDER BY zone,name' : 'SELECT * FROM intrusion ORDER BY zone,name';
    const params = clientId ? [clientId] : [];
    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (err) { res.json([]); }
});

app.put('/api/intrusion/:id', authMiddleware, async (req, res) => {
  if (!dbConnected) return res.status(503).json({ error: 'DB not connected' });
  const { id } = req.params;
  const { status, comments, name, zone, module, sensor_type, ip_address, purchase_date, warranty_expiry } = req.body;
  try {
    const userClientId = req.user.role === 'admin' ? null : req.user.client_id;
    const asset = await pool.query('SELECT name, client_id FROM intrusion WHERE id=$1', [id]);
    const assetName = asset.rows[0]?.name || id;
    const assetClientId = asset.rows[0]?.client_id;
    const assetClient = await getClientNameById(assetClientId);
    let query, params;
    if (req.user.role === 'admin') {
      query = userClientId ?
        'UPDATE intrusion SET name=COALESCE($1,name),zone=COALESCE($2,zone),status=COALESCE($3,status),module=COALESCE($4,module),sensor_type=COALESCE($5,sensor_type),ip_address=COALESCE($6,ip_address),purchase_date=$7,warranty_expiry=$8,comments=COALESCE($9,comments),updated_at=CURRENT_TIMESTAMP WHERE id=$10 AND client_id=$11' :
        'UPDATE intrusion SET name=COALESCE($1,name),zone=COALESCE($2,zone),status=COALESCE($3,status),module=COALESCE($4,module),sensor_type=COALESCE($5,sensor_type),ip_address=COALESCE($6,ip_address),purchase_date=$7,warranty_expiry=$8,comments=COALESCE($9,comments),updated_at=CURRENT_TIMESTAMP WHERE id=$10';
      params = userClientId ?
        [name,zone,status,module,sensor_type,ip_address,purchase_date,warranty_expiry,comments,id,userClientId] :
        [name,zone,status,module,sensor_type,ip_address,purchase_date,warranty_expiry,comments,id];
    } else {
      query = userClientId ? 'UPDATE intrusion SET status=COALESCE($1,status),comments=COALESCE($2,comments),updated_at=CURRENT_TIMESTAMP WHERE id=$3 AND client_id=$4' : 'UPDATE intrusion SET status=COALESCE($1,status),comments=COALESCE($2,comments),updated_at=CURRENT_TIMESTAMP WHERE id=$3';
      params = userClientId ? [status,comments,id,userClientId] : [status,comments,id];
    }
    await pool.query(query, params);
    await logActivity(assetClientId || userClientId || 1, req.user.username, 'Updated', `Intrusion point ${assetName} updated (${assetClient})`);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ============================================================
// SERVICE REQUESTS
// ============================================================

app.get('/api/service-requests', authMiddleware, async (req, res) => {
  if (!dbConnected) return res.json([]);
  try {
    const clientId = req.user.role === 'admin' ? null : req.user.client_id;
    const query = clientId ? 'SELECT * FROM service_requests WHERE client_id=$1 ORDER BY created_at DESC' : 'SELECT * FROM service_requests ORDER BY created_at DESC';
    const params = clientId ? [clientId] : [];
    const result = await pool.query(query, params);
    for (const sr of result.rows) {
      const history = await pool.query('SELECT * FROM sr_history WHERE sr_id=$1 ORDER BY created_at', [sr.id]);
      sr.history = history.rows;
      if (sr.related_hardware && typeof sr.related_hardware === 'string') {
        try { sr.related_hardware = JSON.parse(sr.related_hardware); } catch (e) { sr.related_hardware = []; }
      }
      if (!sr.related_hardware) sr.related_hardware = [];
    }
    res.json(result.rows);
  } catch (err) { res.json([]); }
});

app.post('/api/service-requests', authMiddleware, async (req, res) => {
  if (!dbConnected) return res.status(503).json({ error: 'DB not connected' });
  const { subject, client, site, category, priority, assigned_to, body, related_hardware } = req.body;
  const srId = `SR-${String(Math.floor(Math.random() * 9000) + 1000)}`;
  const clientId = req.user.role === 'admin' ? 1 : req.user.client_id;
  try {
    const result = await pool.query(
      `INSERT INTO service_requests (client_id,sr_id,subject,client,site,category,priority,assigned_to,body,received,created_by,related_hardware) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,CURRENT_DATE,$10,$11) RETURNING *`,
      [clientId, srId, subject, client, site, category, priority, assigned_to, body, req.user.username, JSON.stringify(related_hardware || [])]
    );
    await pool.query('INSERT INTO sr_history (sr_id,time,msg) VALUES ($1,$2,$3)', [result.rows[0].id, new Date().toLocaleTimeString(), 'Created by ' + req.user.username]);
    await logActivity(clientId, req.user.username, 'Created', 'SR ' + srId + ' created for ' + client);
    
    const msToken = req.user.msToken;
    if (msToken) {
      const emailBody = `<h2>New Service Request: ${srId}</h2><p><strong>Client:</strong> ${client}</p><p><strong>Site:</strong> ${site}</p><p><strong>Category:</strong> ${category}</p><p><strong>Priority:</strong> ${priority}</p><p><strong>Assigned To:</strong> ${assigned_to}</p><p><strong>Subject:</strong> ${subject}</p><p><strong>Description:</strong> ${body || 'No description'}</p><hr><p>View in CAMS: <a href="${process.env.APP_URL || "https://e-tech-cams.up.railway.app"}">Open Dashboard</a></p>`;
      await sendEmailNotification('support@e-techsystemsja.com', `[CAMS] New SR: ${srId} — ${subject}`, emailBody, `Bearer ${msToken}`);
      
      if (assigned_to && assigned_to !== 'Unassigned' && TECH_EMAILS[assigned_to]) {
        const techEmailBody = `<h2>You've been assigned a Service Request</h2><p><strong>SR ID:</strong> ${srId}</p><p><strong>Subject:</strong> ${subject}</p><p><strong>Client:</strong> ${client}</p><p><strong>Site:</strong> ${site}</p><p><strong>Priority:</strong> ${priority}</p><hr><p>View in CAMS: <a href="${process.env.APP_URL || "https://e-tech-cams.up.railway.app"}">Open Dashboard</a></p>`;
        await sendEmailNotification(TECH_EMAILS[assigned_to], `[CAMS] Assigned: ${srId} — ${subject}`, techEmailBody, `Bearer ${msToken}`);
      }
    }
    
    res.json(result.rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/service-requests/:id', authMiddleware, async (req, res) => {
  if (!dbConnected) return res.status(503).json({ error: 'DB not connected' });
  const { id } = req.params;
  const { priority, assigned_to, status, notes } = req.body;
  const clientId = req.user.role === 'admin' ? null : req.user.client_id;
  try {
    const current = await pool.query('SELECT * FROM service_requests WHERE id=$1', [id]);
    const oldSr = current.rows[0];
    const oldAssigned = oldSr?.assigned_to;
    const oldStatus = oldSr?.status;
    // COALESCE so a partial update (e.g. the field app's "Resolve" button,
    // which only sends {status:'Resolved'}) doesn't wipe out the other
    // fields — this route previously overwrote priority/assigned_to/notes
    // with NULL whenever they weren't included in the request body.
    const query = clientId ? `UPDATE service_requests SET priority=COALESCE($1,priority),assigned_to=COALESCE($2,assigned_to),status=COALESCE($3,status),notes=COALESCE($4,notes),updated_at=CURRENT_TIMESTAMP WHERE id=$5 AND client_id=$6` : `UPDATE service_requests SET priority=COALESCE($1,priority),assigned_to=COALESCE($2,assigned_to),status=COALESCE($3,status),notes=COALESCE($4,notes),updated_at=CURRENT_TIMESTAMP WHERE id=$5`;
    const params = clientId ? [priority,assigned_to,status,notes,id,clientId] : [priority,assigned_to,status,notes,id];
    await pool.query(query, params);
    
    // Track resolution time for achievements
    if (status === 'Resolved' && oldStatus !== 'Resolved') {
      await pool.query('UPDATE service_requests SET resolved_at = CURRENT_TIMESTAMP WHERE id = $1', [id]);
    }
    
    if (assigned_to && assigned_to !== oldAssigned) {
      await pool.query('INSERT INTO sr_history (sr_id,time,msg) VALUES ($1,$2,$3)', [id, new Date().toLocaleTimeString(), `Transferred from ${oldAssigned||'Unassigned'} to ${assigned_to} by ${req.user.username}`]);
      
      const msToken = req.user.msToken;
      if (msToken && assigned_to !== 'Unassigned' && TECH_EMAILS[assigned_to]) {
        const techEmailBody = `<h2>You've been assigned a Service Request</h2><p><strong>SR ID:</strong> ${oldSr.sr_id}</p><p><strong>Subject:</strong> ${oldSr.subject}</p><p><strong>Client:</strong> ${oldSr.client}</p><p><strong>Site:</strong> ${oldSr.site}</p><p><strong>Priority:</strong> ${priority || oldSr.priority}</p><hr><p>View in CAMS: <a href="${process.env.APP_URL || "https://e-tech-cams.up.railway.app"}">Open Dashboard</a></p>`;
        await sendEmailNotification(TECH_EMAILS[assigned_to], `[CAMS] Assigned: ${oldSr.sr_id} — ${oldSr.subject}`, techEmailBody, `Bearer ${msToken}`);
      }
    }
    
    await pool.query('INSERT INTO sr_history (sr_id,time,msg) VALUES ($1,$2,$3)', [id, new Date().toLocaleTimeString(), `Updated: ${status} by ${req.user.username}`]);
    const logClientId = clientId || 1;
    await logActivity(logClientId, req.user.username, 'Updated', 'SR ' + id + ' updated to ' + status);
    
    if (status === 'Resolved' && oldStatus !== 'Resolved') {
      const updated = await pool.query('SELECT * FROM service_requests WHERE id=$1', [id]);
      const sr = updated.rows[0];
      const history = await pool.query('SELECT * FROM sr_history WHERE sr_id=$1 ORDER BY created_at', [id]);
      const msToken = req.user.msToken;
      if (msToken) {
        const reportBody = `<h2>Service Request Resolved: ${sr.sr_id}</h2><p><strong>Client:</strong> ${sr.client}</p><p><strong>Site:</strong> ${sr.site}</p><p><strong>Category:</strong> ${sr.category}</p><p><strong>Priority:</strong> ${sr.priority}</p><p><strong>Subject:</strong> ${sr.subject}</p><p><strong>Created By:</strong> ${sr.created_by}</p><p><strong>Resolved By:</strong> ${req.user.username}</p><p><strong>Resolution Notes:</strong> ${notes||'No notes'}</p><hr><h3>Timeline</h3><ul>${history.rows.map(h=>`<li>${h.time} — ${h.msg}</li>`).join('')}</ul><hr><p>View in CAMS: <a href="${process.env.APP_URL || "https://e-tech-cams.up.railway.app"}">Open Dashboard</a></p>`;
        await sendEmailNotification('support@e-techsystemsja.com', `[CAMS] RESOLVED: ${sr.sr_id} — ${sr.subject}`, reportBody, `Bearer ${msToken}`);
      }
    }
    
    const updated = await pool.query('SELECT * FROM service_requests WHERE id=$1', [id]);
    res.json({ success: true, data: updated.rows[0] });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/service-requests/:id/transfer', authMiddleware, async (req, res) => {
  if (!dbConnected) return res.status(503).json({ error: 'DB not connected' });
  const { id } = req.params;
  const { assigned_to } = req.body;
  try {
    const current = await pool.query('SELECT * FROM service_requests WHERE id=$1', [id]);
    const oldAssigned = current.rows[0]?.assigned_to;
    await pool.query('UPDATE service_requests SET assigned_to=$1,updated_at=CURRENT_TIMESTAMP WHERE id=$2', [assigned_to, id]);
    await pool.query('INSERT INTO sr_history (sr_id,time,msg) VALUES ($1,$2,$3)', [id, new Date().toLocaleTimeString(), `Transferred from ${oldAssigned||'Unassigned'} to ${assigned_to} by ${req.user.username}`]);
    await logActivity(1, req.user.username, 'Assigned', 'SR ' + id + ' transferred to ' + assigned_to);
    
    const msToken = req.user.msToken;
    if (msToken && assigned_to !== 'Unassigned' && TECH_EMAILS[assigned_to]) {
      const sr = current.rows[0];
      const techEmailBody = `<h2>You've been assigned a Service Request</h2><p><strong>SR ID:</strong> ${sr.sr_id}</p><p><strong>Subject:</strong> ${sr.subject}</p><p><strong>Client:</strong> ${sr.client}</p><p><strong>Site:</strong> ${sr.site}</p><p><strong>Priority:</strong> ${sr.priority}</p><hr><p>View in CAMS: <a href="${process.env.APP_URL || "https://e-tech-cams.up.railway.app"}">Open Dashboard</a></p>`;
      await sendEmailNotification(TECH_EMAILS[assigned_to], `[CAMS] Assigned: ${sr.sr_id} — ${sr.subject}`, techEmailBody, `Bearer ${msToken}`);
    }
    
    const updated = await pool.query('SELECT * FROM service_requests WHERE id=$1', [id]);
    res.json({ success: true, data: updated.rows[0] });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ============================================================
// ACHIEVEMENT TICKER ENDPOINTS
// ============================================================

app.get('/api/achievements', authMiddleware, async (req, res) => {
  if (!dbConnected) return res.json({ messages: [], has_messages: false });
  
  try {
    const clientId = req.user.role === 'admin' ? null : req.user.client_id;
    const messages = [];
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    const tomorrow = new Date(today);
    tomorrow.setDate(tomorrow.getDate() + 1);
    const now = new Date();
    
    // 1. SR RESOLVED TODAY
    const todayResolved = await pool.query(
      "SELECT * FROM service_requests WHERE client_id=$1 AND status='Resolved' AND resolved_at >= $2 AND resolved_at < $3 ORDER BY resolved_at DESC",
      [clientId || 1, today.toISOString(), tomorrow.toISOString()]
    );
    
    const todayCount = todayResolved.rows.length;
    if (todayCount > 0) {
      const latest = todayResolved.rows[0];
      const assigned = latest.assigned_to || 'Unassigned';
      messages.push(`🎯 SR-${latest.sr_id} "${latest.subject}" resolved by ${assigned}`);
    }
    
    // 2. FAST RESOLUTION (< 1 HOUR)
    const fastResolved = await pool.query(
      "SELECT * FROM service_requests WHERE client_id=$1 AND status='Resolved' AND resolved_at IS NOT NULL AND received IS NOT NULL AND (EXTRACT(EPOCH FROM (resolved_at - received)) / 60) < 60 ORDER BY resolved_at DESC LIMIT 1",
      [clientId || 1]
    );
    if (fastResolved.rows.length > 0) {
      const sr = fastResolved.rows[0];
      const mins = Math.round((new Date(sr.resolved_at) - new Date(sr.received)) / 60000);
      const assigned = sr.assigned_to || 'Unassigned';
      messages.push(`⚡ Speed demon! SR-${sr.sr_id} resolved in ${mins} minutes by ${assigned}`);
    }
    
    // 3. 5+ RESOLVED IN A DAY
    if (todayCount >= 5) {
      const assigned = todayResolved.rows[0]?.assigned_to || 'Someone';
      messages.push(`🔥 ${assigned} is on fire — ${todayCount} SRs resolved today`);
    }
    
    // 4. FIRST RESOLUTION OF THE DAY
    if (todayResolved.rows.length > 0) {
      const first = todayResolved.rows[todayResolved.rows.length - 1];
      const time = new Date(first.resolved_at).toLocaleTimeString('en-US', { hour: 'numeric', minute: '2-digit' });
      const assigned = first.assigned_to || 'Unassigned';
      messages.push(`🌅 First resolution of the day — ${assigned} at ${time}`);
    }
    
    // 5. LAST RESOLUTION OF THE DAY
    if (todayResolved.rows.length > 0) {
      const last = todayResolved.rows[0];
      const time = new Date(last.resolved_at).toLocaleTimeString('en-US', { hour: 'numeric', minute: '2-digit' });
      const assigned = last.assigned_to || 'Unassigned';
      messages.push(`🌙 Night owl! ${assigned} resolved SR-${last.sr_id} at ${time}`);
    }
    
    // 6. WEEKEND WORK
    const isWeekend = now.getDay() === 6 || now.getDay() === 0;
    if (isWeekend) {
      const weekendResolved = await pool.query(
        "SELECT * FROM service_requests WHERE client_id=$1 AND status='Resolved' AND resolved_at >= $2 AND resolved_at < $3",
        [clientId || 1, today.toISOString(), tomorrow.toISOString()]
      );
      if (weekendResolved.rows.length > 0) {
        const assigned = weekendResolved.rows[0]?.assigned_to || 'Someone';
        messages.push(`💪 Weekend warrior! ${assigned} resolved ${weekendResolved.rows.length} SRs on ${today.toLocaleDateString('en-US', { weekday: 'long' })}`);
      }
    }
    
    // 7. MILESTONE: 50TH SR
    const totalResolved = await pool.query(
      "SELECT COUNT(*) as count FROM service_requests WHERE client_id=$1 AND status='Resolved'",
      [clientId || 1]
    );
    const total = parseInt(totalResolved.rows[0]?.count || 0);
    
    if (total === 50) {
      const lastResolved = await pool.query(
        "SELECT * FROM service_requests WHERE client_id=$1 AND status='Resolved' ORDER BY resolved_at DESC LIMIT 1",
        [clientId || 1]
      );
      const assigned = lastResolved.rows[0]?.assigned_to || 'Someone';
      messages.push(`🏅 50 SRs resolved — ${assigned} joins the Half Century Club`);
    }
    if (total === 100) {
      const lastResolved = await pool.query(
        "SELECT * FROM service_requests WHERE client_id=$1 AND status='Resolved' ORDER BY resolved_at DESC LIMIT 1",
        [clientId || 1]
      );
      const assigned = lastResolved.rows[0]?.assigned_to || 'Someone';
      messages.push(`💯 Century! ${assigned} just resolved their 100th SR`);
    }
    if (total === 500) {
      const lastResolved = await pool.query(
        "SELECT * FROM service_requests WHERE client_id=$1 AND status='Resolved' ORDER BY resolved_at DESC LIMIT 1",
        [clientId || 1]
      );
      const assigned = lastResolved.rows[0]?.assigned_to || 'Someone';
      messages.push(`👑 Legend status: ${assigned} hits 500 resolved SRs`);
    }
    
    // 8. TEAM MILESTONE: 1000TH ACROSS TEAM
    if (total === 1000) {
      messages.push(`🎉 Team milestone: 1,000 SRs resolved this year`);
    }
    
    // 9. 7-DAY STREAK
    const sevenDaysAgo = new Date(today);
    sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);
    const streakCheck = await pool.query(
      "SELECT DISTINCT DATE(resolved_at) as date FROM service_requests WHERE client_id=$1 AND status='Resolved' AND resolved_at >= $2 ORDER BY date DESC",
      [clientId || 1, sevenDaysAgo.toISOString()]
    );
    const uniqueDays = streakCheck.rows.map(r => new Date(r.date).getDate());
    let streakCount = 0;
    for (let i = 0; i < 7; i++) {
      const checkDate = new Date(today);
      checkDate.setDate(checkDate.getDate() - i);
      if (uniqueDays.includes(checkDate.getDate())) {
        streakCount++;
      } else {
        break;
      }
    }
    if (streakCount >= 7) {
      const assigned = todayResolved.rows[0]?.assigned_to || 'Someone';
      messages.push(`🔥 7-day streak! ${assigned} has resolved at least 1 SR every day this week`);
    }
    if (streakCount >= 30) {
      const assigned = todayResolved.rows[0]?.assigned_to || 'Someone';
      messages.push(`📅 30-day resolution streak — ${assigned} is unstoppable`);
    }
    
    // 10. DAILY LEADERBOARD
    const dailyLeader = await pool.query(
      "SELECT assigned_to, COUNT(*) as count FROM service_requests WHERE client_id=$1 AND status='Resolved' AND resolved_at >= $2 AND resolved_at < $3 AND assigned_to IS NOT NULL AND assigned_to != 'Unassigned' GROUP BY assigned_to ORDER BY count DESC LIMIT 1",
      [clientId || 1, today.toISOString(), tomorrow.toISOString()]
    );
    if (dailyLeader.rows.length > 0 && dailyLeader.rows[0].assigned_to) {
      messages.push(`👑 Today's MVP: ${dailyLeader.rows[0].assigned_to} — ${dailyLeader.rows[0].count} resolutions`);
    }
    
    // 11. WEEKLY LEADERBOARD
    const weekAgo = new Date(today);
    weekAgo.setDate(weekAgo.getDate() - 7);
    const weeklyLeader = await pool.query(
      "SELECT assigned_to, COUNT(*) as count FROM service_requests WHERE client_id=$1 AND status='Resolved' AND resolved_at >= $2 AND assigned_to IS NOT NULL AND assigned_to != 'Unassigned' GROUP BY assigned_to ORDER BY count DESC LIMIT 1",
      [clientId || 1, weekAgo.toISOString()]
    );
    if (weeklyLeader.rows.length > 0 && weeklyLeader.rows[0].assigned_to) {
      messages.push(`🏆 This week's champion: ${weeklyLeader.rows[0].assigned_to} — ${weeklyLeader.rows[0].count} SRs resolved`);
    }
    
    // 12. BUSIEST TECH (MOST ACTIVE SRs)
    const busiestTech = await pool.query(
      "SELECT assigned_to, COUNT(*) as count FROM service_requests WHERE client_id=$1 AND status != 'Resolved' AND assigned_to IS NOT NULL AND assigned_to != 'Unassigned' GROUP BY assigned_to ORDER BY count DESC LIMIT 1",
      [clientId || 1]
    );
    if (busiestTech.rows.length > 0 && busiestTech.rows[0].assigned_to) {
      messages.push(`📋 Busiest tech: ${busiestTech.rows[0].assigned_to} with ${busiestTech.rows[0].count} active SRs`);
    }
    
    // Check if we have any messages
    const hasMessages = messages.length > 0;
    
    res.json({ 
      messages: messages.slice(0, 12),
      has_messages: hasMessages,
      total_resolved: total
    });
    
  } catch (err) {
    console.error('Achievements error:', err);
    res.json({ messages: [], has_messages: false });
  }
});

// ============================================================
// CLIENTS
// ============================================================

app.get('/api/client-names', authMiddleware, async (req, res) => {
  if (!dbConnected) return res.json([]);
  try {
    const result = await pool.query('SELECT id,name FROM clients');
    res.json(result.rows);
  } catch (err) { res.json([]); }
});

app.get('/api/clients', authMiddleware, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  if (!dbConnected) return res.json([]);
  try {
    const result = await pool.query('SELECT id,name,email,phone,address,logo_url FROM clients');
    res.json(result.rows);
  } catch (err) { res.json([]); }
});

app.post('/api/clients', authMiddleware, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  if (!dbConnected) return res.status(503).json({ error: 'DB not connected' });
  const { name, email, phone, address, logo_url } = req.body;
  try {
    const result = await pool.query('INSERT INTO clients (name,email,phone,address,logo_url) VALUES ($1,$2,$3,$4,$5) RETURNING *', [name,email,phone,address,logo_url]);
    await logActivity(1, req.user.username, 'Created', 'Client ' + name + ' added');
    res.json(result.rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/clients/:name', authMiddleware, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  if (!dbConnected) return res.status(503).json({ error: 'DB not connected' });
  const { name } = req.params;
  const { email, phone, address, logo_url } = req.body;
  try {
    const result = await pool.query('UPDATE clients SET email=$1,phone=$2,address=$3,logo_url=$4,updated_at=CURRENT_TIMESTAMP WHERE name=$5 RETURNING *', [email||'',phone||'',address||'',logo_url||'',name]);
    if (result.rowCount === 0) return res.status(404).json({ error: 'Client not found' });
    await logActivity(1, req.user.username, 'Updated', 'Client ' + name + ' updated');
    res.json(result.rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/clients/:name', authMiddleware, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  if (!dbConnected) return res.status(503).json({ error: 'DB not connected' });
  const { name } = req.params;
  try {
    const result = await pool.query('DELETE FROM clients WHERE name=$1', [name]);
    if (result.rowCount === 0) return res.status(404).json({ error: 'Client not found' });
    await logActivity(1, req.user.username, 'Deleted', 'Client ' + name + ' deleted');
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ============================================================
// ACTIVITY LOG
// ============================================================

app.get('/api/activity-log', authMiddleware, async (req, res) => {
  if (!dbConnected) return res.json([]);
  try {
    const limit = parseInt(req.query.limit) || 100;
    const clientId = req.user.role === 'admin' ? null : req.user.client_id;
    const twentyFourHoursAgo = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
    const query = clientId ? 
      'SELECT id,client_id,username,action,detail,created_at FROM activity_log WHERE client_id=$1 AND created_at >= $2 ORDER BY created_at DESC LIMIT $3' : 
      'SELECT id,client_id,username,action,detail,created_at FROM activity_log WHERE created_at >= $1 ORDER BY created_at DESC LIMIT $2';
    const params = clientId ? [clientId, twentyFourHoursAgo, limit] : [twentyFourHoursAgo, limit];
    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (err) { res.json([]); }
});

app.post('/api/activity-log', authMiddleware, async (req, res) => {
  if (!dbConnected) return res.status(503).json({ error: 'DB not connected' });
  const { action, detail } = req.body;
  const clientId = req.user.role === 'admin' ? 1 : req.user.client_id;
  try {
    await pool.query('INSERT INTO activity_log (client_id,username,action,detail) VALUES ($1,$2,$3,$4)', [clientId,req.user.username,action,detail]);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ============================================================
// OUTLOOK — SHARED MAILBOX support@e-techsystemsja.com
// ============================================================

// Shared mailbox access requires the current user to have personally signed in
// via Microsoft SSO (req.user.msToken) — by design, only Microsoft-login users
// can see the support inbox. No app-level fallback token here on purpose.
// (The scheduled bi-weekly reports are separate and still use MS_GRAPH_TOKEN.)
function getGraphToken(req) {
  return req.user.msToken || null;
}

app.get('/api/outlook/emails', authMiddleware, async (req, res) => {
  const graphToken = getGraphToken(req);
  if (!graphToken) {
    try {
      const folder = req.query.folder || 'inbox';
      const result = await pool.query('SELECT * FROM emails WHERE folder=$1 ORDER BY created_at DESC LIMIT 100', [folder]);
      return res.json(result.rows);
    } catch (dbErr) { return res.json([]); }
  }
  try {
    const folder = req.query.folder || 'inbox';
    let endpoint;
    switch(folder) {
      case 'sent': endpoint = `https://graph.microsoft.com/v1.0/users/${SHARED_MAILBOX}/mailFolders/sentitems/messages`; break;
      case 'drafts': endpoint = `https://graph.microsoft.com/v1.0/users/${SHARED_MAILBOX}/mailFolders/drafts/messages`; break;
      case 'deleted': endpoint = `https://graph.microsoft.com/v1.0/users/${SHARED_MAILBOX}/mailFolders/deleteditems/messages`; break;
      default: endpoint = `https://graph.microsoft.com/v1.0/users/${SHARED_MAILBOX}/mailFolders/inbox/messages`;
    }
    const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString();
    const response = await axios.get(endpoint, {
      headers: { Authorization: `Bearer ${graphToken}` },
      timeout: 8000,
      params: { 
        $top: 50, 
        $orderby: 'receivedDateTime desc', 
        $filter: `receivedDateTime ge ${thirtyDaysAgo}`,
        $select: 'id,subject,from,toRecipients,receivedDateTime,bodyPreview,body,isRead,flag,hasAttachments,webLink' 
      }
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
      const result = await pool.query('SELECT * FROM emails WHERE folder=$1 ORDER BY created_at DESC LIMIT 100', [folder]);
      return res.json(result.rows);
    } catch (dbErr) { res.json([]); }
  }
});

app.post('/api/outlook/send', authMiddleware, async (req, res) => {
  const { to, cc, subject, body } = req.body;
  const graphToken = getGraphToken(req);
  try {
    if (!graphToken) throw new Error('No Microsoft Graph token available');
    const emailData = { message: { subject, body: { contentType: 'HTML', content: body }, toRecipients: to.split(',').map(email => ({ emailAddress: { address: email.trim() } })) } };
    if (cc) { emailData.message.ccRecipients = cc.split(',').map(email => ({ emailAddress: { address: email.trim() } })); }
    await axios.post(`https://graph.microsoft.com/v1.0/users/${SHARED_MAILBOX}/sendMail`, emailData, {
      headers: { Authorization: `Bearer ${graphToken}`, 'Content-Type': 'application/json' },
      timeout: 8000
    });
    try {
      await pool.query('INSERT INTO emails (client_id,sender,recipient,subject,body,folder) VALUES ($1,$2,$3,$4,$5,$6)', [req.user.client_id||1,req.user.username,to,subject,body,'sent']);
    } catch (dbErr) { console.error('Failed to save sent email locally:', dbErr.message); }
    res.json({ success: true });
  } catch (err) {
    console.error('Outlook send error:', err.message);
    try {
      await pool.query('INSERT INTO emails (client_id,sender,recipient,subject,body,folder) VALUES ($1,$2,$3,$4,$5,$6)', [req.user.client_id||1,req.user.username,to,subject,body,'sent']);
      res.json({ success: true, local_only: true });
    } catch (dbErr) { res.status(500).json({ error: 'Failed to send email' }); }
  }
});

app.post('/api/outlook/read/:id', authMiddleware, async (req, res) => {
  const graphToken = getGraphToken(req);
  if (!graphToken) return res.status(503).json({ error: 'No Microsoft Graph token available' });
  try { await axios.patch(`https://graph.microsoft.com/v1.0/users/${SHARED_MAILBOX}/messages/${req.params.id}`, { isRead: true }, { headers: { Authorization: `Bearer ${graphToken}`, 'Content-Type': 'application/json' }, timeout: 8000 }); res.json({ success: true }); }
  catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/outlook/flag/:id', authMiddleware, async (req, res) => {
  const { flagged } = req.body;
  const graphToken = getGraphToken(req);
  if (!graphToken) return res.status(503).json({ error: 'No Microsoft Graph token available' });
  try { await axios.patch(`https://graph.microsoft.com/v1.0/users/${SHARED_MAILBOX}/messages/${req.params.id}`, { flag: flagged ? { flagStatus: 'flagged' } : { flagStatus: 'notFlagged' } }, { headers: { Authorization: `Bearer ${graphToken}`, 'Content-Type': 'application/json' }, timeout: 8000 }); res.json({ success: true }); }
  catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/outlook/delete/:id', authMiddleware, async (req, res) => {
  const graphToken = getGraphToken(req);
  if (!graphToken) return res.status(503).json({ error: 'No Microsoft Graph token available' });
  try { await axios.post(`https://graph.microsoft.com/v1.0/users/${SHARED_MAILBOX}/messages/${req.params.id}/move`, { destinationId: 'deleteditems' }, { headers: { Authorization: `Bearer ${graphToken}`, 'Content-Type': 'application/json' }, timeout: 8000 }); res.json({ success: true }); }
  catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/outlook/convert-to-sr/:id', authMiddleware, async (req, res) => {
  const graphToken = getGraphToken(req);
  if (!graphToken) return res.status(503).json({ error: 'No Microsoft Graph token available' });
  try {
    const response = await axios.get(`https://graph.microsoft.com/v1.0/users/${SHARED_MAILBOX}/messages/${req.params.id}`, { headers: { Authorization: `Bearer ${graphToken}` }, timeout: 8000 });
    const msg = response.data;
    const srId = `SR-${String(Math.floor(Math.random() * 9000) + 1000)}`;
    const subject = msg.subject || 'Converted from email';
    const body = msg.bodyPreview || msg.body?.content || '';
    const sender = msg.from?.emailAddress?.name || 'Unknown';
    await pool.query(`INSERT INTO service_requests (client_id,sr_id,subject,client,site,category,priority,assigned_to,body,received,created_by) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,CURRENT_DATE,$10)`,
      [req.user.client_id||1,srId,subject,'KFTL','Unknown','Other','Medium','Unassigned',`From: ${sender}\n\n${body}`,req.user.username]);
    await logActivity(1, req.user.username, 'Converted', 'Email converted to SR ' + srId);
    res.json({ success: true, sr_id: srId });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ============================================================
// FILES — MICROSOFT GRAPH ONEDRIVE
// ============================================================

app.get('/api/files/graph', authMiddleware, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  try {
    const folder = req.query.folder || '';
    const endpoint = folder ? `https://graph.microsoft.com/v1.0/me/drive/root:/${folder}:/children` : 'https://graph.microsoft.com/v1.0/me/drive/root/children';
    const response = await axios.get(endpoint, { headers: { Authorization: `Bearer ${req.user.msToken}` } });
    const files = response.data.value.map(item => ({ id: item.id, name: item.name, type: item.folder ? 'folder' : (item.file?.mimeType||'file'), size: item.size, modified: item.lastModifiedDateTime, webUrl: item.webUrl, downloadUrl: item['@microsoft.graph.downloadUrl'], isFolder: !!item.folder }));
    res.json(files);
  } catch (err) { console.error('Files fetch error:', err.message); res.json([]); }
});

app.get('/api/files/download/:id', authMiddleware, async (req, res) => {
  try { const response = await axios.get(`https://graph.microsoft.com/v1.0/me/drive/items/${req.params.id}`, { headers: { Authorization: `Bearer ${req.user.msToken}` } }); res.redirect(response.data['@microsoft.graph.downloadUrl']); }
  catch (err) { res.status(500).json({ error: err.message }); }
});

// ============================================================
// DATABASE EMAILS (local fallback)
// ============================================================

app.get('/api/emails', authMiddleware, async (req, res) => {
  if (!dbConnected) return res.json([]);
  try {
    const folder = req.query.folder || 'inbox';
    const clientId = req.user.role === 'admin' ? null : req.user.client_id;
    const query = clientId ? 'SELECT * FROM emails WHERE client_id=$1 AND folder=$2 ORDER BY created_at DESC' : 'SELECT * FROM emails WHERE folder=$1 ORDER BY created_at DESC';
    const params = clientId ? [clientId,folder] : [folder];
    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (err) { res.json([]); }
});

app.post('/api/emails', authMiddleware, async (req, res) => {
  if (!dbConnected) return res.status(503).json({ error: 'DB not connected' });
  const { sender, recipient, subject, body, folder } = req.body;
  const clientId = req.user.role === 'admin' ? 1 : req.user.client_id;
  try {
    const result = await pool.query('INSERT INTO emails (client_id,sender,recipient,subject,body,folder) VALUES ($1,$2,$3,$4,$5,$6) RETURNING *', [clientId,sender,recipient,subject,body,folder||'inbox']);
    res.json(result.rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ============================================================
// STATIONS & MONITORS
// ============================================================

app.get('/api/stations', authMiddleware, async (req, res) => {
  if (!dbConnected) return res.json([]);
  try {
    const clientId = req.user.role === 'admin' ? null : req.user.client_id;
    const query = clientId ? 'SELECT * FROM stations WHERE client_id=$1 ORDER BY zone,name' : 'SELECT * FROM stations ORDER BY zone,name';
    const params = clientId ? [clientId] : [];
    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (err) { res.json([]); }
});

app.put('/api/stations/:id', authMiddleware, async (req, res) => {
  if (!dbConnected) return res.status(503).json({ error: 'DB not connected' });
  const { id } = req.params;
  const { status, name, zone, make, model, apps, ip_address, install_date, purchase_date, warranty_expiry } = req.body;
  try {
    const userClientId = req.user.role === 'admin' ? null : req.user.client_id;
    const asset = await pool.query('SELECT name, client_id FROM stations WHERE id=$1', [id]);
    const assetName = asset.rows[0]?.name || id;
    const assetClientId = asset.rows[0]?.client_id;
    const assetClient = await getClientNameById(assetClientId);
    const query = userClientId ? 
      'UPDATE stations SET name=COALESCE($1,name),zone=COALESCE($2,zone),status=COALESCE($3,status),make=COALESCE($4,make),model=COALESCE($5,model),apps=COALESCE($6,apps),ip_address=COALESCE($7,ip_address),install_date=$8,purchase_date=$9,warranty_expiry=$10,updated_at=CURRENT_TIMESTAMP WHERE id=$11 AND client_id=$12' :
      'UPDATE stations SET name=COALESCE($1,name),zone=COALESCE($2,zone),status=COALESCE($3,status),make=COALESCE($4,make),model=COALESCE($5,model),apps=COALESCE($6,apps),ip_address=COALESCE($7,ip_address),install_date=$8,purchase_date=$9,warranty_expiry=$10,updated_at=CURRENT_TIMESTAMP WHERE id=$11';
    const params = userClientId ? [name,zone,status,make,model,apps,ip_address,install_date,purchase_date,warranty_expiry,id,userClientId] : [name,zone,status,make,model,apps,ip_address,install_date,purchase_date,warranty_expiry,id];
    await pool.query(query, params);
    await logActivity(assetClientId || userClientId || 1, req.user.username, 'Updated', `Station ${assetName} updated (${assetClient})`);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/monitors', authMiddleware, async (req, res) => {
  if (!dbConnected) return res.json([]);
  try {
    const clientId = req.user.role === 'admin' ? null : req.user.client_id;
    const query = clientId ? 'SELECT * FROM monitors WHERE client_id=$1 ORDER BY zone,name' : 'SELECT * FROM monitors ORDER BY zone,name';
    const params = clientId ? [clientId] : [];
    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (err) { res.json([]); }
});

app.put('/api/monitors/:id', authMiddleware, async (req, res) => {
  if (!dbConnected) return res.status(503).json({ error: 'DB not connected' });
  const { id } = req.params;
  const { status, name, zone, make, model, size, install_date, purchase_date, warranty_expiry } = req.body;
  try {
    const userClientId = req.user.role === 'admin' ? null : req.user.client_id;
    const asset = await pool.query('SELECT name, client_id FROM monitors WHERE id=$1', [id]);
    const assetName = asset.rows[0]?.name || id;
    const assetClientId = asset.rows[0]?.client_id;
    const assetClient = await getClientNameById(assetClientId);
    const query = userClientId ?
      'UPDATE monitors SET name=COALESCE($1,name),zone=COALESCE($2,zone),status=COALESCE($3,status),make=COALESCE($4,make),model=COALESCE($5,model),size=COALESCE($6,size),install_date=$7,purchase_date=$8,warranty_expiry=$9,updated_at=CURRENT_TIMESTAMP WHERE id=$10 AND client_id=$11' :
      'UPDATE monitors SET name=COALESCE($1,name),zone=COALESCE($2,zone),status=COALESCE($3,status),make=COALESCE($4,make),model=COALESCE($5,model),size=COALESCE($6,size),install_date=$7,purchase_date=$8,warranty_expiry=$9,updated_at=CURRENT_TIMESTAMP WHERE id=$10';
    const params = userClientId ? [name,zone,status,make,model,size,install_date,purchase_date,warranty_expiry,id,userClientId] : [name,zone,status,make,model,size,install_date,purchase_date,warranty_expiry,id];
    await pool.query(query, params);
    await logActivity(assetClientId || userClientId || 1, req.user.username, 'Updated', `Monitor ${assetName} updated (${assetClient})`);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ============================================================
// BI-WEEKLY REPORTS
// ============================================================

function getWeekRange() {
  const now = new Date();
  const dayOfWeek = now.getDay();
  const daysToMonday = dayOfWeek === 0 ? 6 : dayOfWeek - 1;
  const monday = new Date(now);
  monday.setDate(now.getDate() - daysToMonday - 14);
  monday.setHours(0, 0, 0, 0);
  const sunday = new Date(monday);
  sunday.setDate(monday.getDate() + 13);
  sunday.setHours(23, 59, 59, 999);
  return { start: monday, end: sunday };
}

// Deterministic "is this a report week" check based on the calendar date itself,
// rather than an in-memory counter. The old approach (reportWeekCounter++, check
// even/odd) reset to 0 every time the server restarted/redeployed, so which
// Fridays actually sent reports was effectively random rather than a real
// every-other-week cadence.
const REPORT_SCHEDULE_EPOCH = new Date('2026-01-02T00:00:00Z'); // fixed reference Friday
function isReportWeek(date = new Date()) {
  const msPerWeek = 7 * 24 * 60 * 60 * 1000;
  const weeksSinceEpoch = Math.floor((date.getTime() - REPORT_SCHEDULE_EPOCH.getTime()) / msPerWeek);
  return ((weeksSinceEpoch % 2) + 2) % 2 === 0;
}

function formatDateRange(start, end) {
  const options = { day: 'numeric', month: 'long', year: 'numeric' };
  return `${start.toLocaleDateString('en-GB', options)} — ${end.toLocaleDateString('en-GB', options)}`;
}

async function generateClientReport(clientId, clientName, clientEmail, msToken) {
  const { start, end } = getWeekRange();
  const dateRangeStr = formatDateRange(start, end);

  const cameras = await pool.query('SELECT status FROM cameras WHERE client_id=$1', [clientId]);
  const doors = await pool.query('SELECT status FROM doors WHERE client_id=$1', [clientId]);
  const servers = await pool.query('SELECT status FROM servers WHERE client_id=$1', [clientId]);
  const switches = await pool.query('SELECT status FROM switches WHERE client_id=$1', [clientId]);
  
  const totalAssets = cameras.rowCount + doors.rowCount + servers.rowCount + switches.rowCount;
  const onlineAssets = cameras.rows.filter(c => c.status === 'Online' || c.status === 'Working').length +
                       doors.rows.filter(d => d.status === 'Online' || d.status === 'Working').length +
                       servers.rows.filter(s => s.status === 'Online').length +
                       switches.rows.filter(s => s.status === 'Online').length;
  const offlineAssets = totalAssets - onlineAssets;
  const healthPct = totalAssets > 0 ? ((onlineAssets / totalAssets) * 100).toFixed(1) : '100.0';

  const srsPeriod = await pool.query(
    'SELECT * FROM service_requests WHERE client_id=$1 AND created_at >= $2 AND created_at <= $3 ORDER BY created_at DESC',
    [clientId, start.toISOString(), end.toISOString()]
  );
  
  const srsCreated = srsPeriod.rows.length;
  const srsResolved = srsPeriod.rows.filter(sr => sr.status === 'Resolved').length;
  
  const openSRs = await pool.query(
    "SELECT * FROM service_requests WHERE client_id=$1 AND status != 'Resolved' ORDER BY created_at DESC",
    [clientId]
  );
  
  const highPriorityOpen = openSRs.rows.filter(sr => sr.priority === 'High').length;

  let srTable = '';
  if (srsPeriod.rows.length > 0) {
    srTable = `<table border="1" cellpadding="8" cellspacing="0" style="border-collapse:collapse;width:100%;margin-top:12px;">
      <tr style="background:#f0f0f0;"><th>SR ID</th><th>Subject</th><th>Priority</th><th>Status</th><th>Assigned</th><th>Created</th></tr>`;
    srsPeriod.rows.forEach(sr => {
      const createdDate = new Date(sr.created_at).toLocaleDateString('en-GB', { day: '2-digit', month: '2-digit' });
      srTable += `<tr><td>${sr.sr_id}</td><td>${sr.subject}</td><td>${sr.priority}</td><td>${sr.status}</td><td>${sr.assigned_to || 'Unassigned'}</td><td>${createdDate}</td></tr>`;
    });
    srTable += '</table>';
  } else {
    srTable = '<p>No service requests were created or updated during this period.</p>';
  }

  const emailBody = `
    <div style="font-family:Arial,sans-serif;max-width:650px;margin:0 auto;">
      <h2 style="color:#1a3a5c;">CAMS Bi-Weekly Report</h2>
      <p><strong>Client:</strong> ${clientName}</p>
      <p><strong>Period:</strong> ${dateRangeStr}</p>
      <hr>
      <p>Dear ${clientName} Team,</p>
      <p>Here is your bi-weekly asset management summary from E-Tech Systems.</p>
      <h3 style="color:#1a3a5c;">Overview</h3>
      <p>Over the past two weeks, <strong>${srsCreated} service requests</strong> were raised for your sites and <strong>${srsResolved} were resolved</strong>. You currently have <strong>${openSRs.rows.length} open requests</strong>, <strong>${highPriorityOpen} of which ${highPriorityOpen === 1 ? 'is' : 'are'} high priority</strong>${highPriorityOpen > 0 ? ' and require immediate attention' : ''}.</p>
      <p>Your asset health stands at <strong>${healthPct}%</strong> with <strong>${onlineAssets} of ${totalAssets} assets</strong> online and healthy. <strong>${offlineAssets} assets</strong> are currently offline or defective and may need servicing.</p>
      <h3 style="color:#1a3a5c;">Key Figures</h3>
      <table border="1" cellpadding="8" cellspacing="0" style="border-collapse:collapse;width:100%;">
        <tr style="background:#f0f0f0;"><td><strong>Service Requests Created</strong></td><td>${srsCreated}</td></tr>
        <tr><td><strong>Service Requests Resolved</strong></td><td>${srsResolved}</td></tr>
        <tr style="background:#f0f0f0;"><td><strong>Currently Open SRs</strong></td><td>${openSRs.rows.length}</td></tr>
        <tr><td><strong>High Priority Open SRs</strong></td><td>${highPriorityOpen}</td></tr>
        <tr style="background:#f0f0f0;"><td><strong>Total Assets</strong></td><td>${totalAssets}</td></tr>
        <tr><td><strong>Online / Healthy</strong></td><td>${onlineAssets} (${healthPct}%)</td></tr>
        <tr style="background:#f0f0f0;"><td><strong>Offline / Defective</strong></td><td>${offlineAssets}</td></tr>
      </table>
      <h3 style="color:#1a3a5c;">Service Requests This Period</h3>
      ${srTable}
      ${highPriorityOpen > 0 ? `<h3 style="color:#cc0000;">Priority Items In Progress</h3><p><strong>${highPriorityOpen} high priority SR${highPriorityOpen > 1 ? 's' : ''} remain${highPriorityOpen === 1 ? 's' : ''} open.</strong> Our team is actively working to resolve ${highPriorityOpen === 1 ? 'this request' : 'these requests'} as soon as possible.</p>` : ''}
      ${offlineAssets > 0 ? `<p><strong>${offlineAssets} assets are currently offline or defective.</strong> While not listed here, your account manager can provide a full breakdown on request.</p>` : ''}
      <p>If you have any questions or need to escalate an issue, please reply to this email or submit a new request through the CAMS portal.</p>
      <p>View full dashboard: <a href="${process.env.APP_URL || "https://e-tech-cams.up.railway.app"}">Open CAMS</a></p>
      <p style="color:#666;font-size:12px;">— E-Tech Systems Support</p>
    </div>`;

  if (clientEmail) {
    await sendEmailNotification(clientEmail, `[CAMS] Bi-Weekly Report — ${clientName} — ${dateRangeStr}`, emailBody, `Bearer ${msToken}`);
    console.log(`✅ Client report sent to ${clientName} (${clientEmail})`);
  }
}

async function generateAdminReport(msToken) {
  const { start, end } = getWeekRange();
  const dateRangeStr = formatDateRange(start, end);

  const clientsResult = await pool.query('SELECT id,name,email FROM clients');
  const clients = clientsResult.rows;

  const totalCameras = await pool.query('SELECT status FROM cameras');
  const totalDoors = await pool.query('SELECT status FROM doors');
  const totalServers = await pool.query('SELECT status FROM servers');
  const totalSwitches = await pool.query('SELECT status FROM switches');
  
  const totalAssets = totalCameras.rowCount + totalDoors.rowCount + totalServers.rowCount + totalSwitches.rowCount;
  const onlineAssets = totalCameras.rows.filter(c => c.status === 'Online' || c.status === 'Working').length +
                       totalDoors.rows.filter(d => d.status === 'Online' || d.status === 'Working').length +
                       totalServers.rows.filter(s => s.status === 'Online').length +
                       totalSwitches.rows.filter(s => s.status === 'Online').length;
  const offlineAssets = totalAssets - onlineAssets;
  const healthPct = totalAssets > 0 ? ((onlineAssets / totalAssets) * 100).toFixed(1) : '100.0';

  const allSRsPeriod = await pool.query(
    'SELECT * FROM service_requests WHERE created_at >= $1 AND created_at <= $2',
    [start.toISOString(), end.toISOString()]
  );
  const srsCreated = allSRsPeriod.rows.length;
  const srsResolved = allSRsPeriod.rows.filter(sr => sr.status === 'Resolved').length;
  
  const openSRs = await pool.query("SELECT * FROM service_requests WHERE status != 'Resolved' ORDER BY created_at DESC");
  const highPriorityOpen = openSRs.rows.filter(sr => sr.priority === 'High');

  // Fetch client_id + status for every asset once (4 queries total instead of 4-per-client),
  // then group in memory. This replaces the old per-client query loop that ran 4 queries
  // per client per pass (and ran that whole loop twice).
  const allCamerasByClient = await pool.query('SELECT client_id, status FROM cameras');
  const allDoorsByClient = await pool.query('SELECT client_id, status FROM doors');
  const allServersByClient = await pool.query('SELECT client_id, status FROM servers');
  const allSwitchesByClient = await pool.query('SELECT client_id, status FROM switches');

  function groupByClient(rows) {
    const map = {};
    for (const row of rows) {
      if (!map[row.client_id]) map[row.client_id] = [];
      map[row.client_id].push(row);
    }
    return map;
  }
  const camerasByClient = groupByClient(allCamerasByClient.rows);
  const doorsByClient = groupByClient(allDoorsByClient.rows);
  const serversByClient = groupByClient(allServersByClient.rows);
  const switchesByClient = groupByClient(allSwitchesByClient.rows);

  let clientTable = '';
  let lowestHealthClient = null;
  let lowestHealth = 100;

  for (const client of clients) {
    const cCameras = camerasByClient[client.id] || [];
    const cDoors = doorsByClient[client.id] || [];
    const cServers = serversByClient[client.id] || [];
    const cSwitches = switchesByClient[client.id] || [];

    const cTotal = cCameras.length + cDoors.length + cServers.length + cSwitches.length;
    const cOnline = cCameras.filter(c => c.status === 'Online' || c.status === 'Working').length +
                    cDoors.filter(d => d.status === 'Online' || d.status === 'Working').length +
                    cServers.filter(s => s.status === 'Online').length +
                    cSwitches.filter(s => s.status === 'Online').length;
    const cOffline = cTotal - cOnline;
    const cHealthNum = cTotal > 0 ? parseFloat(((cOnline / cTotal) * 100).toFixed(1)) : 100;
    const cHealth = cHealthNum.toFixed(1);

    const cSRsCreated = allSRsPeriod.rows.filter(sr => sr.client_id === client.id).length;
    const cSRsResolved = allSRsPeriod.rows.filter(sr => sr.client_id === client.id && sr.status === 'Resolved').length;
    const cOpen = openSRs.rows.filter(sr => sr.client_id === client.id).length;

    clientTable += `<tr><td>${client.name}</td><td>${cTotal}</td><td>${cOnline}</td><td>${cOffline}</td><td>${cHealth}%</td><td>${cSRsCreated}</td><td>${cSRsResolved}</td><td>${cOpen}</td></tr>`;

    if (cHealthNum < lowestHealth) {
      lowestHealth = cHealthNum;
      lowestHealthClient = client.name;
    }
  }

  let hpTable = '';
  if (highPriorityOpen.length > 0) {
    hpTable = `<table border="1" cellpadding="8" cellspacing="0" style="border-collapse:collapse;width:100%;margin-top:12px;">
      <tr style="background:#f0f0f0;"><th>SR ID</th><th>Client</th><th>Subject</th><th>Assigned</th><th>Created</th></tr>`;
    highPriorityOpen.forEach(sr => {
      const createdDate = new Date(sr.created_at).toLocaleDateString('en-GB', { day: '2-digit', month: '2-digit' });
      hpTable += `<tr><td>${sr.sr_id}</td><td>${sr.client}</td><td>${sr.subject}</td><td>${sr.assigned_to || 'Unassigned'}</td><td>${createdDate}</td></tr>`;
    });
    hpTable += '</table>';
  }

  const activityLog = await pool.query(
    'SELECT * FROM activity_log WHERE created_at >= $1 AND created_at <= $2 ORDER BY created_at DESC LIMIT 20',
    [start.toISOString(), end.toISOString()]
  );
  
  let activityTable = '';
  if (activityLog.rows.length > 0) {
    activityTable = `<table border="1" cellpadding="8" cellspacing="0" style="border-collapse:collapse;width:100%;margin-top:12px;">
      <tr style="background:#f0f0f0;"><th>Date</th><th>User</th><th>Action</th><th>Detail</th></tr>`;
    activityLog.rows.forEach(log => {
      const logDate = new Date(log.created_at).toLocaleDateString('en-GB', { day: '2-digit', month: '2-digit' });
      activityTable += `<tr><td>${logDate}</td><td>${log.username}</td><td>${log.action}</td><td>${log.detail}</td></tr>`;
    });
    activityTable += '</table>';
  }

  const emailBody = `
    <div style="font-family:Arial,sans-serif;max-width:650px;margin:0 auto;">
      <h2 style="color:#1a3a5c;">CAMS Bi-Weekly Admin Report</h2>
      <p><strong>Period:</strong> ${dateRangeStr}</p>
      <hr>
      <h3 style="color:#1a3a5c;">Executive Summary</h3>
      <p>Across all <strong>${clients.length} clients</strong>, <strong>${srsCreated} service requests</strong> were created in the last two weeks and <strong>${srsResolved} were resolved</strong>. There are currently <strong>${openSRs.rows.length} open requests</strong>, of which <strong>${highPriorityOpen.length} ${highPriorityOpen.length === 1 ? 'is' : 'are'} high priority</strong> and require immediate action.</p>
      <p>Overall asset health across all clients is <strong>${healthPct}%</strong> — <strong>${onlineAssets} of ${totalAssets} assets</strong> are online and healthy. <strong>${offlineAssets} assets</strong> are currently offline or defective.</p>
      <h3 style="color:#1a3a5c;">Overall Figures</h3>
      <table border="1" cellpadding="8" cellspacing="0" style="border-collapse:collapse;width:100%;">
        <tr style="background:#f0f0f0;"><td><strong>Total Clients</strong></td><td>${clients.length}</td></tr>
        <tr><td><strong>Service Requests Created</strong></td><td>${srsCreated}</td></tr>
        <tr style="background:#f0f0f0;"><td><strong>Service Requests Resolved</strong></td><td>${srsResolved}</td></tr>
        <tr><td><strong>Currently Open SRs</strong></td><td>${openSRs.rows.length}</td></tr>
        <tr style="background:#f0f0f0;"><td><strong>High Priority Open SRs</strong></td><td>${highPriorityOpen.length}</td></tr>
        <tr><td><strong>Total Assets (all clients)</strong></td><td>${totalAssets}</td></tr>
        <tr style="background:#f0f0f0;"><td><strong>Online / Healthy</strong></td><td>${onlineAssets} (${healthPct}%)</td></tr>
        <tr><td><strong>Offline / Defective</strong></td><td>${offlineAssets}</td></tr>
      </table>
      <h3 style="color:#1a3a5c;">Breakdown by Client</h3>
      <table border="1" cellpadding="8" cellspacing="0" style="border-collapse:collapse;width:100%;">
        <tr style="background:#f0f0f0;"><th>Client</th><th>Assets</th><th>Online</th><th>Offline</th><th>Health</th><th>SRs Created</th><th>Resolved</th><th>Open</th></tr>
        ${clientTable}
      </table>
      ${lowestHealthClient && lowestHealth < 95 ? `<p><strong>${lowestHealthClient}</strong> has the lowest asset health at <strong>${lowestHealth}%</strong> and may need additional attention.</p>` : ''}
      ${highPriorityOpen.length > 0 ? `<h3 style="color:#cc0000;">Open High Priority SRs</h3><p>These require immediate action:</p>${hpTable}` : '<p>No high priority SRs are currently open.</p>'}
      ${activityLog.rows.length > 0 ? `<h3 style="color:#1a3a5c;">Notable Activity (Last 14 Days)</h3>${activityTable}` : ''}
      <p>View full dashboard: <a href="${process.env.APP_URL || "https://e-tech-cams.up.railway.app"}">Open CAMS</a></p>
    </div>`;

  await sendEmailNotification(ADMIN_EMAIL, `[CAMS] Bi-Weekly Admin Report — ${dateRangeStr}`, emailBody, `Bearer ${msToken}`);
  console.log(`✅ Admin report sent to ${ADMIN_EMAIL}`);
}

async function runBiWeeklyReports() {
  if (!dbConnected) {
    console.log('⚠️ Reports skipped: DB not connected');
    return;
  }
  
  console.log('📊 Running bi-weekly reports...');
  
  try {
    const msToken = process.env.MS_GRAPH_TOKEN;
    
    if (!msToken) {
      console.log('⚠️ No MS Graph token available for reports. Skipping.');
      return;
    }
    
    await generateAdminReport(msToken);
    
    const clients = await pool.query('SELECT id,name,email FROM clients WHERE email IS NOT NULL AND email != \'\'');
    for (const client of clients.rows) {
      await generateClientReport(client.id, client.name, client.email, msToken);
    }
    
    console.log('✅ Bi-weekly reports completed');
  } catch (err) {
    console.error('❌ Report generation failed:', err.message);
  }
}

cron.schedule('0 17 * * 5', () => {
  if (isReportWeek()) {
    runBiWeeklyReports();
  }
}, {
  timezone: "America/Jamaica"
});

console.log('📅 Bi-weekly reports scheduled: Every other Friday at 5:00 PM Jamaica time');

app.post('/api/reports/run', authMiddleware, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  try {
    await runBiWeeklyReports();
    res.json({ success: true, message: 'Reports generated and sent' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================
// SERVE HTML
// ============================================================

app.get('/', (req, res) => { res.sendFile(path.join(__dirname, 'index.html')); });
app.get('/mobile', (req, res) => { res.sendFile(path.join(__dirname, 'field-app.html')); });
app.get('*', (req, res) => { res.sendFile(path.join(__dirname, 'index.html')); });

// ============================================================
// START
// ============================================================

app.listen(port, () => {
  console.log(`🚀 Running on port ${port}`);
  console.log(`📊 DB: ${dbConnected ? '✅ Connected' : '❌ Disconnected'}`);
});
