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
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

const app = express();
// Railway (like most PaaS providers) terminates HTTPS at its proxy layer and
// forwards plain HTTP internally to this app — without this, req.protocol
// always reports "http" even when the actual visitor connected over https,
// which broke the Graph OAuth redirect_uri matching (Microsoft requires an
// exact match, and "http://..." != "https://..." as far as it's concerned).
app.set('trust proxy', true);
const port = process.env.PORT || 3000;

// Shared mailbox
const SHARED_MAILBOX = 'support@e-techsystemsja.com';

// ============================================================
// SELF-REFRESHING MICROSOFT GRAPH TOKEN (for the shared mailbox)
// ============================================================
// Graph access tokens cannot be made to never expire — that's a Microsoft
// platform limit, not a config option. What CAN last effectively forever is
// the refresh_token issued alongside it (as long as it's used at least once
// every ~90 days), which this exchanges for a fresh access_token
// automatically whenever the stored one is close to expiring. This replaces
// the old approach of manually pasting a new MS_GRAPH_TOKEN into Railway
// roughly every hour.
const MS_CLIENT_ID_SERVER = 'e87a6592-aaa5-4a13-9c85-8dbc8e9cd7b2';
const MS_TENANT_ID_SERVER = '799ae988-9d3d-40d3-bf5c-93197f5d8d44';
const GRAPH_SCOPES = 'https://graph.microsoft.com/Mail.Send https://graph.microsoft.com/Mail.ReadWrite offline_access';

async function getStoredGraphAuth() {
  if (!dbConnected) return null;
  try {
    const result = await pool.query('SELECT access_token, refresh_token, expires_at FROM graph_auth WHERE id = 1');
    return result.rows[0] || null;
  } catch (err) { return null; }
}

async function saveGraphAuth(accessToken, refreshToken, expiresInSeconds) {
  const expiresAt = new Date(Date.now() + expiresInSeconds * 1000);
  await pool.query(
    `INSERT INTO graph_auth (id, access_token, refresh_token, expires_at, updated_at)
     VALUES (1, $1, $2, $3, CURRENT_TIMESTAMP)
     ON CONFLICT (id) DO UPDATE SET access_token = $1, refresh_token = $2, expires_at = $3, updated_at = CURRENT_TIMESTAMP`,
    [accessToken, refreshToken, expiresAt]
  );
}

async function refreshGraphToken(refreshToken) {
  const response = await axios.post(
    `https://login.microsoftonline.com/${MS_TENANT_ID_SERVER}/oauth2/v2.0/token`,
    new URLSearchParams({
      client_id: MS_CLIENT_ID_SERVER,
      grant_type: 'refresh_token',
      refresh_token: refreshToken,
      scope: GRAPH_SCOPES
    }),
    { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
  );
  const { access_token, refresh_token, expires_in } = response.data;
  // Microsoft may or may not rotate the refresh_token on each use — if it
  // doesn't send a new one, keep using the current one.
  await saveGraphAuth(access_token, refresh_token || refreshToken, expires_in);
  return access_token;
}

// The one function everything else should call — always returns a valid,
// current token (refreshing automatically if needed), or null if the shared
// mailbox has never been connected at all.
async function getValidGraphToken() {
  const stored = await getStoredGraphAuth();
  if (!stored || !stored.access_token) {
    return process.env.MS_GRAPH_TOKEN || null; // fallback for a not-yet-migrated deployment
  }
  const refreshBufferMs = 5 * 60 * 1000; // refresh 5 minutes before actual expiry
  const isExpiringSoon = new Date(stored.expires_at).getTime() - refreshBufferMs < Date.now();
  if (isExpiringSoon && stored.refresh_token) {
    try {
      return await refreshGraphToken(stored.refresh_token);
    } catch (err) {
      console.error('❌ Failed to auto-refresh Graph token:', err.response?.data?.error_description || err.message);
      return stored.access_token; // fall back to what we have rather than fail outright
    }
  }
  return stored.access_token;
}


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
  'TECH_USERNAME', 'TECH_PASSWORD',
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

// The database can drop an idle pooled connection (restart, failover, an
// admin terminating sessions). pg reports that as an error event on the
// pool; with no listener Node treats it as unhandled and the whole server
// exits. Log it instead: the pool discards that client and opens a fresh
// connection on the next query.
pool.on('error', (err) => {
  console.error('⚠️ Idle DB connection lost:', err.message);
});

let dbConnected = false;

pool.connect((err, client, release) => {
  if (err) {
    console.error('❌ DB Error:', err.message);
  } else {
    console.log('✅ DB Connected');
    dbConnected = true;
    release();
    // Schema change for client full logos (also in migrations/004). Safe to
    // re-run; a failure is logged and the server keeps running.
    pool.query('ALTER TABLE clients ADD COLUMN IF NOT EXISTS logo_full_url TEXT')
      .then(() => console.log('✅ clients.logo_full_url column ready'))
      .catch(e => console.error('❌ Could not add clients.logo_full_url:', e.message));
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

// Validates the client of every import row before anything is inserted. Returns the
// parsed client_id for each row, or null after sending a 400 if any row is unusable.
async function validateImportClients(rows, res) {
  if (!Array.isArray(rows) || rows.length === 0) {
    res.status(400).json({ error: 'Import body must be a non-empty array of rows.' });
    return null;
  }
  const clientIds = rows.map(r => {
    const raw = r && r.client_id != null ? String(r.client_id).trim() : '';
    return /^\d+$/.test(raw) && Number(raw) > 0 ? Number(raw) : null;
  });
  if (clientIds.some(id => id === null)) {
    res.status(400).json({ error: 'Every row needs a client. Select a client before importing.' });
    return null;
  }
  const distinct = [...new Set(clientIds)];
  // ids beyond the int4 range cannot exist and would make the lookup itself throw
  const lookup = distinct.filter(id => id <= 2147483647);
  const result = lookup.length ? await pool.query('SELECT id FROM clients WHERE id = ANY($1)', [lookup]) : { rows: [] };
  const known = new Set(result.rows.map(c => Number(c.id)));
  const unknown = distinct.filter(id => !known.has(id));
  if (unknown.length) {
    res.status(400).json({ error: 'Unknown client id(s): ' + unknown.join(', ') });
    return null;
  }
  return clientIds;
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

// client_admin/client_user tokens (the new per-person client accounts) only
// carry {id, role} — never client_id or zone access — so that revoking a
// sub-user's zone access, or disabling their account, takes effect on their
// very next request instead of waiting up to 42 days for their token to
// expire. This looks up their current client_id/zones/status fresh from the
// DB on every request. Staff token shapes (admin, technician) already carry
// client_id directly in the token and are left untouched — they don't hit
// the DB here at all.
async function loadFreshUserPermissions(decoded) {
  const result = await pool.query('SELECT id,email,client_id,role,status FROM users WHERE id=$1', [decoded.id]);
  const u = result.rows[0];
  if (!u || u.status !== 'active') return null;
  const user = { id: u.id, username: u.email, email: u.email, client_id: u.client_id, role: u.role };
  if (u.role === 'client_user') {
    const zoneRows = await pool.query('SELECT z.name FROM user_zone_access uza JOIN zones z ON z.id=uza.zone_id WHERE uza.user_id=$1', [u.id]);
    user.zones = zoneRows.rows.map(r => r.name);
  }
  return user;
}

async function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    return res.status(401).json({ error: 'No token provided' });
  }

  const token = authHeader.split(' ')[1];
  if (!token) {
    return res.status(401).json({ error: 'Invalid token format' });
  }

  let decoded;
  try {
    decoded = jwt.verify(token, process.env.JWT_SECRET);
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token' });
  }

  // The shared KFTL/KWL/PAJ logins (role 'client') have been retired — every
  // client now signs in with their own invited account. Old shared-login
  // tokens are refused so those sessions end instead of lingering for up to
  // 42 days.
  if (decoded.role === 'client') {
    return res.status(401).json({ error: 'Shared client logins have been retired — sign in with your invited email account.' });
  }

  if (decoded.role === 'client_admin' || decoded.role === 'client_user') {
    let user;
    try {
      user = await loadFreshUserPermissions(decoded);
    } catch (err) {
      // A database hiccup is not a reason to sign the person out.
      return res.status(503).json({ error: 'Service temporarily unavailable' });
    }
    if (!user) return res.status(401).json({ error: 'Account no longer active' });
    req.user = user;
  } else {
    req.user = decoded;
  }
  next();
}

// Applied to any list endpoint whose rows carry a `zone` column — a
// client_user only sees rows in the zone(s) their client_admin assigned
// them. client_admin (whole-client access) and every other role are
// unaffected, since only client_user tokens ever populate req.user.zones.
function filterByZoneAccess(rows, req) {
  if (req.user.role !== 'client_user' || !req.user.zones) return rows;
  return rows.filter(r => req.user.zones.includes(r.zone));
}

// client_admin/client_user may update an asset's status and comments only —
// the same thing the old shared client logins could do. Every other field
// stays E-Tech-staff-only. The asset must belong to their client, and a
// client_user may only touch assets in the zone(s) assigned to them.
// Admin and technician requests pass through untouched.
const CLIENT_EDITABLE_ASSET_TABLES = ['cameras', 'doors', 'servers', 'storage', 'switches', 'intrusion', 'stations', 'monitors'];

async function blockAssetEdit(req, res, next) {
  if (req.user.role !== 'client_admin' && req.user.role !== 'client_user') return next();

  const table = req.path.split('/')[2]; // '/api/<table>/:id[/comment]'
  if (!CLIENT_EDITABLE_ASSET_TABLES.includes(table)) {
    return res.status(403).json({ error: 'Not authorized' });
  }

  // Drop everything except status and comments before the route sees it.
  req.body = { status: req.body?.status, comments: req.body?.comments };

  try {
    const result = await pool.query(`SELECT client_id, zone FROM ${table} WHERE id=$1`, [req.params.id]);
    const asset = result.rows[0];
    if (!asset || asset.client_id !== req.user.client_id) {
      return res.status(404).json({ error: 'Asset not found' });
    }
    if (req.user.role === 'client_user' && !(req.user.zones || []).includes(asset.zone)) {
      return res.status(404).json({ error: 'Asset not found' });
    }
    next();
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
}

function isClientAccount(req) {
  return req.user.role === 'client_admin' || req.user.role === 'client_user';
}

const loginRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many login attempts. Try again in a few minutes.' }
});

const inviteRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many attempts. Try again in a few minutes.' }
});

// ============================================================
// HEALTH CHECK
// ============================================================

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', db: dbConnected ? 'connected' : 'disconnected' });
});

// ============================================================
// AUTH
// ============================================================

app.post('/api/auth/login', loginRateLimit, async (req, res) => {
  const { username, password } = req.body;

  if (username === process.env.ADMIN_USERNAME && password === process.env.ADMIN_PASSWORD) {
    const token = jwt.sign({ id: 1, username: process.env.ADMIN_USERNAME, client_id: null, role: 'admin' }, process.env.JWT_SECRET, { expiresIn: '42d' });
    await logActivity(1, process.env.ADMIN_USERNAME, 'Login', 'Admin logged in');
    return res.json({ token, user: { id: 1, username: process.env.ADMIN_USERNAME, client_id: null, client_name: null, role: 'admin', photo_url: null } });
  }

  if (username === process.env.TECH_USERNAME && password === process.env.TECH_PASSWORD) {
    const token = jwt.sign({ id: 3, username: process.env.TECH_USERNAME, client_id: null, role: 'technician' }, process.env.JWT_SECRET, { expiresIn: '42d' });
    await logActivity(1, process.env.TECH_USERNAME, 'Login', 'Technician logged in');
    return res.json({ token, user: { id: 3, username: process.env.TECH_USERNAME, client_id: null, client_name: null, role: 'technician', photo_url: null } });
  }

  // Per-person client accounts (client_admin / client_user) — email is the
  // username here. This is the only way clients sign in; the old shared
  // KFTL/KWL/PAJ logins have been retired.
  if (dbConnected && username && username.includes('@')) {
    try {
      const result = await pool.query('SELECT id,client_id,email,password_hash,role,status FROM users WHERE email=$1', [username.toLowerCase()]);
      const u = result.rows[0];
      if (u && u.status === 'active') {
        const match = await bcrypt.compare(password || '', u.password_hash);
        if (match) {
          const token = jwt.sign({ id: u.id, role: u.role }, process.env.JWT_SECRET, { expiresIn: '42d' });
          const clientName = await getClientNameById(u.client_id);
          await logActivity(u.client_id, u.email, 'Login', `${u.role === 'client_admin' ? 'Client admin' : 'Client user'} logged in`);
          return res.json({ token, user: { id: u.id, username: u.email, email: u.email, client_id: u.client_id, client_name: clientName, role: u.role, photo_url: null } });
        }
      }
    } catch (err) {
      console.error('Client account login lookup failed:', err.message);
    }
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

  // KNOWN LIMITATION: msToken (a live Microsoft Graph access token — mailbox
  // read/send included, see GRAPH_SCOPES) rides inside the CAMS JWT itself.
  // Anyone who gets hold of a leaked CAMS token doesn't just get CAMS access,
  // they get that staff member's mailbox too. Fixing this means moving the
  // Graph token to server-side storage keyed by user id (like graph_auth
  // already does for the shared mailbox) instead of embedding it — bigger
  // change than fits here, not done in this pass.
  const jwtToken = jwt.sign(
    { id: msId, username: username, email: email, client_id: null, role: role, msToken: msToken },
    process.env.JWT_SECRET,
    { expiresIn: '42d' }
  );

  await logActivity(1, username, 'Login', `Microsoft login — ${email} (${role})`);

  res.json({
    token: jwtToken,
    user: { id: msId, username: username, email: email, client_id: null, client_name: null, role: role, photo_url: photoUrl }
  });

  console.log(`✅ Microsoft login: ${username} (${email}) — Role: ${role}`);
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
    res.json(filterByZoneAccess(result.rows, req));
  } catch (err) {
    res.json([]);
  }
});

app.put('/api/cameras/:id', authMiddleware, blockAssetEdit, async (req, res) => {
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

app.put('/api/cameras/:id/comment', authMiddleware, blockAssetEdit, async (req, res) => {
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
    const clientIds = await validateImportClients(cameras, res);
    if (!clientIds) return;
    for (const [idx, cam] of cameras.entries()) {
      await pool.query(`INSERT INTO cameras (client_id,name,zone,status,comments,model,manufacturer,resolution,archiver,ip_address,mac_address,warranty,purchase_date,date_cleaned) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
        [clientIds[idx],cam.name||'',cam.zone||'',cam.status||'Working',cam.comments||'',cam.model||'',cam.manufacturer||'',cam.resolution||'',cam.archiver||'',cam.ip_address||'',cam.mac_address||'',cam.warranty||null,cam.purchase_date||null,cam.date_cleaned||null]);
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
    const clientIds = await validateImportClients(doors, res);
    if (!clientIds) return;
    for (const [idx, door] of doors.entries()) {
      await pool.query(`INSERT INTO doors (client_id,name,zone,status,tech,reader,lock_type,ip_address,controller_type,door_swing,access_type,anti_passback,install_date,warranty_expiry,comments) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`,
        [clientIds[idx], door.name||'', door.zone||door.site||'', door.status||'Online', door.tech||'', door.reader||'', door.lock_type||'', door.ip_address||'', door.controller_type||'', door.door_swing||'', door.access_type||'', door.anti_passback||'', door.install_date||null, door.warranty_expiry||null, door.comments||'']);
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
    const clientIds = await validateImportClients(servers, res);
    if (!clientIds) return;
    for (const [idx, srv] of servers.entries()) {
      await pool.query(`INSERT INTO servers (client_id,name,zone,status,make,model,capacity,used,health,apps,serial,purchase_date,warranty_expiry,comments) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
        [clientIds[idx],srv.name||srv.serial||'',srv.zone||srv.location||'',srv.status||'Online',srv.make||'',srv.model||'',srv.capacity||'',srv.used||'',srv.health||'',srv.apps||'',srv.serial||'',srv.purchase_date||null,srv.warranty_expiry||null,srv.comments||'']);
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
    const clientIds = await validateImportClients(switches, res);
    if (!clientIds) return;
    for (const [idx, sw] of switches.entries()) {
      await pool.query(`INSERT INTO switches (client_id,name,zone,status,model,firmware,ip_address,mac_address,purchase_date,warranty_expiry,comments) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
        [clientIds[idx],sw.name||'',sw.zone||sw.location||'',sw.status||'Online',sw.model||'',sw.firmware||'',sw.ip_address||'',sw.mac||'',sw.purchase_date||null,sw.warranty_expiry||null,sw.comments||'']);
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
    const clientIds = await validateImportClients(software, res);
    if (!clientIds) return;
    for (const [idx, sw] of software.entries()) {
      await pool.query(`INSERT INTO software (client_id, name, vendor, version, license_type, status, expiry_date, purchase_date, warranty_expiry, comments) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
        [clientIds[idx], sw.name||'', sw.vendor||'', sw.version||'', sw.license_type||'', sw.status||'Good', sw.expiry_date||null, sw.purchase_date||null, sw.warranty_expiry||null, sw.comments||'']);
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
    const clientIds = await validateImportClients(stations, res);
    if (!clientIds) return;
    for (const [idx, s] of stations.entries()) {
      await pool.query(`INSERT INTO stations (client_id,name,zone,status,make,model,apps,ip_address,install_date,purchase_date,warranty_expiry) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
        [clientIds[idx], s.name||'', s.zone||'', s.status||'Online', s.make||'', s.model||'', s.apps||'', s.ip_address||'', s.install_date||null, s.purchase_date||null, s.warranty_expiry||null]);
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
    const clientIds = await validateImportClients(monitors, res);
    if (!clientIds) return;
    for (const [idx, m] of monitors.entries()) {
      await pool.query(`INSERT INTO monitors (client_id,name,zone,status,make,model,size,install_date,purchase_date,warranty_expiry) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
        [clientIds[idx], m.name||'', m.zone||'', m.status||'Online', m.make||'', m.model||'', m.size||'', m.install_date||null, m.purchase_date||null, m.warranty_expiry||null]);
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
    const clientIds = await validateImportClients(points, res);
    if (!clientIds) return;
    for (const [idx, i] of points.entries()) {
      await pool.query(`INSERT INTO intrusion (client_id,name,zone,status,module,sensor_type,ip_address,purchase_date,warranty_expiry,comments) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
        [clientIds[idx], i.name||'', i.zone||'', i.status||'Online', i.module||'', i.sensor_type||'', i.ip_address||'', i.purchase_date||null, i.warranty_expiry||null, i.comments||'']);
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
    const clientIds = await validateImportClients(devices, res);
    if (!clientIds) return;
    for (const [idx, s] of devices.entries()) {
      await pool.query(`INSERT INTO storage (client_id,name,zone,status,type,make,model,capacity,used,serial,purchase_date,warranty_expiry,comments) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
        [clientIds[idx], s.name||'', s.zone||'', s.status||'Online', s.type||'', s.make||'', s.model||'', s.capacity||'', s.used||'', s.serial||'', s.purchase_date||null, s.warranty_expiry||null, s.comments||'']);
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
    res.json(filterByZoneAccess(result.rows, req));
  } catch (err) { res.json([]); }
});

app.put('/api/doors/:id', authMiddleware, blockAssetEdit, async (req, res) => {
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
    res.json(filterByZoneAccess(result.rows, req));
  } catch (err) { res.json([]); }
});

app.put('/api/servers/:id', authMiddleware, blockAssetEdit, async (req, res) => {
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
    res.json(filterByZoneAccess(result.rows, req));
  } catch (err) { res.json([]); }
});

app.put('/api/storage/:id', authMiddleware, blockAssetEdit, async (req, res) => {
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
    res.json(filterByZoneAccess(result.rows, req));
  } catch (err) { res.json([]); }
});

app.put('/api/switches/:id', authMiddleware, blockAssetEdit, async (req, res) => {
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
    res.json(filterByZoneAccess(result.rows, req));
  } catch (err) { res.json([]); }
});

app.put('/api/intrusion/:id', authMiddleware, blockAssetEdit, async (req, res) => {
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
// FIELD APP DEVICE UPDATES
// ============================================================
// Comments only. The full PUT /api/<type>/:id routes write every date
// column exactly as sent (so the dashboard's edit forms can clear them),
// which meant a comment-only PUT from the field app set warranty/purchase/
// install dates to NULL; this route touches nothing but `comments`. Device
// status is changed on the dashboard only, so a body with `status` is
// refused outright. Used only by the field app. E-Tech staff only (admin,
// technician).
const PATCHABLE_ASSETS = {
  cameras: { label: 'Camera', comments: true },
  doors: { label: 'Door', comments: true },
  servers: { label: 'Server', comments: true },
  storage: { label: 'Storage device', comments: true },
  switches: { label: 'Switch', comments: true },
  intrusion: { label: 'Intrusion point', comments: true },
  // stations and monitors have no comments column, so nothing to update
  stations: { label: 'Station', comments: false },
  monitors: { label: 'Monitor', comments: false },
};

app.patch('/api/assets/:type/:id', authMiddleware, async (req, res) => {
  if (req.user.role !== 'admin' && req.user.role !== 'technician') return res.status(403).json({ error: 'Not authorized' });
  const { type, id } = req.params;
  const spec = Object.prototype.hasOwnProperty.call(PATCHABLE_ASSETS, type) ? PATCHABLE_ASSETS[type] : null;
  if (!spec) return res.status(400).json({ error: 'type must be one of: ' + Object.keys(PATCHABLE_ASSETS).join(', ') });

  const body = req.body && typeof req.body === 'object' ? req.body : {};
  if (Object.prototype.hasOwnProperty.call(body, 'status')) return res.status(400).json({ error: "Device status can't be changed from the field app." });
  if (!spec.comments) return res.status(400).json({ error: `${spec.label}s don't have comments` });
  if (!Object.prototype.hasOwnProperty.call(body, 'comments')) return res.status(400).json({ error: 'Send comments' });
  const comments = body.comments;
  if (comments !== null && typeof comments !== 'string') return res.status(400).json({ error: 'comments must be a string' });
  if (!dbConnected) return res.status(503).json({ error: 'DB not connected' });
  if (!/^\d+$/.test(id) || Number(id) > 2147483647) return res.status(404).json({ error: 'Device not found' });

  try {
    const result = await pool.query(
      `UPDATE ${type} SET comments = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2 RETURNING *`,
      [comments, Number(id)]
    );
    const asset = result.rows[0];
    if (!asset) return res.status(404).json({ error: 'Device not found' });
    const assetClient = await getClientNameById(asset.client_id);
    await logActivity(asset.client_id || 1, req.user.username, 'Updated', `${spec.label} ${asset.name || id} comment updated (${assetClient})`);
    res.json({ success: true, data: asset });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ============================================================
// INSTALLATION (field app ↔ EEST)
// ============================================================
// The field app's Installation tab. Each route forwards to EEST's CAMS
// integration API (contract: "CAMS integration" in the EEST README) with the
// shared X-Integration-Key and the signed-in tech's email. The key stays on
// this server; the phone only ever talks to CAMS.
//
// Only E-Tech staff signed in with Microsoft can use it: their token carries
// their email. The shared admin/tech password logins have no email, and
// client accounts aren't staff, so both get 403.
const installPhotoUpload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 50 * 1024 * 1024, files: 1 } });

// EEST's origin. Tolerates a trailing slash or /api so either form of the URL works.
function eestOrigin() {
  return String(process.env.EEST_API_URL || '').trim().replace(/\/+$/, '').replace(/\/api$/, '');
}

function requireInstallationAccess(req, res, next) {
  if (isClientAccount(req) || !req.user.email) {
    return res.status(403).json({ error: 'Installation jobs are only available to E-Tech staff signed in with Microsoft.' });
  }
  if (!eestOrigin() || !process.env.CAMS_INTEGRATION_KEY) {
    return res.status(503).json({ error: "The EEST link isn't set up on the CAMS server yet (EEST_API_URL and CAMS_INTEGRATION_KEY). Ask an admin." });
  }
  next();
}

// Photo links come back relative to EEST's origin; the phone needs them absolute.
function withEestPhotoLinks(device) {
  if (device && Array.isArray(device.photos)) {
    device.photos = device.photos.map(p => (typeof p === 'string' && p.startsWith('/') ? eestOrigin() + p : p));
  }
  return device;
}

async function forwardToEest(req, res, method, eestPath, body) {
  const headers = { 'X-Integration-Key': process.env.CAMS_INTEGRATION_KEY, 'X-User-Email': req.user.email };
  if (body !== undefined && !(body instanceof FormData)) headers['Content-Type'] = 'application/json';
  let response;
  try {
    response = await fetch(eestOrigin() + '/api/integrations/cams' + eestPath, {
      method,
      headers,
      body: body === undefined || body instanceof FormData ? body : JSON.stringify(body),
      signal: AbortSignal.timeout(60000)
    });
  } catch (err) {
    console.error(`EEST ${method} ${eestPath} failed:`, err.message);
    return res.status(502).json({ error: "Couldn't reach EEST. Try again in a minute." });
  }
  let data;
  try { data = JSON.parse(await response.text()); } catch (e) { data = { error: `EEST returned an unexpected response (${response.status})` }; }
  // A 401 from EEST means CAMS's integration key is wrong — not the tech's
  // session. Passing 401 on would sign them out of the field app, so it goes
  // back as 502 with EEST's message instead. Every other status passes through.
  if (response.status === 401) {
    console.error('EEST rejected the integration key:', data && data.error);
    return res.status(502).json({ error: 'EEST refused the CAMS integration key (' + ((data && data.error) || 'unauthorized') + '). Ask an admin to check CAMS_INTEGRATION_KEY.' });
  }
  if (response.ok && data) {
    if (Array.isArray(data.projects)) {
      data.projects.forEach(p => (p.zones || []).forEach(z => (z.devices || []).forEach(withEestPhotoLinks)));
    } else {
      withEestPhotoLinks(data);
    }
  }
  res.status(response.status).json(data);
}

app.get('/api/installation/jobs', authMiddleware, requireInstallationAccess, (req, res) => {
  forwardToEest(req, res, 'GET', '/jobs');
});

app.patch('/api/installation/devices/:id', authMiddleware, requireInstallationAccess, (req, res) => {
  forwardToEest(req, res, 'PATCH', '/devices/' + encodeURIComponent(req.params.id), req.body || {});
});

app.post('/api/installation/devices/:id/photos', authMiddleware, requireInstallationAccess, (req, res) => {
  installPhotoUpload.single('file')(req, res, (err) => {
    if (err) {
      const tooBig = err.code === 'LIMIT_FILE_SIZE';
      return res.status(tooBig ? 413 : 400).json({ error: tooBig ? 'Photos can be up to 50 MB' : err.message });
    }
    const form = new FormData();
    if (req.file) form.append('file', new Blob([req.file.buffer], { type: req.file.mimetype }), req.file.originalname || 'photo.jpg');
    forwardToEest(req, res, 'POST', '/devices/' + encodeURIComponent(req.params.id) + '/photos', form);
  });
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

// Paged, filtered search for the dashboard's SR tab. The plain GET above is
// deliberately left alone — field-app.html and several dashboard widgets
// (urgent list, ticker, related SRs, export) rely on its full response.
const SR_STATUSES = ['Open', 'In Progress', 'On-Site Review', 'Pending', 'Resolved', 'Retracted'];
const SR_TIME_ZONE = 'America/Jamaica';
const SR_SEARCH_COLUMNS = ['sr_id', 'subject', 'client', 'site', 'category', 'assigned_to', 'notes', 'body'];
const SR_OPEN = `COALESCE(status, '') NOT IN ('Resolved', 'Retracted')`;
// Age: open SRs count up from creation, resolved SRs show time-to-resolve,
// and anything closed without a resolved_at (old rows, retractions) has none.
const SR_AGE = `CASE WHEN status = 'Resolved' THEN resolved_at - created_at WHEN status = 'Retracted' THEN NULL ELSE CURRENT_TIMESTAMP - created_at END`;
// The only expressions ?sort= can reach — never interpolate the raw value.
const SR_SORTS = {
  created_at: 'created_at',
  sr_id: 'sr_id',
  client: 'LOWER(client)',
  site: 'LOWER(site)',
  priority: `CASE WHEN priority ILIKE '%high%' THEN 3 WHEN priority ILIKE '%medium%' THEN 2 WHEN priority ILIKE '%low%' THEN 1 END`,
  status: `array_position(ARRAY['Open','In Progress','On-Site Review','Pending','Resolved','Retracted'], status)`,
  assigned_to: `LOWER(NULLIF(assigned_to, ''))`,
  age: SR_AGE,
};

function parseSrSearchDate(value) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) return null;
  const [y, m, d] = value.split('-').map(Number);
  const dt = new Date(Date.UTC(y, m - 1, d));
  return dt.getUTCFullYear() === y && dt.getUTCMonth() === m - 1 && dt.getUTCDate() === d ? value : null;
}

app.get('/api/service-requests/search', authMiddleware, async (req, res) => {
  if (!dbConnected) return res.status(503).json({ error: 'DB not connected' });
  const bad = message => res.status(400).json({ error: message });
  for (const key of Object.keys(req.query)) {
    if (typeof req.query[key] !== 'string') return bad(`Query parameter "${key}" may only be given once`);
  }
  const val = key => (req.query[key] || '').trim();
  const where = [];
  const params = [];
  const add = value => { params.push(value); return '$' + params.length; };

  // Client accounts are always pinned to their own client, whatever they ask
  // for. New SRs are now stored with the correct client_id, but older
  // staff-created SRs were filed with client_id=1 (or NULL) whatever client
  // they were for, so the SR's client name has to match as well — the same
  // check the dashboard used to apply in the browser.
  const isStaff = req.user.role === 'admin' || req.user.role === 'technician';
  if (!isStaff) {
    const p = add(req.user.client_id);
    where.push(`client_id = ${p}`, `LOWER(COALESCE(client, '')) = (SELECT LOWER(name) FROM clients WHERE id = ${p})`);
  } else if (val('client_id')) {
    const clientId = Number(val('client_id'));
    if (!/^\d+$/.test(val('client_id')) || clientId < 1 || clientId > 2147483647) return bad('client_id must be a positive integer');
    const p = add(clientId);
    where.push(`(LOWER(client) = (SELECT LOWER(name) FROM clients WHERE id = ${p}) OR (COALESCE(client, '') = '' AND client_id = ${p}))`);
  }

  if (val('q')) {
    const p = add('%' + val('q').replace(/[\\%_]/g, ch => '\\' + ch) + '%');
    where.push('(' + SR_SEARCH_COLUMNS.map(col => `${col} ILIKE ${p}`).join(' OR ') + ')');
  }
  if (val('status')) {
    if (!SR_STATUSES.includes(val('status'))) return bad('status must be one of: ' + SR_STATUSES.join(', '));
    where.push(`status = ${add(val('status'))}`);
  }
  for (const col of ['site', 'priority', 'category']) {
    if (val(col)) where.push(`${col} = ${add(val(col))}`);
  }
  if (val('assigned_to') === 'Unassigned') {
    where.push(`(assigned_to IS NULL OR assigned_to IN ('', 'Unassigned'))`);
  } else if (val('assigned_to')) {
    where.push(`assigned_to = ${add(val('assigned_to'))}`);
  }

  // from/to are whole days in Jamaica time, both inclusive.
  const dateField = val('date_field') || 'created';
  if (dateField !== 'created' && dateField !== 'resolved') return bad("date_field must be 'created' or 'resolved'");
  const from = val('from') ? parseSrSearchDate(val('from')) : '';
  const to = val('to') ? parseSrSearchDate(val('to')) : '';
  if (from === null) return bad('from must be a valid date in YYYY-MM-DD format');
  if (to === null) return bad('to must be a valid date in YYYY-MM-DD format');
  if (from && to && from > to) return bad('from must not be after to');
  const fromP = from ? add(from) : null;
  const toP = to ? add(to) : null;
  const inRange = col => [
    fromP && `${col} >= (${fromP}::date::timestamp AT TIME ZONE '${SR_TIME_ZONE}')`,
    toP && `${col} < ((${toP}::date + 1)::timestamp AT TIME ZONE '${SR_TIME_ZONE}')`,
  ].filter(Boolean);
  where.push(...inRange(dateField === 'resolved' ? 'resolved_at' : 'created_at'));

  const sort = val('sort') || 'created_at';
  if (!Object.prototype.hasOwnProperty.call(SR_SORTS, sort)) return bad('sort must be one of: ' + Object.keys(SR_SORTS).join(', '));
  const dir = (val('dir') || 'desc').toLowerCase();
  if (dir !== 'asc' && dir !== 'desc') return bad("dir must be 'asc' or 'desc'");
  const pageRaw = val('page') || '1';
  const pageSizeRaw = val('page_size') || '50';
  if (!/^\d+$/.test(pageRaw) || Number(pageRaw) < 1) return bad('page must be a positive integer');
  if (!/^\d+$/.test(pageSizeRaw) || Number(pageSizeRaw) < 1) return bad('page_size must be a positive integer');
  const page = Number(pageRaw);
  const pageSize = Math.min(Number(pageSizeRaw), 200);
  const offset = (page - 1) * pageSize;
  if (!Number.isSafeInteger(offset)) return bad('page is too large');

  const whereSql = where.length ? 'WHERE ' + where.join(' AND ') : '';
  const resolvedInRange = ["status = 'Resolved'", ...inRange('resolved_at')].join(' AND ');
  try {
    const summaryResult = await pool.query(
      `SELECT COUNT(*)::int AS total,
              COUNT(*) FILTER (WHERE ${SR_OPEN})::int AS open,
              COUNT(*) FILTER (WHERE ${SR_OPEN} AND priority = 'High')::int AS high_open,
              COUNT(*) FILTER (WHERE ${resolvedInRange})::int AS resolved_in_range,
              AVG(EXTRACT(EPOCH FROM (resolved_at - created_at)) / 86400) FILTER (WHERE status = 'Resolved' AND created_at IS NOT NULL AND resolved_at IS NOT NULL) AS avg_resolve_days
       FROM service_requests ${whereSql}`,
      params
    );
    const s = summaryResult.rows[0];
    const result = await pool.query(
      `SELECT * FROM service_requests ${whereSql}
       ORDER BY ${SR_SORTS[sort]} ${dir.toUpperCase()} NULLS LAST, created_at DESC NULLS LAST, id DESC
       LIMIT $${params.length + 1} OFFSET $${params.length + 2}`,
      [...params, pageSize, offset]
    );
    const rows = result.rows;
    const historyBySr = {};
    if (rows.length) {
      const history = await pool.query('SELECT * FROM sr_history WHERE sr_id = ANY($1) ORDER BY created_at', [rows.map(sr => sr.id)]);
      for (const h of history.rows) (historyBySr[h.sr_id] = historyBySr[h.sr_id] || []).push(h);
    }
    for (const sr of rows) {
      sr.history = historyBySr[sr.id] || [];
      if (sr.related_hardware && typeof sr.related_hardware === 'string') {
        try { sr.related_hardware = JSON.parse(sr.related_hardware); } catch (e) { sr.related_hardware = []; }
      }
      if (!sr.related_hardware) sr.related_hardware = [];
    }
    res.json({
      rows,
      total: s.total,
      page,
      page_size: pageSize,
      summary: {
        open: s.open,
        high_open: s.high_open,
        resolved_in_range: s.resolved_in_range,
        avg_resolve_days: s.avg_resolve_days == null ? null : Math.round(Number(s.avg_resolve_days) * 10) / 10,
      },
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/service-requests', authMiddleware, async (req, res) => {
  if (!dbConnected) return res.status(503).json({ error: 'DB not connected' });
  const { subject, site, category, priority, assigned_to, body, related_hardware } = req.body;
  const srId = `SR-${String(Math.floor(Math.random() * 9000) + 1000)}`;
  try {
    // File the SR under a real client, with client_id and the client name
    // always agreeing. Client accounts get their own client whatever the body
    // says; staff pick one on the form (client_id if valid, else its name).
    let clientRow;
    if (isClientAccount(req)) {
      clientRow = (await pool.query('SELECT id, name FROM clients WHERE id = $1', [req.user.client_id])).rows[0];
    } else {
      const bodyClientId = Number(req.body.client_id);
      if (Number.isInteger(bodyClientId) && bodyClientId > 0 && bodyClientId <= 2147483647) {
        clientRow = (await pool.query('SELECT id, name FROM clients WHERE id = $1', [bodyClientId])).rows[0];
      }
      const clientName = typeof req.body.client === 'string' ? req.body.client.trim() : '';
      if (!clientRow && clientName) {
        clientRow = (await pool.query('SELECT id, name FROM clients WHERE LOWER(name) = LOWER($1) ORDER BY id LIMIT 1', [clientName])).rows[0];
      }
    }
    if (!clientRow) return res.status(400).json({ error: 'Select a valid client for this service request.' });
    const clientId = clientRow.id;
    const client = clientRow.name;
    const result = await pool.query(
      `INSERT INTO service_requests (client_id,sr_id,subject,client,site,category,priority,assigned_to,body,received,created_by,related_hardware) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,CURRENT_DATE,$10,$11) RETURNING *`,
      [clientId, srId, subject, client, site, category, priority, assigned_to, body, req.user.username, JSON.stringify(related_hardware || [])]
    );
    await pool.query('INSERT INTO sr_history (sr_id,time,msg) VALUES ($1,$2,$3)', [result.rows[0].id, new Date().toLocaleTimeString(), 'Created by ' + req.user.username]);
    await logActivity(clientId, req.user.username, 'Created', 'SR ' + srId + ' created for ' + client);
    
    // Shared-mailbox token, not req.user.msToken (which expires after ~1h).
    const msToken = await getValidGraphToken();
    if (!msToken) console.error('Cannot send new-SR email — no Graph token available for the shared mailbox');
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

// "22 Oct 2026 2:14 PM" in Jamaica time, for stamped SR note lines.
const SR_NOTE_MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
function srNoteStamp(date) {
  const p = {};
  new Intl.DateTimeFormat('en-US', { timeZone: 'America/Jamaica', day: 'numeric', month: 'numeric', year: 'numeric', hour: 'numeric', minute: '2-digit', hour12: true })
    .formatToParts(date).forEach(x => { p[x.type] = x.value; });
  return `${p.day} ${SR_NOTE_MONTHS[p.month - 1]} ${p.year} ${p.hour}:${p.minute} ${(p.dayPeriod || '').toUpperCase()}`;
}

app.put('/api/service-requests/:id', authMiddleware, async (req, res) => {
  if (!dbConnected) return res.status(503).json({ error: 'DB not connected' });
  const { id } = req.params;
  const { priority, assigned_to, status } = req.body;
  let { notes } = req.body;
  const clientId = req.user.role === 'admin' ? null : req.user.client_id;
  try {
    const current = await pool.query('SELECT * FROM service_requests WHERE id=$1', [id]);
    const oldSr = current.rows[0];
    const oldAssigned = oldSr?.assigned_to;
    const oldStatus = oldSr?.status;
    // append_note (field app) adds one stamped line to the existing notes
    // instead of replacing them. A full `notes` value sent in the same
    // request wins and append_note is ignored.
    let noteAdded = false;
    const appendNote = typeof req.body.append_note === 'string' ? req.body.append_note.trim() : '';
    if (notes === undefined && appendNote && oldSr) {
      const line = `[${srNoteStamp(new Date())} · ${req.user.username}] ${appendNote}`;
      notes = oldSr.notes ? `${oldSr.notes}\n${line}` : line;
      noteAdded = true;
    }
    // COALESCE so a partial update (e.g. the field app's "Resolve" button,
    // which only sends {status:'Resolved'}) doesn't wipe out the other
    // fields — this route previously overwrote priority/assigned_to/notes
    // with NULL whenever they weren't included in the request body.
    const query = clientId ? `UPDATE service_requests SET priority=COALESCE($1,priority),assigned_to=COALESCE($2,assigned_to),status=COALESCE($3,status),notes=COALESCE($4,notes),updated_at=CURRENT_TIMESTAMP WHERE id=$5 AND client_id=$6` : `UPDATE service_requests SET priority=COALESCE($1,priority),assigned_to=COALESCE($2,assigned_to),status=COALESCE($3,status),notes=COALESCE($4,notes),updated_at=CURRENT_TIMESTAMP WHERE id=$5`;
    const params = clientId ? [priority,assigned_to,status,notes,id,clientId] : [priority,assigned_to,status,notes,id];
    const updateResult = await pool.query(query, params);
    
    // Track resolution time (resolved_at)
    if (status === 'Resolved' && oldStatus !== 'Resolved') {
      await pool.query('UPDATE service_requests SET resolved_at = CURRENT_TIMESTAMP WHERE id = $1', [id]);
    }
    
    if (assigned_to && assigned_to !== oldAssigned) {
      await pool.query('INSERT INTO sr_history (sr_id,time,msg) VALUES ($1,$2,$3)', [id, new Date().toLocaleTimeString(), `Transferred from ${oldAssigned||'Unassigned'} to ${assigned_to} by ${req.user.username}`]);
      
      const msToken = await getValidGraphToken();
      if (!msToken) console.error('Cannot send assigned email — no Graph token available for the shared mailbox');
      if (msToken && assigned_to !== 'Unassigned' && TECH_EMAILS[assigned_to]) {
        const techEmailBody = `<h2>You've been assigned a Service Request</h2><p><strong>SR ID:</strong> ${oldSr.sr_id}</p><p><strong>Subject:</strong> ${oldSr.subject}</p><p><strong>Client:</strong> ${oldSr.client}</p><p><strong>Site:</strong> ${oldSr.site}</p><p><strong>Priority:</strong> ${priority || oldSr.priority}</p><hr><p>View in CAMS: <a href="${process.env.APP_URL || "https://e-tech-cams.up.railway.app"}">Open Dashboard</a></p>`;
        await sendEmailNotification(TECH_EMAILS[assigned_to], `[CAMS] Assigned: ${oldSr.sr_id} — ${oldSr.subject}`, techEmailBody, `Bearer ${msToken}`);
      }
    }
    
    // One timeline entry per field that actually changed (an assignee change
    // already got its transfer entry above), and none for a no-op save. A
    // field left out of the body keeps its old value via the COALESCE above,
    // so it isn't a change.
    if (oldSr && updateResult.rowCount > 0) {
      const by = req.user.username;
      const after = (value, before) => (value === undefined || value === null ? before : value);
      const changes = [];
      const newStatus = after(status, oldSr.status);
      const newPriority = after(priority, oldSr.priority);
      if (newStatus !== oldSr.status) changes.push(`Status: ${oldSr.status || '—'} → ${newStatus} by ${by}`);
      if (newPriority !== oldSr.priority) changes.push(`Priority: ${oldSr.priority || '—'} → ${newPriority} by ${by}`);
      if ((after(notes, oldSr.notes) || '') !== (oldSr.notes || '')) changes.push(noteAdded ? `Note added by ${by}` : `Notes updated by ${by}`);
      for (const msg of changes) {
        await pool.query('INSERT INTO sr_history (sr_id,time,msg) VALUES ($1,$2,$3)', [id, new Date().toLocaleTimeString(), msg]);
      }
    }
    const logClientId = clientId || 1;
    await logActivity(logClientId, req.user.username, 'Updated', 'SR ' + id + (status ? ' updated to ' + status : noteAdded ? ' note added' : ' updated'));
    
    if (status === 'Resolved' && oldStatus !== 'Resolved') {
      const updated = await pool.query('SELECT * FROM service_requests WHERE id=$1', [id]);
      const sr = updated.rows[0];
      const history = await pool.query('SELECT * FROM sr_history WHERE sr_id=$1 ORDER BY created_at', [id]);
      // Uses the self-refreshing shared-mailbox token (same as
      // runMonthlyReports()) instead of req.user.msToken — the old
      // approach silently skipped this email whenever the person who
      // resolved the ticket didn't happen to have a live Microsoft session
      // at that exact moment, the same failure mode that used to make the
      // monthly reports go silently missing.
      const graphToken = await getValidGraphToken();
      if (graphToken) {
        const authHeader = `Bearer ${graphToken}`;
        const resolvedSubject = `[CAMS] RESOLVED: ${sr.sr_id} — ${sr.subject}`;
        const reportBody = `<h2>Service Request Resolved: ${sr.sr_id}</h2><p><strong>Client:</strong> ${sr.client}</p><p><strong>Site:</strong> ${sr.site}</p><p><strong>Category:</strong> ${sr.category}</p><p><strong>Priority:</strong> ${sr.priority}</p><p><strong>Subject:</strong> ${sr.subject}</p><p><strong>Created By:</strong> ${sr.created_by}</p><p><strong>Resolved By:</strong> ${req.user.username}</p><p><strong>Resolution Notes:</strong> ${notes||'No notes'}</p><hr><h3>Timeline</h3><ul>${history.rows.map(h=>`<li>${h.time} — ${h.msg}</li>`).join('')}</ul><hr><p>View in CAMS: <a href="${process.env.APP_URL || "https://e-tech-cams.up.railway.app"}">Open Dashboard</a></p>`;
        await sendEmailNotification('support@e-techsystemsja.com', resolvedSubject, reportBody, authHeader);

        // Also notify the SR's client's own registered users (the new
        // per-person client accounts), one email per recipient rather than
        // one email with everyone in To/CC. Most clients have no registered
        // users yet (still on the shared KFTL/KWL/PAJ-style logins), so
        // this is expected to no-op for now — that's fine, the support@
        // email above always goes out regardless.
        let clientUsersNotified = 0;
        if (sr.client_id) {
          try {
            const clientUsers = await pool.query("SELECT email FROM users WHERE client_id=$1 AND status='active'", [sr.client_id]);
            for (const u of clientUsers.rows) {
              const sent = await sendEmailNotification(u.email, resolvedSubject, reportBody, authHeader);
              if (sent) clientUsersNotified++;
            }
          } catch (notifyErr) {
            console.error('Could not notify client users of SR resolution:', notifyErr.message);
          }
        }
        await logActivity(logClientId, req.user.username, 'Notified', `SR ${sr.sr_id} resolution emailed to support@e-techsystemsja.com` + (clientUsersNotified > 0 ? ` and ${clientUsersNotified} registered client user${clientUsersNotified === 1 ? '' : 's'}` : ' (no registered client users to notify)'));
      } else {
        console.error('Cannot send SR-resolved email — no Graph token available for the shared mailbox');
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
    
    const msToken = await getValidGraphToken();
    if (!msToken) console.error('Cannot send assigned email — no Graph token available for the shared mailbox');
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
// CLIENT TICKER
// ============================================================
// Live, client-specific lines for the scrolling ticker on a client's
// dashboard: what needs attention now, then recent progress. Client
// accounts only — staff never see it.

// [table, readable type word, dashboard tab the device lives on]
const TICKER_ASSET_TABLES = [
  ['cameras', 'camera', 'cameras'],
  ['doors', 'door', 'doors'],
  ['servers', 'server', 'compute'],
  ['storage', 'storage', 'compute'],
  ['switches', 'switch', 'networking'],
  ['intrusion', 'intrusion point', 'intrusion'],
  ['stations', 'workstation', 'controlcenter'],
  ['monitors', 'monitor', 'controlcenter'],
];
const TICKER_TIME_ZONE = 'America/Jamaica';
// Shown only when there is nothing live to say — never mixed with live items.
const TICKER_FALLBACK_LINES = ['24 Hour Support from E-Tech Systems', 'Send us a service request', 'Update asset statuses', 'Visit us at e-techsystemsja.com'];

function tickerJamaicaYMD(date) {
  return new Intl.DateTimeFormat('en-CA', { timeZone: TICKER_TIME_ZONE, year: 'numeric', month: '2-digit', day: '2-digit' }).format(date);
}

// "today", "yesterday", a weekday name within the week, else "15 Oct".
function tickerRelativeDay(date, now) {
  const days = Math.round((Date.parse(tickerJamaicaYMD(now)) - Date.parse(tickerJamaicaYMD(date))) / 86400000);
  if (days <= 0) return 'today';
  if (days === 1) return 'yesterday';
  if (days < 7) return new Intl.DateTimeFormat('en-US', { timeZone: TICKER_TIME_ZONE, weekday: 'long' }).format(date);
  return new Intl.DateTimeFormat('en-GB', { timeZone: TICKER_TIME_ZONE, day: 'numeric', month: 'short' }).format(date);
}

const tickerPlural = (n, word, many) => `${n} ${n === 1 ? word : (many || word + 's')}`;

app.get('/api/ticker', authMiddleware, async (req, res) => {
  if (!isClientAccount(req)) return res.status(403).json({ error: 'Not authorized' });
  if (!dbConnected) return res.status(503).json({ error: 'DB not connected' });
  const clientId = req.user.client_id;
  // Same SR scope as the SR list: their client_id, and the SR's client name
  // must be theirs too. New SRs are now stored with the correct client_id;
  // the name check protects older staff-created SRs filed with client_id=1.
  const srScope = `client_id = $1 AND LOWER(COALESCE(client, '')) = (SELECT LOWER(name) FROM clients WHERE id = $1)`;
  const open = `COALESCE(status, '') NOT IN ('Resolved', 'Retracted')`;
  const high = `priority ILIKE '%high%'`;
  try {
    const [assets, openCounts, openTop, recent, month] = await Promise.all([
      pool.query(
        TICKER_ASSET_TABLES.map(([table, type, tab], i) =>
          `SELECT name, zone, status, '${type}' AS type, '${tab}' AS tab, ${i} AS ord FROM ${table} WHERE client_id = $1`
        ).join(' UNION ALL ') + ' ORDER BY ord, zone, name',
        [clientId]
      ),
      pool.query(`SELECT COUNT(*)::int AS open, COUNT(*) FILTER (WHERE ${high})::int AS high FROM service_requests WHERE ${srScope} AND ${open}`, [clientId]),
      pool.query(
        `SELECT sr_id, subject, status, assigned_to FROM service_requests WHERE ${srScope} AND ${open}
         ORDER BY (${high}) DESC, created_at DESC NULLS LAST, id DESC LIMIT 3`,
        [clientId]
      ),
      pool.query(
        `SELECT sr_id, subject, assigned_to, resolved_at FROM service_requests
         WHERE ${srScope} AND status = 'Resolved' AND resolved_at >= CURRENT_TIMESTAMP - INTERVAL '7 days'
         ORDER BY resolved_at DESC LIMIT 3`,
        [clientId]
      ),
      pool.query(
        `SELECT COUNT(*)::int AS closed,
                AVG(EXTRACT(EPOCH FROM (resolved_at - created_at))) FILTER (WHERE created_at IS NOT NULL) AS avg_seconds
         FROM service_requests
         WHERE ${srScope} AND status = 'Resolved'
           AND resolved_at >= (date_trunc('month', CURRENT_TIMESTAMP AT TIME ZONE '${TICKER_TIME_ZONE}') AT TIME ZONE '${TICKER_TIME_ZONE}')`,
        [clientId]
      ),
    ]);

    const items = [];
    const now = new Date();

    // 1. All-clear when every device is up (offline devices are not listed).
    const devices = filterByZoneAccess(assets.rows, req);
    const isOnline = d => ['online', 'working'].includes(String(d.status || '').trim().toLowerCase());
    if (devices.length && devices.every(isOnline)) {
      const sites = new Set(devices.map(d => (d.zone || '').trim()).filter(Boolean)).size;
      items.push({ kind: 'all_clear', text: `All ${tickerPlural(devices.length, 'device')} online` + (sites ? ` across ${tickerPlural(sites, 'site')}` : ''), priority: 'info' });
    }

    // 3. Open requests.
    const { open: openCount, high: highCount } = openCounts.rows[0];
    if (openCount) {
      items.push({ kind: 'open_requests', text: tickerPlural(openCount, 'open request') + (highCount ? ` · ${highCount} high priority` : ''), priority: highCount ? 'high' : 'normal' });
    }

    // 4. Who's handling what.
    for (const sr of openTop.rows) {
      const who = sr.assigned_to && sr.assigned_to !== 'Unassigned' ? `${sr.assigned_to} assigned` : 'awaiting assignment';
      items.push({ kind: 'assignment', text: `${sr.sr_id} ${sr.subject || ''}`.trim() + ` — ${sr.status || 'Open'}, ${who}`, priority: 'normal', link: { type: 'sr', sr_id: sr.sr_id } });
    }

    // 5. Recently resolved.
    for (const sr of recent.rows) {
      const by = sr.assigned_to && sr.assigned_to !== 'Unassigned' ? ` (${sr.assigned_to})` : '';
      items.push({ kind: 'resolved', text: `Resolved ${tickerRelativeDay(new Date(sr.resolved_at), now)}: ${sr.sr_id} ${sr.subject || ''}`.trim() + by, priority: 'info', link: { type: 'sr', sr_id: sr.sr_id } });
    }

    // 6. This month's response record.
    const { closed, avg_seconds } = month.rows[0];
    if (closed) {
      let avg = '';
      if (avg_seconds != null) {
        const hours = Number(avg_seconds) / 3600;
        avg = hours < 1 ? 'under an hour' : hours < 24 ? tickerPlural(Math.round(hours), 'hour') : `${(hours / 24).toFixed(1)} days`;
        avg = `Average resolution this month: ${avg} · `;
      }
      items.push({ kind: 'response_time', text: avg + tickerPlural(closed, 'request') + ' closed' + (avg ? '' : ' this month'), priority: 'info' });
    }

    if (!items.length) {
      for (const text of TICKER_FALLBACK_LINES) items.push({ kind: 'fallback', text, priority: 'info' });
    }
    res.json({ items, generated_at: now.toISOString() });
  } catch (err) { res.status(500).json({ error: err.message }); }
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
    const result = await pool.query('SELECT id,name,email,phone,address,logo_url,logo_full_url FROM clients');
    res.json(result.rows);
  } catch (err) { res.json([]); }
});

// The signed-in client's own name and logos, for their top bar and avatar.
app.get('/api/my-client', authMiddleware, async (req, res) => {
  if (!isClientAccount(req)) return res.status(403).json({ error: 'Client accounts only' });
  if (!dbConnected) return res.status(503).json({ error: 'DB not connected' });
  try {
    const result = await pool.query('SELECT id,name,logo_url,logo_full_url FROM clients WHERE id=$1', [req.user.client_id]);
    if (!result.rows[0]) return res.status(404).json({ error: 'Client not found' });
    res.json(result.rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Client logos are PNG data URLs made by the dashboard's logo processing.
const CLIENT_LOGO_MAX_BYTES = 400 * 1024;
const LOGO_FIELDS = ['logo_url', 'logo_full_url'];
// Returns an error message, or null when every logo field present is
// empty/null or a PNG data URL of at most 400 KB.
function invalidClientLogo(body) {
  for (const key of LOGO_FIELDS) {
    const v = body[key];
    if (v == null || v === '') continue;
    const m = typeof v === 'string' && v.match(/^data:image\/png;base64,([A-Za-z0-9+/]+={0,2})$/);
    if (!m) return `${key} must be a PNG image (data:image/png;base64,…).`;
    const bytes = Math.floor(m[1].length * 3 / 4) - (m[1].endsWith('==') ? 2 : m[1].endsWith('=') ? 1 : 0);
    if (bytes > CLIENT_LOGO_MAX_BYTES) return `${key} is too large — logos must be at most 400 KB.`;
  }
  return null;
}

app.post('/api/clients', authMiddleware, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  if (!dbConnected) return res.status(503).json({ error: 'DB not connected' });
  const { name, email, phone, address } = req.body;
  const badLogo = invalidClientLogo(req.body);
  if (badLogo) return res.status(400).json({ error: badLogo });
  try {
    const result = await pool.query('INSERT INTO clients (name,email,phone,address,logo_url,logo_full_url) VALUES ($1,$2,$3,$4,$5,$6) RETURNING *', [name,email,phone,address,req.body.logo_url||null,req.body.logo_full_url||null]);
    await logActivity(1, req.user.username, 'Created', 'Client ' + name + ' added');
    res.json(result.rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/clients/:name', authMiddleware, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  if (!dbConnected) return res.status(503).json({ error: 'DB not connected' });
  const { name } = req.params;
  const { email, phone, address } = req.body;
  const badLogo = invalidClientLogo(req.body);
  if (badLogo) return res.status(400).json({ error: badLogo });
  // A logo only changes when its key is in the body, so a normal edit
  // never wipes the logos.
  const sets = ['email=$1', 'phone=$2', 'address=$3'], params = [email||'', phone||'', address||''];
  for (const key of LOGO_FIELDS) {
    if (Object.prototype.hasOwnProperty.call(req.body, key)) { params.push(req.body[key] || null); sets.push(`${key}=$${params.length}`); }
  }
  params.push(name);
  try {
    const result = await pool.query(`UPDATE clients SET ${sets.join(',')},updated_at=CURRENT_TIMESTAMP WHERE name=$${params.length} RETURNING *`, params);
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
// CLIENT USER ACCOUNTS (per-person client logins)
// ============================================================
// Two roles: client_admin ("main user", sees their whole client, manages
// their own client's sub-users via My Team) and client_user ("sub-user",
// scoped to whichever zones their client_admin assigned them). Both are
// read-only for asset data (see blockAssetEdit above). Requires
// migrations/001_client_user_accounts.sql to have been run against the
// database — the routes below will error until then.

const INVITE_EXPIRY_DAYS = 7;

function generateInviteToken() {
  const token = crypto.randomBytes(32).toString('hex');
  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
  return { token, tokenHash };
}

async function sendInviteEmail(email, token, clientName, role) {
  const appUrl = process.env.APP_URL || 'https://e-tech-cams.up.railway.app';
  const acceptLink = `${appUrl}/accept-invite.html?token=${token}`;
  const roleLabel = role === 'client_admin' ? 'main user' : 'team member';
  const body = `<h2>You've been invited to CAMS</h2><p>You've been added as a ${roleLabel} for <strong>${clientName}</strong> on E-Tech's Client Asset Management System.</p><p><a href="${acceptLink}">Click here to set your password and activate your account</a></p><p>This link expires in ${INVITE_EXPIRY_DAYS} days.</p><hr><p style="color:#888;font-size:12px;">If you weren't expecting this invite, you can ignore this email.</p>`;
  const graphToken = await getValidGraphToken();
  if (!graphToken) {
    console.error('Cannot send invite email — no Graph token available for the shared mailbox');
    return false;
  }
  return sendEmailNotification(email, `[CAMS] You're invited — ${clientName}`, body, `Bearer ${graphToken}`);
}

// ---- Zones ----
// A real table purely to drive per-zone permissions — it does not replace
// the free-text `zone` field already on every asset row. Membership is
// matched by name against that field, not a foreign key.

app.get('/api/zones', authMiddleware, async (req, res) => {
  if (!dbConnected) return res.json([]);
  const clientId = req.user.role === 'admin' ? req.query.client_id : req.user.client_id;
  if (!clientId) return res.status(400).json({ error: 'client_id required' });
  try {
    const result = await pool.query('SELECT id,name FROM zones WHERE client_id=$1 ORDER BY name', [clientId]);
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Suggests zone names already in use across a client's assets, so a
// client_admin (or E-Tech admin) populating the zones table for the first
// time doesn't have to retype names by hand.
app.get('/api/zones/discover', authMiddleware, async (req, res) => {
  if (!dbConnected) return res.json([]);
  const clientId = req.user.role === 'admin' ? req.query.client_id : req.user.client_id;
  if (!clientId) return res.status(400).json({ error: 'client_id required' });
  try {
    const tables = ['cameras', 'doors', 'servers', 'switches', 'storage', 'intrusion', 'stations', 'monitors'];
    const unionQuery = tables.map(t => `SELECT DISTINCT zone FROM ${t} WHERE client_id=$1 AND zone IS NOT NULL AND zone <> ''`).join(' UNION ');
    const result = await pool.query(unionQuery, [clientId]);
    res.json(result.rows.map(r => r.zone).sort());
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/zones', authMiddleware, async (req, res) => {
  if (!dbConnected) return res.status(503).json({ error: 'DB not connected' });
  if (req.user.role !== 'admin' && req.user.role !== 'client_admin') return res.status(403).json({ error: 'Not authorized' });
  const clientId = req.user.role === 'admin' ? req.body.client_id : req.user.client_id;
  const { name } = req.body;
  if (!clientId || !name) return res.status(400).json({ error: 'client_id and name required' });
  try {
    const result = await pool.query('INSERT INTO zones (client_id,name) VALUES ($1,$2) ON CONFLICT (client_id,name) DO NOTHING RETURNING *', [clientId, name]);
    res.json(result.rows[0] || { client_id: clientId, name });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/zones/:id', authMiddleware, async (req, res) => {
  if (!dbConnected) return res.status(503).json({ error: 'DB not connected' });
  if (req.user.role !== 'admin' && req.user.role !== 'client_admin') return res.status(403).json({ error: 'Not authorized' });
  try {
    const zone = await pool.query('SELECT client_id FROM zones WHERE id=$1', [req.params.id]);
    if (!zone.rows[0]) return res.status(404).json({ error: 'Zone not found' });
    if (req.user.role === 'client_admin' && zone.rows[0].client_id !== req.user.client_id) return res.status(403).json({ error: 'Not authorized' });
    await pool.query('DELETE FROM zones WHERE id=$1', [req.params.id]);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ---- Invite accept flow (public — the invite token itself is the credential) ----

app.get('/api/auth/invite/:token', inviteRateLimit, async (req, res) => {
  if (!dbConnected) return res.status(503).json({ error: 'DB not connected' });
  const tokenHash = crypto.createHash('sha256').update(req.params.token).digest('hex');
  try {
    const result = await pool.query(
      `SELECT i.email, i.role, i.expires_at, i.used_at, c.name AS client_name
       FROM invites i JOIN clients c ON c.id = i.client_id WHERE i.token_hash=$1`,
      [tokenHash]
    );
    const invite = result.rows[0];
    if (!invite) return res.status(404).json({ error: 'Invite not found' });
    if (invite.used_at) return res.status(410).json({ error: 'This invite has already been used' });
    if (new Date(invite.expires_at) < new Date()) return res.status(410).json({ error: 'This invite has expired' });
    res.json({ email: invite.email, role: invite.role, client_name: invite.client_name });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/auth/invite/:token/accept', inviteRateLimit, async (req, res) => {
  if (!dbConnected) return res.status(503).json({ error: 'DB not connected' });
  const { password } = req.body;
  if (!password || password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });
  const tokenHash = crypto.createHash('sha256').update(req.params.token).digest('hex');
  try {
    const result = await pool.query('SELECT * FROM invites WHERE token_hash=$1', [tokenHash]);
    const invite = result.rows[0];
    if (!invite) return res.status(404).json({ error: 'Invite not found' });
    if (invite.used_at) return res.status(410).json({ error: 'This invite has already been used' });
    if (new Date(invite.expires_at) < new Date()) return res.status(410).json({ error: 'This invite has expired' });

    const passwordHash = await bcrypt.hash(password, 12);
    const existing = await pool.query('SELECT id FROM users WHERE email=$1', [invite.email]);
    let userId;
    if (existing.rows[0]) {
      userId = existing.rows[0].id;
      await pool.query('UPDATE users SET password_hash=$1,status=$2,role=$3,client_id=$4 WHERE id=$5', [passwordHash, 'active', invite.role, invite.client_id, userId]);
    } else {
      const inserted = await pool.query(
        'INSERT INTO users (client_id,email,password_hash,role,invited_by,status) VALUES ($1,$2,$3,$4,$5,$6) RETURNING id',
        [invite.client_id, invite.email, passwordHash, invite.role, invite.invited_by, 'active']
      );
      userId = inserted.rows[0].id;
    }
    if (invite.role === 'client_user' && invite.zone_ids && invite.zone_ids.length) {
      for (const zoneId of invite.zone_ids) {
        await pool.query('INSERT INTO user_zone_access (user_id,zone_id) VALUES ($1,$2) ON CONFLICT DO NOTHING', [userId, zoneId]);
      }
    }
    await pool.query('UPDATE invites SET used_at=CURRENT_TIMESTAMP WHERE id=$1', [invite.id]);
    await logActivity(invite.client_id, invite.email, 'Account activated', `${invite.role === 'client_admin' ? 'Client admin' : 'Client user'} account activated from invite`);

    const token = jwt.sign({ id: userId, role: invite.role }, process.env.JWT_SECRET, { expiresIn: '42d' });
    const clientName = await getClientNameById(invite.client_id);
    res.json({ token, user: { id: userId, username: invite.email, email: invite.email, client_id: invite.client_id, client_name: clientName, role: invite.role, photo_url: null } });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ---- E-Tech admin "Users" panel — cross-client ----

app.get('/api/users', authMiddleware, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  if (!dbConnected) return res.json([]);
  try {
    const users = await pool.query(
      `SELECT u.id,u.email,u.role,u.status,u.created_at,u.client_id,c.name AS client_name,
              COALESCE(array_agg(z.name) FILTER (WHERE z.name IS NOT NULL), '{}') AS zones
       FROM users u
       JOIN clients c ON c.id = u.client_id
       LEFT JOIN user_zone_access uza ON uza.user_id = u.id
       LEFT JOIN zones z ON z.id = uza.zone_id
       GROUP BY u.id, c.name ORDER BY c.name, u.email`
    );
    const invites = await pool.query(
      `SELECT i.id,i.email,i.role,i.client_id,c.name AS client_name,i.expires_at,i.created_at
       FROM invites i JOIN clients c ON c.id = i.client_id WHERE i.used_at IS NULL AND i.expires_at > CURRENT_TIMESTAMP ORDER BY c.name, i.email`
    );
    res.json({ users: users.rows, invites: invites.rows });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/users/invite', authMiddleware, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  if (!dbConnected) return res.status(503).json({ error: 'DB not connected' });
  const { email, client_id, role } = req.body;
  if (!email || !client_id || !['client_admin', 'client_user'].includes(role)) {
    return res.status(400).json({ error: 'email, client_id, and role (client_admin|client_user) required' });
  }
  try {
    const client = await pool.query('SELECT name FROM clients WHERE id=$1', [client_id]);
    if (!client.rows[0]) return res.status(404).json({ error: 'Client not found' });
    const { token, tokenHash } = generateInviteToken();
    const expiresAt = new Date(Date.now() + INVITE_EXPIRY_DAYS * 24 * 60 * 60 * 1000);
    await pool.query(
      'INSERT INTO invites (email,client_id,role,invited_by,token_hash,expires_at) VALUES ($1,$2,$3,$4,$5,$6)',
      [email.toLowerCase(), client_id, role, req.user.username, tokenHash, expiresAt]
    );
    await sendInviteEmail(email, token, client.rows[0].name, role);
    await logActivity(client_id, req.user.username, 'Invited', `Invited ${email} as ${role} for ${client.rows[0].name}`);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/users/:id/status', authMiddleware, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  if (!dbConnected) return res.status(503).json({ error: 'DB not connected' });
  const { status } = req.body;
  if (!['active', 'disabled'].includes(status)) return res.status(400).json({ error: 'status must be active or disabled' });
  try {
    const result = await pool.query('UPDATE users SET status=$1 WHERE id=$2 RETURNING email,client_id', [status, req.params.id]);
    if (!result.rows[0]) return res.status(404).json({ error: 'User not found' });
    await logActivity(result.rows[0].client_id, req.user.username, 'Updated', `${result.rows[0].email} ${status === 'disabled' ? 'disabled' : 're-enabled'}`);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/users/:id', authMiddleware, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  if (!dbConnected) return res.status(503).json({ error: 'DB not connected' });
  try {
    const result = await pool.query('DELETE FROM users WHERE id=$1 RETURNING email,client_id', [req.params.id]);
    if (!result.rows[0]) return res.status(404).json({ error: 'User not found' });
    await logActivity(result.rows[0].client_id, req.user.username, 'Deleted', `Removed user ${result.rows[0].email}`);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/invites/:id', authMiddleware, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  if (!dbConnected) return res.status(503).json({ error: 'DB not connected' });
  try {
    const result = await pool.query('DELETE FROM invites WHERE id=$1 AND used_at IS NULL RETURNING email,client_id', [req.params.id]);
    if (!result.rows[0]) return res.status(404).json({ error: 'Invite not found' });
    await logActivity(result.rows[0].client_id, req.user.username, 'Deleted', `Revoked invite for ${result.rows[0].email}`);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ---- Client-side "My Team" panel — client_admin manages their own client's sub-users ----

app.get('/api/my-team', authMiddleware, async (req, res) => {
  if (req.user.role !== 'client_admin') return res.status(403).json({ error: 'Client admin only' });
  if (!dbConnected) return res.json({ users: [], invites: [] });
  try {
    const users = await pool.query(
      `SELECT u.id,u.email,u.role,u.status,u.created_at,
              COALESCE(array_agg(z.name) FILTER (WHERE z.name IS NOT NULL), '{}') AS zones
       FROM users u
       LEFT JOIN user_zone_access uza ON uza.user_id = u.id
       LEFT JOIN zones z ON z.id = uza.zone_id
       WHERE u.client_id=$1 GROUP BY u.id ORDER BY u.email`,
      [req.user.client_id]
    );
    const invites = await pool.query(
      `SELECT i.id,i.email,i.role,i.expires_at,i.created_at,
              COALESCE(array_agg(z.name) FILTER (WHERE z.name IS NOT NULL), '{}') AS zones
       FROM invites i
       LEFT JOIN zones z ON z.id = ANY(i.zone_ids)
       WHERE i.client_id=$1 AND i.used_at IS NULL AND i.expires_at > CURRENT_TIMESTAMP GROUP BY i.id ORDER BY i.email`,
      [req.user.client_id]
    );
    res.json({ users: users.rows, invites: invites.rows });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/my-team/invite', authMiddleware, async (req, res) => {
  if (req.user.role !== 'client_admin') return res.status(403).json({ error: 'Client admin only' });
  if (!dbConnected) return res.status(503).json({ error: 'DB not connected' });
  const { email, zone_ids } = req.body;
  if (!email) return res.status(400).json({ error: 'email required' });
  try {
    const { token, tokenHash } = generateInviteToken();
    const expiresAt = new Date(Date.now() + INVITE_EXPIRY_DAYS * 24 * 60 * 60 * 1000);
    await pool.query(
      'INSERT INTO invites (email,client_id,role,invited_by,token_hash,zone_ids,expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7)',
      [email.toLowerCase(), req.user.client_id, 'client_user', req.user.username, tokenHash, zone_ids || [], expiresAt]
    );
    const clientName = await getClientNameById(req.user.client_id);
    await sendInviteEmail(email, token, clientName, 'client_user');
    await logActivity(req.user.client_id, req.user.username, 'Invited', `Invited ${email} to the team`);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Also used by the E-Tech admin "Users" panel (admin can manage any
// client's zone assignments), not just My Team (client_admin, own client
// only) — same URL for both rather than a mirrored /api/users/:id/zones,
// since the only real difference is the ownership check below.
app.put('/api/my-team/:userId/zones', authMiddleware, async (req, res) => {
  if (req.user.role !== 'admin' && req.user.role !== 'client_admin') return res.status(403).json({ error: 'Not authorized' });
  if (!dbConnected) return res.status(503).json({ error: 'DB not connected' });
  const { zone_ids } = req.body;
  try {
    const target = await pool.query('SELECT email,client_id,role FROM users WHERE id=$1', [req.params.userId]);
    if (!target.rows[0]) return res.status(404).json({ error: 'User not found' });
    if (req.user.role === 'client_admin' && target.rows[0].client_id !== req.user.client_id) return res.status(404).json({ error: 'User not found' });
    if (target.rows[0].role !== 'client_user') return res.status(400).json({ error: 'Only sub-users have zone assignments' });
    await pool.query('DELETE FROM user_zone_access WHERE user_id=$1', [req.params.userId]);
    for (const zoneId of (zone_ids || [])) {
      await pool.query('INSERT INTO user_zone_access (user_id,zone_id) VALUES ($1,$2) ON CONFLICT DO NOTHING', [req.params.userId, zoneId]);
    }
    const logClientId = req.user.role === 'admin' ? target.rows[0].client_id : req.user.client_id;
    await logActivity(logClientId, req.user.username, 'Updated', `Zone access updated for ${target.rows[0].email}`);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/my-team/:userId/status', authMiddleware, async (req, res) => {
  if (req.user.role !== 'client_admin') return res.status(403).json({ error: 'Client admin only' });
  if (!dbConnected) return res.status(503).json({ error: 'DB not connected' });
  const { status } = req.body;
  if (!['active', 'disabled'].includes(status)) return res.status(400).json({ error: 'status must be active or disabled' });
  try {
    const target = await pool.query('SELECT email,client_id FROM users WHERE id=$1', [req.params.userId]);
    if (!target.rows[0] || target.rows[0].client_id !== req.user.client_id) return res.status(404).json({ error: 'User not found' });
    await pool.query('UPDATE users SET status=$1 WHERE id=$2', [status, req.params.userId]);
    await logActivity(req.user.client_id, req.user.username, 'Updated', `${target.rows[0].email} ${status === 'disabled' ? 'disabled' : 're-enabled'}`);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/my-team/:userId', authMiddleware, async (req, res) => {
  if (req.user.role !== 'client_admin') return res.status(403).json({ error: 'Client admin only' });
  if (!dbConnected) return res.status(503).json({ error: 'DB not connected' });
  try {
    const target = await pool.query('SELECT email,client_id FROM users WHERE id=$1', [req.params.userId]);
    if (!target.rows[0] || target.rows[0].client_id !== req.user.client_id) return res.status(404).json({ error: 'User not found' });
    await pool.query('DELETE FROM users WHERE id=$1', [req.params.userId]);
    await logActivity(req.user.client_id, req.user.username, 'Deleted', `Removed ${target.rows[0].email} from the team`);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/my-team/invites/:id', authMiddleware, async (req, res) => {
  if (req.user.role !== 'client_admin') return res.status(403).json({ error: 'Client admin only' });
  if (!dbConnected) return res.status(503).json({ error: 'DB not connected' });
  try {
    const result = await pool.query('DELETE FROM invites WHERE id=$1 AND client_id=$2 AND used_at IS NULL RETURNING email', [req.params.id, req.user.client_id]);
    if (!result.rows[0]) return res.status(404).json({ error: 'Invite not found' });
    await logActivity(req.user.client_id, req.user.username, 'Deleted', `Revoked invite for ${result.rows[0].email}`);
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

// The inbox uses the self-refreshing shared-mailbox token (graph_auth,
// connected via /api/admin/graph-auth/start), not req.user.msToken. The
// msToken in the CAMS JWT is a Microsoft access token that expires after
// about an hour, while the JWT lasts 42 days, so the inbox used to go
// stale until the person logged out and back in.
async function getGraphToken(req) {
  return await getValidGraphToken();
}

// Staff only. Clients must never reach the support inbox.
function requireStaff(req, res, next) {
  if (req.user.role !== 'admin' && req.user.role !== 'technician') return res.status(403).json({ error: 'Not authorized' });
  next();
}

const MAILBOX_DISCONNECTED = 'The support mailbox is disconnected — an admin needs to reconnect it.';

// Turns a failed Graph call into an honest response: disconnected (401/403),
// too slow (timeout or network error, so no response at all), or a
// Microsoft error.
function sendMailboxError(res, err, label) {
  const status = err.response?.status;
  console.error(label + ':', status || err.code || '', err.response?.data?.error?.message || err.message);
  if (status === 401 || status === 403) return res.status(503).json({ error: MAILBOX_DISCONNECTED });
  if (!err.response && (err.request || err.code)) return res.status(504).json({ error: 'The support mailbox took too long to respond — try again.' });
  res.status(502).json({ error: `Couldn't load the support mailbox (Microsoft error ${status || 'unknown'}).` });
}

app.get('/api/outlook/emails', authMiddleware, requireStaff, async (req, res) => {
  const graphToken = await getGraphToken(req);
  // No local `emails` fallback here: a broken connection should show as
  // broken, not as stale mail.
  if (!graphToken) {
    console.error('Outlook fetch: no Graph token available for the shared mailbox');
    return res.status(503).json({ error: MAILBOX_DISCONNECTED });
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
      timeout: 20000,
      params: {
        $top: 50,
        $orderby: 'receivedDateTime desc',
        $filter: `receivedDateTime ge ${thirtyDaysAgo}`,
        // No body: the list only needs the preview. Opening an email loads
        // the full body from /api/outlook/message/:id.
        $select: 'id,subject,from,toRecipients,receivedDateTime,bodyPreview,isRead,flag,hasAttachments,webLink'
      }
    });
    const emails = response.data.value.map(msg => ({
      id: msg.id, sender: msg.from?.emailAddress?.name || 'Unknown', sender_email: msg.from?.emailAddress?.address || '',
      recipient: msg.toRecipients?.map(r => r.emailAddress?.name).join(', ') || '', subject: msg.subject || '(no subject)',
      body: msg.bodyPreview || '', is_read: msg.isRead, is_flagged: !!msg.flag?.flagStatus,
      folder: folder, created_at: msg.receivedDateTime, has_attachments: msg.hasAttachments, webLink: msg.webLink
    }));
    res.json(emails);
  } catch (err) {
    sendMailboxError(res, err, 'Outlook fetch error');
  }
});

const INLINE_IMAGE_MAX_BYTES = 2 * 1024 * 1024;

// One message with its full body. Inline images (src="cid:...") are swapped
// for data: URLs so they show without the browser needing Graph access.
app.get('/api/outlook/message/:id', authMiddleware, requireStaff, async (req, res) => {
  const graphToken = await getGraphToken(req);
  if (!graphToken) {
    console.error('Outlook message: no Graph token available for the shared mailbox');
    return res.status(503).json({ error: MAILBOX_DISCONNECTED });
  }
  const messageUrl = `https://graph.microsoft.com/v1.0/users/${SHARED_MAILBOX}/messages/${encodeURIComponent(req.params.id)}`;
  const headers = { Authorization: `Bearer ${graphToken}` };
  try {
    const { data: msg } = await axios.get(messageUrl, {
      headers, timeout: 20000,
      params: { $select: 'id,subject,from,toRecipients,receivedDateTime,body,hasAttachments,webLink' }
    });
    let fullBody = msg.body?.content || '';
    if (/cid:/i.test(fullBody)) {
      // No $select: contentId and contentBytes only exist on fileAttachment,
      // and Graph rejects selecting them on the base attachment type.
      const { data: atts } = await axios.get(`${messageUrl}/attachments`, {
        headers, timeout: 20000,
        params: { $filter: 'isInline eq true' }
      });
      const stripCid = (cid) => cid.trim().replace(/^<|>$/g, '').toLowerCase();
      const images = {};
      for (const a of atts.value || []) {
        if (!a.contentId || !a.contentBytes) continue;
        if (Math.floor(a.contentBytes.length * 3 / 4) > INLINE_IMAGE_MAX_BYTES) continue; // decoded size
        images[stripCid(a.contentId)] = `data:${a.contentType || 'application/octet-stream'};base64,${a.contentBytes}`;
      }
      fullBody = fullBody.replace(/src\s*=\s*(["'])cid:([^"']+)\1/gi, (match, quote, cid) => {
        const dataUrl = images[stripCid(cid)];
        return dataUrl ? `src=${quote}${dataUrl}${quote}` : match;
      });
    }
    res.json({
      id: msg.id, subject: msg.subject || '(no subject)', sender: msg.from?.emailAddress?.name || 'Unknown',
      sender_email: msg.from?.emailAddress?.address || '', recipient: msg.toRecipients?.map(r => r.emailAddress?.name).join(', ') || '',
      created_at: msg.receivedDateTime, fullBody, has_attachments: msg.hasAttachments, webLink: msg.webLink
    });
  } catch (err) {
    sendMailboxError(res, err, 'Outlook message error');
  }
});

// ---- Composing from the support mailbox (new, reply, reply all, forward) ----
// The browser sends plain text. It is HTML-escaped here, line breaks become
// <br>, and the signature is added here from the signed-in user, so nothing
// typed can inject HTML and the signature can't be edited or spoofed.
const EMAIL_ADDRESS_RE = /^[^\s@<>()[\]\\,;:"]+@[^\s@<>()[\]\\,;:"]+\.[a-z]{2,}$/i;
const MAX_RECIPIENTS = 20;
const MAX_EMAIL_TEXT = 20000;
const MAX_SUBJECT = 255;

function escapeHtml(v) {
  return String(v).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

// Accepts an array or a comma/semicolon separated string.
function parseRecipients(v) {
  if (v == null || v === '') return [];
  const list = Array.isArray(v) ? v : String(v).split(/[,;]/);
  return list.map(a => String(a).trim()).filter(Boolean);
}

function emailSignature(req) {
  return `${req.user.username || 'E-Tech'} · E-Tech Systems Support`;
}

function composeEmailHtml(text, req) {
  const typed = escapeHtml(text).replace(/\r\n|\r|\n/g, '<br>');
  return `<div>${typed}</div><br><div>— ${escapeHtml(emailSignature(req))}</div>`;
}

// Returns an error message for bad input, or null.
function validateCompose({ to, cc, text, subject, toRequired, textRequired }) {
  if (toRequired && to.length === 0) return 'Add at least one recipient in To.';
  if (to.length + cc.length > MAX_RECIPIENTS) return `Too many recipients — the limit is ${MAX_RECIPIENTS}.`;
  const bad = [...to, ...cc].filter(a => !EMAIL_ADDRESS_RE.test(a));
  if (bad.length) return `Not a valid email address: ${bad.join(', ')}`;
  if (typeof text !== 'string') return 'The message text is missing.';
  if (textRequired && !text.trim()) return 'Write a message before sending.';
  if (text.length > MAX_EMAIL_TEXT) return `The message is too long — the limit is ${MAX_EMAIL_TEXT.toLocaleString('en-US')} characters.`;
  if (subject != null && (typeof subject !== 'string' || subject.length > MAX_SUBJECT)) return `The subject is too long — the limit is ${MAX_SUBJECT} characters.`;
  return null;
}

const toGraphRecipients = list => list.map(address => ({ emailAddress: { address } }));

app.post('/api/outlook/send', authMiddleware, requireStaff, async (req, res) => {
  const to = parseRecipients(req.body.to), cc = parseRecipients(req.body.cc);
  const subject = typeof req.body.subject === 'string' ? req.body.subject.trim() : '';
  const text = req.body.body;
  const invalid = validateCompose({ to, cc, text, subject, toRequired: true, textRequired: true });
  if (invalid) return res.status(400).json({ error: invalid });
  const graphToken = await getGraphToken(req);
  if (!graphToken) {
    console.error('Outlook send: no Graph token available for the shared mailbox');
    return res.status(503).json({ error: MAILBOX_DISCONNECTED });
  }
  const html = composeEmailHtml(text, req);
  const emailData = { message: { subject, body: { contentType: 'HTML', content: html }, toRecipients: toGraphRecipients(to) } };
  if (cc.length) emailData.message.ccRecipients = toGraphRecipients(cc);
  try {
    await axios.post(`https://graph.microsoft.com/v1.0/users/${SHARED_MAILBOX}/sendMail`, emailData, {
      headers: { Authorization: `Bearer ${graphToken}`, 'Content-Type': 'application/json' },
      timeout: 20000
    });
  } catch (err) {
    // Not saved locally: a copy in `emails` would look sent when it wasn't.
    return sendMailboxError(res, err, 'Outlook send error');
  }
  try {
    await pool.query('INSERT INTO emails (client_id,sender,recipient,subject,body,folder) VALUES ($1,$2,$3,$4,$5,$6)', [req.user.client_id||1,req.user.username,to.join(', '),subject,html,'sent']);
  } catch (dbErr) { console.error('Failed to save sent email locally:', dbErr.message); }
  await logActivity(1, req.user.username, 'Email', `Sent email to ${[...to, ...cc].join(', ')} — "${subject || '(no subject)'}"`);
  res.json({ success: true });
});

// Reply / reply all. Microsoft threads it, sets "RE:" and quotes the original.
// The original is read first for the activity log (recipient and subject).
app.post('/api/outlook/reply/:id', authMiddleware, requireStaff, async (req, res) => {
  const replyAll = req.body.replyAll === true;
  const cc = parseRecipients(req.body.cc);
  const subject = typeof req.body.subject === 'string' && req.body.subject.trim() ? req.body.subject.trim() : null;
  const text = req.body.comment;
  const invalid = validateCompose({ to: [], cc, text, subject, toRequired: false, textRequired: true });
  if (invalid) return res.status(400).json({ error: invalid });
  const graphToken = await getGraphToken(req);
  if (!graphToken) {
    console.error('Outlook reply: no Graph token available for the shared mailbox');
    return res.status(503).json({ error: MAILBOX_DISCONNECTED });
  }
  const messageUrl = `https://graph.microsoft.com/v1.0/users/${SHARED_MAILBOX}/messages/${encodeURIComponent(req.params.id)}`;
  const headers = { Authorization: `Bearer ${graphToken}`, 'Content-Type': 'application/json' };
  try {
    const { data: original } = await axios.get(messageUrl, { headers, timeout: 20000, params: { $select: 'subject,from,toRecipients,ccRecipients' } });
    const payload = { comment: composeEmailHtml(text, req) };
    if (subject || cc.length) {
      payload.message = {};
      if (subject) payload.message.subject = subject;
      if (cc.length) payload.message.ccRecipients = toGraphRecipients(cc);
    }
    await axios.post(`${messageUrl}/${replyAll ? 'replyAll' : 'reply'}`, payload, { headers, timeout: 20000 });
    const addr = r => r?.emailAddress?.address;
    let recipients = [addr(original.from)];
    if (replyAll) recipients = recipients.concat((original.toRecipients || []).map(addr), (original.ccRecipients || []).map(addr));
    recipients = [...new Set(recipients.concat(cc).filter(a => a && a.toLowerCase() !== SHARED_MAILBOX))];
    await logActivity(1, req.user.username, 'Email', `${replyAll ? 'Replied all' : 'Replied'} to ${recipients.join(', ') || 'unknown'} — "${subject || original.subject || '(no subject)'}"`);
    res.json({ success: true });
  } catch (err) {
    sendMailboxError(res, err, 'Outlook reply error');
  }
});

app.post('/api/outlook/forward/:id', authMiddleware, requireStaff, async (req, res) => {
  const to = parseRecipients(req.body.to), cc = parseRecipients(req.body.cc);
  const subject = typeof req.body.subject === 'string' && req.body.subject.trim() ? req.body.subject.trim() : null;
  const text = req.body.comment == null ? '' : req.body.comment;
  const invalid = validateCompose({ to, cc, text, subject, toRequired: true, textRequired: false });
  if (invalid) return res.status(400).json({ error: invalid });
  const graphToken = await getGraphToken(req);
  if (!graphToken) {
    console.error('Outlook forward: no Graph token available for the shared mailbox');
    return res.status(503).json({ error: MAILBOX_DISCONNECTED });
  }
  const messageUrl = `https://graph.microsoft.com/v1.0/users/${SHARED_MAILBOX}/messages/${encodeURIComponent(req.params.id)}`;
  const headers = { Authorization: `Bearer ${graphToken}`, 'Content-Type': 'application/json' };
  try {
    const { data: original } = await axios.get(messageUrl, { headers, timeout: 20000, params: { $select: 'subject' } });
    const payload = { comment: composeEmailHtml(text, req), toRecipients: toGraphRecipients(to) };
    if (subject || cc.length) {
      payload.message = {};
      if (subject) payload.message.subject = subject;
      if (cc.length) payload.message.ccRecipients = toGraphRecipients(cc);
    }
    await axios.post(`${messageUrl}/forward`, payload, { headers, timeout: 20000 });
    await logActivity(1, req.user.username, 'Email', `Forwarded "${subject || original.subject || '(no subject)'}" to ${[...to, ...cc].join(', ')}`);
    res.json({ success: true });
  } catch (err) {
    sendMailboxError(res, err, 'Outlook forward error');
  }
});

app.post('/api/outlook/read/:id', authMiddleware, requireStaff, async (req, res) => {
  const graphToken = await getGraphToken(req);
  if (!graphToken) return res.status(503).json({ error: 'No Microsoft Graph token available' });
  try { await axios.patch(`https://graph.microsoft.com/v1.0/users/${SHARED_MAILBOX}/messages/${req.params.id}`, { isRead: true }, { headers: { Authorization: `Bearer ${graphToken}`, 'Content-Type': 'application/json' }, timeout: 8000 }); res.json({ success: true }); }
  catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/outlook/flag/:id', authMiddleware, requireStaff, async (req, res) => {
  const { flagged } = req.body;
  const graphToken = await getGraphToken(req);
  if (!graphToken) return res.status(503).json({ error: 'No Microsoft Graph token available' });
  try { await axios.patch(`https://graph.microsoft.com/v1.0/users/${SHARED_MAILBOX}/messages/${req.params.id}`, { flag: flagged ? { flagStatus: 'flagged' } : { flagStatus: 'notFlagged' } }, { headers: { Authorization: `Bearer ${graphToken}`, 'Content-Type': 'application/json' }, timeout: 8000 }); res.json({ success: true }); }
  catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/outlook/delete/:id', authMiddleware, requireStaff, async (req, res) => {
  const graphToken = await getGraphToken(req);
  if (!graphToken) return res.status(503).json({ error: 'No Microsoft Graph token available' });
  try { await axios.post(`https://graph.microsoft.com/v1.0/users/${SHARED_MAILBOX}/messages/${req.params.id}/move`, { destinationId: 'deleteditems' }, { headers: { Authorization: `Bearer ${graphToken}`, 'Content-Type': 'application/json' }, timeout: 8000 }); res.json({ success: true }); }
  catch (err) { res.status(500).json({ error: err.message }); }
});

// ============================================================
// FILES — MICROSOFT GRAPH ONEDRIVE
// ============================================================
// These read each person's own drive, so they stay on req.user.msToken.
// That token has the same one-hour expiry the inbox used to hit: after an
// hour these fail until the person signs in with Microsoft again.

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
    res.json(filterByZoneAccess(result.rows, req));
  } catch (err) { res.json([]); }
});

app.put('/api/stations/:id', authMiddleware, blockAssetEdit, async (req, res) => {
  if (!dbConnected) return res.status(503).json({ error: 'DB not connected' });
  const { id } = req.params;
  const { status, name, zone, make, model, apps, ip_address, install_date, purchase_date, warranty_expiry } = req.body;
  try {
    const userClientId = req.user.role === 'admin' ? null : req.user.client_id;
    const asset = await pool.query('SELECT name, client_id FROM stations WHERE id=$1', [id]);
    const assetName = asset.rows[0]?.name || id;
    const assetClientId = asset.rows[0]?.client_id;
    const assetClient = await getClientNameById(assetClientId);
    // Invited client accounts change status only (blockAssetEdit already
    // checked ownership and zone). The full update below would also null
    // out the date fields, which the client form never sends.
    if (isClientAccount(req)) {
      await pool.query('UPDATE stations SET status=COALESCE($1,status),updated_at=CURRENT_TIMESTAMP WHERE id=$2 AND client_id=$3', [status, id, req.user.client_id]);
      await logActivity(assetClientId || req.user.client_id, req.user.username, 'Updated', `Station ${assetName} status updated (${assetClient})`);
      return res.json({ success: true });
    }
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
    res.json(filterByZoneAccess(result.rows, req));
  } catch (err) { res.json([]); }
});

app.put('/api/monitors/:id', authMiddleware, blockAssetEdit, async (req, res) => {
  if (!dbConnected) return res.status(503).json({ error: 'DB not connected' });
  const { id } = req.params;
  const { status, name, zone, make, model, size, install_date, purchase_date, warranty_expiry } = req.body;
  try {
    const userClientId = req.user.role === 'admin' ? null : req.user.client_id;
    const asset = await pool.query('SELECT name, client_id FROM monitors WHERE id=$1', [id]);
    const assetName = asset.rows[0]?.name || id;
    const assetClientId = asset.rows[0]?.client_id;
    const assetClient = await getClientNameById(assetClientId);
    // Invited client accounts change status only (blockAssetEdit already
    // checked ownership and zone). The full update below would also null
    // out the date fields, which the client form never sends.
    if (isClientAccount(req)) {
      await pool.query('UPDATE monitors SET status=COALESCE($1,status),updated_at=CURRENT_TIMESTAMP WHERE id=$2 AND client_id=$3', [status, id, req.user.client_id]);
      await logActivity(assetClientId || req.user.client_id, req.user.username, 'Updated', `Monitor ${assetName} status updated (${assetClient})`);
      return res.json({ success: true });
    }
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
// MONTHLY REPORTS
// ============================================================

// Covers the previous full calendar month — e.g. a report sent on the 1st
// of February covers all of January. Date's month arithmetic handles the
// January/December year rollover on its own.
function getMonthRange() {
  const now = new Date();
  const start = new Date(now.getFullYear(), now.getMonth() - 1, 1, 0, 0, 0, 0);
  const end = new Date(now.getFullYear(), now.getMonth(), 0, 23, 59, 59, 999);
  return { start, end };
}

function formatDateRange(start, end) {
  const options = { day: 'numeric', month: 'long', year: 'numeric' };
  return `${start.toLocaleDateString('en-GB', options)} — ${end.toLocaleDateString('en-GB', options)}`;
}

async function generateClientReport(clientId, clientName, clientEmail, msToken) {
  const { start, end } = getMonthRange();
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
      <h2 style="color:#1a3a5c;">CAMS Monthly Report</h2>
      <p><strong>Client:</strong> ${clientName}</p>
      <p><strong>Period:</strong> ${dateRangeStr}</p>
      <hr>
      <p>Dear ${clientName} Team,</p>
      <p>Here is your monthly asset management summary from E-Tech Systems.</p>
      <h3 style="color:#1a3a5c;">Overview</h3>
      <p>Over the past month, <strong>${srsCreated} service requests</strong> were raised for your sites and <strong>${srsResolved} were resolved</strong>. You currently have <strong>${openSRs.rows.length} open requests</strong>, <strong>${highPriorityOpen} of which ${highPriorityOpen === 1 ? 'is' : 'are'} high priority</strong>${highPriorityOpen > 0 ? ' and require immediate attention' : ''}.</p>
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
    await sendEmailNotification(clientEmail, `[CAMS] Monthly Report — ${clientName} — ${dateRangeStr}`, emailBody, `Bearer ${msToken}`);
    console.log(`✅ Client report sent to ${clientName} (${clientEmail})`);
  }
}

async function generateAdminReport(msToken) {
  const { start, end } = getMonthRange();
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
      <h2 style="color:#1a3a5c;">CAMS Monthly Admin Report</h2>
      <p><strong>Period:</strong> ${dateRangeStr}</p>
      <hr>
      <h3 style="color:#1a3a5c;">Executive Summary</h3>
      <p>Across all <strong>${clients.length} clients</strong>, <strong>${srsCreated} service requests</strong> were created in the last month and <strong>${srsResolved} were resolved</strong>. There are currently <strong>${openSRs.rows.length} open requests</strong>, of which <strong>${highPriorityOpen.length} ${highPriorityOpen.length === 1 ? 'is' : 'are'} high priority</strong> and require immediate action.</p>
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
      ${activityLog.rows.length > 0 ? `<h3 style="color:#1a3a5c;">Notable Activity (Last Month)</h3>${activityTable}` : ''}
      <p>View full dashboard: <a href="${process.env.APP_URL || "https://e-tech-cams.up.railway.app"}">Open CAMS</a></p>
    </div>`;

  await sendEmailNotification(ADMIN_EMAIL, `[CAMS] Monthly Admin Report — ${dateRangeStr}`, emailBody, `Bearer ${msToken}`);
  console.log(`✅ Admin report sent to ${ADMIN_EMAIL}`);
}

async function runMonthlyReports() {
  if (!dbConnected) {
    console.log('⚠️ Reports skipped: DB not connected');
    return { sent: false, reason: 'Database not connected' };
  }

  console.log('📊 Running monthly reports...');
  
  try {
    const msToken = await getValidGraphToken();
    
    if (!msToken) {
      console.log('⚠️ Shared mailbox has never been connected — reports skipped. Use POST /api/admin/graph-auth/connect once to set this up.');
      return { sent: false, reason: 'Shared mailbox not connected yet — this needs a one-time setup via /api/admin/graph-auth/connect, not just an env var' };
    }
    
    await generateAdminReport(msToken);
    
    const clients = await pool.query('SELECT id,name,email FROM clients WHERE email IS NOT NULL AND email != \'\'');
    for (const client of clients.rows) {
      await generateClientReport(client.id, client.name, client.email, msToken);
    }
    
    console.log('✅ Monthly reports completed');
    return { sent: true, clientsEmailed: clients.rows.length };
  } catch (err) {
    console.error('❌ Report generation failed:', err.message);
    return { sent: false, reason: err.message };
  }
}

// 5:00 PM Jamaica time on the 1st of every month — by then the previous
// calendar month (the period getMonthRange() reports on) has fully ended.
cron.schedule('0 17 1 * *', () => {
  runMonthlyReports();
}, {
  timezone: "America/Jamaica"
});

console.log('📅 Monthly reports scheduled: 1st of each month at 5:00 PM Jamaica time');

// One-time (or re-run if it ever fully lapses) setup: exchange an
// authorization code for the shared mailbox's first access+refresh token
// pair. After this, the app refreshes itself automatically forever.
// Dedicated redirect target for connecting the shared mailbox — deliberately
// NOT the app's homepage, since that page's own Microsoft-login code was
// silently grabbing the ?code= parameter for its own unrelated login flow
// before a human ever got a chance to see or copy it. This route captures
// the code and completes the whole exchange itself — no copy/paste needed.
// PKCE helpers — same technique the app's own frontend login already uses,
// just needed server-side now too since Azure AD requires it for this kind
// of browser redirect flow.
function base64URLEncode(buffer) {
  return buffer.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}
let pendingGraphAuthVerifier = null; // rare, single-admin, one-time action — in-memory is fine

// Visit this URL directly (no manual URL-building needed) to start connecting
// the shared mailbox. Generates the required PKCE challenge and redirects to
// Microsoft automatically.
app.get('/api/admin/graph-auth/start', (req, res) => {
  const verifier = base64URLEncode(crypto.randomBytes(32));
  pendingGraphAuthVerifier = verifier;
  const challenge = base64URLEncode(crypto.createHash('sha256').update(verifier).digest());
  const redirectUri = `${req.protocol}://${req.get('host')}/api/admin/graph-auth/callback`;
  const authUrl = `https://login.microsoftonline.com/${MS_TENANT_ID_SERVER}/oauth2/v2.0/authorize?` +
    `client_id=${MS_CLIENT_ID_SERVER}&response_type=code&redirect_uri=${encodeURIComponent(redirectUri)}` +
    `&scope=${encodeURIComponent(GRAPH_SCOPES)}&response_mode=query` +
    `&code_challenge=${challenge}&code_challenge_method=S256`;
  res.redirect(authUrl);
});

app.get('/api/admin/graph-auth/callback', async (req, res) => {
  const { code, error, error_description } = req.query;
  const redirectUri = `${req.protocol}://${req.get('host')}/api/admin/graph-auth/callback`;

  if (error) {
    return res.send(`<html><body style="font-family:sans-serif;padding:40px;"><h2>❌ Microsoft returned an error</h2><p>${error}: ${error_description || ''}</p></body></html>`);
  }
  if (!code) {
    return res.send(`<html><body style="font-family:sans-serif;padding:40px;"><h2>No authorization code received</h2></body></html>`);
  }

  try {
    const response = await axios.post(
      `https://login.microsoftonline.com/${MS_TENANT_ID_SERVER}/oauth2/v2.0/token`,
      new URLSearchParams({
        client_id: MS_CLIENT_ID_SERVER,
        grant_type: 'authorization_code',
        code,
        redirect_uri: redirectUri,
        scope: GRAPH_SCOPES,
        code_verifier: pendingGraphAuthVerifier || ''
      }),
      { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
    );
    const { access_token, refresh_token, expires_in } = response.data;
    if (!refresh_token) {
      return res.send(`<html><body style="font-family:sans-serif;padding:40px;"><h2>⚠️ No refresh_token returned</h2><p>Make sure the sign-in request included the offline_access scope.</p></body></html>`);
    }
    await saveGraphAuth(access_token, refresh_token, expires_in);
    res.send(`<html><body style="font-family:sans-serif;padding:40px;"><h2>✅ Shared mailbox connected</h2><p>Reports will now refresh their own Graph access automatically. You can close this tab.</p></body></html>`);
  } catch (err) {
    res.send(`<html><body style="font-family:sans-serif;padding:40px;"><h2>❌ Token exchange failed</h2><p>${err.response?.data?.error_description || err.message}</p></body></html>`);
  }
});

app.post('/api/admin/graph-auth/connect', authMiddleware, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  const { code, redirectUri } = req.body;
  if (!code || !redirectUri) return res.status(400).json({ error: 'code and redirectUri are required' });
  try {
    const response = await axios.post(
      `https://login.microsoftonline.com/${MS_TENANT_ID_SERVER}/oauth2/v2.0/token`,
      new URLSearchParams({
        client_id: MS_CLIENT_ID_SERVER,
        grant_type: 'authorization_code',
        code,
        redirect_uri: redirectUri,
        scope: GRAPH_SCOPES
      }),
      { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
    );
    const { access_token, refresh_token, expires_in } = response.data;
    if (!refresh_token) {
      return res.status(400).json({ error: 'Microsoft did not return a refresh_token — make sure the authorization request included the offline_access scope' });
    }
    await saveGraphAuth(access_token, refresh_token, expires_in);
    res.json({ success: true, message: 'Shared mailbox connected — reports will now refresh their own access automatically' });
  } catch (err) {
    res.status(500).json({ error: err.response?.data?.error_description || err.message });
  }
});

app.get('/api/admin/graph-auth/status', authMiddleware, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  const stored = await getStoredGraphAuth();
  if (!stored || !stored.access_token) return res.json({ connected: false });
  res.json({ connected: true, expiresAt: stored.expires_at, hasRefreshToken: !!stored.refresh_token });
});

app.post('/api/reports/run', authMiddleware, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  try {
    const result = await runMonthlyReports();
    if (result.sent) {
      res.json({ success: true, message: `Reports actually sent to admin + ${result.clientsEmailed} client(s)` });
    } else {
      res.status(200).json({ success: false, message: 'Reports were NOT sent', reason: result.reason });
    }
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
