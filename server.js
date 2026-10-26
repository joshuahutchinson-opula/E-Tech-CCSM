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
    // First-login walkthrough (also in migrations/005). NULL = not done yet.
    pool.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS onboarded_at TIMESTAMP')
      .then(() => console.log('✅ users.onboarded_at column ready'))
      .catch(e => console.error('❌ Could not add users.onboarded_at:', e.message));
    // Separate controller, reader and lock warranties on doors (also in migrations/008).
    runSchema(DOOR_WARRANTY_SCHEMA)
      .then(() => console.log('✅ Door part warranty columns ready'))
      .catch(e => console.error('❌ Could not add door part warranty columns:', e.message));
    // Stored monthly reports (also in migrations/006). Once ready, sends a
    // missed monthly report and retries failed deliveries.
    // Password reset links (also in migrations/007).
    runSchema(PASSWORD_RESET_SCHEMA)
      .then(() => console.log('✅ Password reset tables ready'))
      .catch(e => console.error('❌ Could not create password reset tables:', e.message));
    ensureReportTables()
      .then(() => { console.log('✅ Report tables ready'); return runSchema(EXPIRY_ALERT_SCHEMA); })
      .then(() => { console.log('✅ Expiry alert tables ready'); return runReportMaintenance(); })
      .catch(e => console.error('❌ Could not create report or expiry alert tables:', e.message));
  }
});

// ============================================================
// MIDDLEWARE
// ============================================================

app.use(cors());
app.use(express.json({ limit: '50mb' }));
// The app folder is served as static files, so server-only files are
// refused first (404), matched on the decoded, normalised path, any case.
const SERVER_ONLY_PATHS = /^\/(?:server\.js|package\.json|package-lock\.json|(?:migrations|node_modules|uploads|\.github)(?:\/|$))|\.(?:md|sql)$/i;
app.use((req, res, next) => {
  let p;
  try { p = decodeURIComponent(req.path); } catch (e) { return res.status(404).send('Not found'); }
  p = path.posix.normalize('/' + p.replace(/\\/g, '/'));
  if (SERVER_ONLY_PATHS.test(p)) return res.status(404).send('Not found');
  next();
});
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

// Sends through the shared mailbox; throws on failure.
async function postGraphMail(to, subject, body, authHeader) {
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
}

async function sendEmailNotification(to, subject, body, authHeader) {
  try {
    await postGraphMail(to, subject, body, authHeader);
    return true;
  } catch (err) {
    console.error('Email notification failed:', err.message);
    return false;
  }
}

// Every active user of a client, lowercased and de-duplicated.
async function getClientUserEmails(clientId) {
  const result = await pool.query("SELECT DISTINCT LOWER(email) AS email FROM users WHERE client_id=$1 AND status='active'", [clientId]);
  return result.rows.map(r => r.email);
}

// One email per client user (never a shared To/CC). Returns how many were
// sent; skips without a client or token, and never throws.
async function notifyClientUsers(clientId, subject, html, token) {
  if (!clientId || !token) return 0;
  let sent = 0;
  try {
    for (const email of await getClientUserEmails(clientId)) {
      if (await sendEmailNotification(email, subject, html, `Bearer ${token}`)) sent++;
    }
  } catch (err) {
    console.error('Could not notify client users:', err.message);
  }
  return sent;
}

// ---- Multiple technicians per SR ----
// service_requests.assigned_to holds a comma-separated list ("Roger, Akeem");
// empty or "Unassigned" means nobody. Tech names never contain commas.
function parseAssignees(v) {
  const list = Array.isArray(v) ? v : String(v == null ? '' : v).split(',');
  return [...new Set(list.map(s => String(s == null ? '' : s).trim()).filter(s => s && s !== 'Unassigned'))];
}
function formatAssignees(arr) { return arr.length ? arr.join(', ') : 'Unassigned'; }
// Request body assigned_to (array or string) -> { list, value } or { error };
// {} when it wasn't sent.
function normaliseAssignedTo(v) {
  if (v === undefined || v === null) return {};
  const list = parseAssignees(v);
  const unknown = list.find(n => !Object.prototype.hasOwnProperty.call(TECH_EMAILS, n));
  if (unknown) return { error: `Unknown technician: ${unknown}` };
  return { list, value: formatAssignees(list) };
}
// Compares sets, not strings. msg is null when nothing changed.
function assignmentChange(oldValue, newList, by) {
  const old = parseAssignees(oldValue);
  const added = newList.filter(n => !old.includes(n)), removed = old.filter(n => !newList.includes(n));
  let msg = null;
  if (added.length && removed.length) msg = `Added ${added.join(', ')}, removed ${removed.join(', ')} by ${by}`;
  else if (added.length) msg = `${old.length ? 'Added' : 'Assigned'} ${added.join(', ')} by ${by}`;
  else if (removed.length) msg = `Removed ${removed.join(', ')} by ${by}`;
  return { added, removed, msg };
}
// "[CAMS] Assigned" email to each newly added tech only.
async function emailNewAssignees(sr, added, priority, token) {
  if (!token || !sr) return;
  for (const tech of added) {
    const techEmailBody = `<h2>You've been assigned a Service Request</h2><p><strong>SR ID:</strong> ${sr.sr_id}</p><p><strong>Subject:</strong> ${sr.subject}</p><p><strong>Client:</strong> ${sr.client}</p><p><strong>Site:</strong> ${sr.site}</p><p><strong>Priority:</strong> ${priority || sr.priority}</p><hr><p>View in CAMS: <a href="${process.env.APP_URL || "https://e-tech-cams.up.railway.app"}">Open Dashboard</a></p>`;
    await sendEmailNotification(TECH_EMAILS[tech], `[CAMS] Assigned: ${sr.sr_id} — ${sr.subject}`, techEmailBody, `Bearer ${token}`);
  }
}

// Client-facing SR emails: every SR value is escaped; internal notes are never included.
const isRealTech = name => typeof name === 'string' && name.trim() !== '' && name.trim() !== 'Unassigned';
function srClientEmailHtml(heading, rows, closing) {
  const appUrl = process.env.APP_URL || "https://e-tech-cams.up.railway.app";
  return `<h2>${escapeHtml(heading)}</h2>` +
    rows.map(([label, value]) => `<p><strong>${label}:</strong> ${escapeHtml(value == null || value === '' ? '—' : value)}</p>`).join('') +
    (closing ? `<p>${escapeHtml(closing)}</p>` : '') +
    `<hr><p>View in CAMS: <a href="${appUrl}">Open CAMS</a></p>`;
}
function notifyRequestReceived(sr, token) {
  if (!sr || !sr.client_id) return Promise.resolve(0);
  return notifyClientUsers(sr.client_id, `[CAMS] Request received: ${sr.sr_id} — ${sr.subject}`,
    srClientEmailHtml(`Request received: ${sr.sr_id}`, [['SR ID', sr.sr_id], ['Subject', sr.subject], ['Site', sr.site], ['Priority', sr.priority]],
      'E-Tech has been notified and will assign a technician.'), token);
}
function notifyTechnicianAssigned(sr, tech, priority, token) {
  if (!sr || !sr.client_id || !isRealTech(tech)) return Promise.resolve(0);
  return notifyClientUsers(sr.client_id, `[CAMS] Technician assigned: ${sr.sr_id} — ${sr.subject}`,
    srClientEmailHtml(`Technician assigned: ${sr.sr_id}`, [['SR ID', sr.sr_id], ['Subject', sr.subject], ['Site', sr.site], ['Priority', priority || sr.priority], [tech.includes(',') ? 'Technicians' : 'Technician', tech]],
      `${tech} from E-Tech ${tech.includes(',') ? 'have' : 'has'} been assigned to your request.`), token);
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
const PASSWORD_CHANGED = Symbol('password changed');

async function loadFreshUserPermissions(decoded) {
  const result = await pool.query('SELECT id,email,client_id,role,status,password_changed_at FROM users WHERE id=$1', [decoded.id]);
  const u = result.rows[0];
  if (!u || u.status !== 'active') return null;
  // A password reset signs out every session issued before it.
  if (u.password_changed_at && (decoded.iat || 0) * 1000 < new Date(u.password_changed_at).getTime()) return PASSWORD_CHANGED;
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
    if (user === PASSWORD_CHANGED) return res.status(401).json({ error: 'Your password was changed.' });
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

// Forgot password and reset links (kept apart from the invite counter).
const passwordResetRateLimit = rateLimit({
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
      const result = await pool.query('SELECT * FROM users WHERE email=$1', [username.toLowerCase()]);
      const u = result.rows[0];
      if (u && u.status === 'active') {
        const match = await bcrypt.compare(password || '', u.password_hash);
        if (match) {
          const token = jwt.sign({ id: u.id, role: u.role }, process.env.JWT_SECRET, { expiresIn: '42d' });
          const clientName = await getClientNameById(u.client_id);
          await logActivity(u.client_id, u.email, 'Login', `${u.role === 'client_admin' ? 'Client admin' : 'Client user'} logged in`);
          return res.json({ token, onboarding_required: onboardingRequired(u), user: { id: u.id, username: u.email, email: u.email, client_id: u.client_id, client_name: clientName, role: u.role, photo_url: null } });
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
  // Only the Microsoft token is trusted: who signed in comes from Graph's
  // /me for that token, never from the email, name or id in the body.
  const msToken = typeof req.body?.msToken === 'string' ? req.body.msToken : '';
  if (!msToken) return res.status(401).json({ error: 'Microsoft sign-in could not be verified.' });
  let me;
  try {
    me = (await axios.get('https://graph.microsoft.com/v1.0/me', { headers: { Authorization: `Bearer ${msToken}` } })).data;
  } catch (err) {
    return res.status(401).json({ error: 'Microsoft sign-in could not be verified.' });
  }
  const email = String(me?.mail || me?.userPrincipalName || '').trim();
  const msId = me?.id;
  const displayName = me?.displayName || '';
  if (!email || !msId) return res.status(401).json({ error: 'Microsoft sign-in could not be verified.' });

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

  await logActivity(1, username, 'Login', `Microsoft login — ${displayName ? displayName + ' ' : ''}<${email}> (${role})`);

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
      cameras = await pool.query('SELECT status, zone FROM cameras');
      doors = await pool.query('SELECT status, zone FROM doors');
      servers = await pool.query('SELECT status, zone FROM servers');
      switches = await pool.query('SELECT status, zone FROM switches');
      srs = await pool.query("SELECT status FROM service_requests WHERE status != 'Resolved'");
    } else {
      const clientId = req.user.client_id;
      cameras = await pool.query('SELECT status, zone FROM cameras WHERE client_id = $1', [clientId]);
      doors = await pool.query('SELECT status, zone FROM doors WHERE client_id = $1', [clientId]);
      servers = await pool.query('SELECT status, zone FROM servers WHERE client_id = $1', [clientId]);
      switches = await pool.query('SELECT status, zone FROM switches WHERE client_id = $1', [clientId]);
      srs = await pool.query("SELECT status FROM service_requests WHERE client_id = $1 AND status != 'Resolved'", [clientId]);
    }

    // A client_user counts only devices in their zones, like the device lists.
    const devices = [cameras, doors, servers, switches].flatMap(r => filterByZoneAccess(r.rows, req));
    const isOnline = d => ['online', 'working'].includes(String(d.status || '').toLowerCase());
    const totalDevices = devices.length;
    const offline = devices.filter(d => !isOnline(d)).length;
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

// The purchase_date columns on asset tables are kept but unused (no route reads or writes them).
app.put('/api/cameras/:id', authMiddleware, blockAssetEdit, async (req, res) => {
  if (!dbConnected) return res.status(503).json({ error: 'DB not connected' });
  const { id } = req.params;
  const { status, comments, name, zone, model, manufacturer, resolution, archiver, ip_address, mac_address, warranty, date_cleaned } = req.body;
  try {
    const userClientId = req.user.role === 'admin' ? null : req.user.client_id;
    const asset = await pool.query('SELECT name, client_id FROM cameras WHERE id=$1', [id]);
    const assetName = asset.rows[0]?.name || id;
    const assetClientId = asset.rows[0]?.client_id;
    const assetClient = await getClientNameById(assetClientId);
    
    if (req.user.role === 'admin') {
      const query = userClientId ? 
        `UPDATE cameras SET name=COALESCE($1,name),zone=COALESCE($2,zone),status=COALESCE($3,status),model=COALESCE($4,model),manufacturer=COALESCE($5,manufacturer),resolution=COALESCE($6,resolution),archiver=COALESCE($7,archiver),ip_address=COALESCE($8,ip_address),mac_address=COALESCE($9,mac_address),warranty=$10,date_cleaned=$11,comments=COALESCE($12,comments),updated_at=CURRENT_TIMESTAMP WHERE id=$13 AND client_id=$14` :
        `UPDATE cameras SET name=COALESCE($1,name),zone=COALESCE($2,zone),status=COALESCE($3,status),model=COALESCE($4,model),manufacturer=COALESCE($5,manufacturer),resolution=COALESCE($6,resolution),archiver=COALESCE($7,archiver),ip_address=COALESCE($8,ip_address),mac_address=COALESCE($9,mac_address),warranty=$10,date_cleaned=$11,comments=COALESCE($12,comments),updated_at=CURRENT_TIMESTAMP WHERE id=$13`;
      const params = userClientId ? [name,zone,status,model,manufacturer,resolution,archiver,ip_address,mac_address,warranty,date_cleaned,comments,id,userClientId] : [name,zone,status,model,manufacturer,resolution,archiver,ip_address,mac_address,warranty,date_cleaned,comments,id];
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
      await pool.query(`INSERT INTO cameras (client_id,name,zone,status,comments,model,manufacturer,resolution,archiver,ip_address,mac_address,warranty,date_cleaned) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
        [clientIds[idx],cam.name||'',cam.zone||'',cam.status||'Working',cam.comments||'',cam.model||'',cam.manufacturer||'',cam.resolution||'',cam.archiver||'',cam.ip_address||'',cam.mac_address||'',cam.warranty||null,cam.date_cleaned||null]);
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
      await pool.query(`INSERT INTO doors (client_id,name,zone,status,tech,reader,lock_type,ip_address,controller_type,door_swing,access_type,anti_passback,install_date,controller_warranty_expiry,reader_warranty_expiry,lock_warranty_expiry,comments) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`,
        [clientIds[idx], door.name||'', door.zone||door.site||'', door.status||'Online', door.tech||'', door.reader||'', door.lock_type||'', door.ip_address||'', door.controller_type||'', door.door_swing||'', door.access_type||'', door.anti_passback||'', door.install_date||null,
          // An old-style warranty_expiry column fills any part not given.
          door.controller_warranty_expiry||door.warranty_expiry||null, door.reader_warranty_expiry||door.warranty_expiry||null, door.lock_warranty_expiry||door.warranty_expiry||null, door.comments||'']);
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
      await pool.query(`INSERT INTO servers (client_id,name,zone,status,make,model,capacity,used,health,apps,serial,warranty_expiry,comments) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
        [clientIds[idx],srv.name||srv.serial||'',srv.zone||srv.location||'',srv.status||'Online',srv.make||'',srv.model||'',srv.capacity||'',srv.used||'',srv.health||'',srv.apps||'',srv.serial||'',srv.warranty_expiry||null,srv.comments||'']);
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
      await pool.query(`INSERT INTO switches (client_id,name,zone,status,model,firmware,ip_address,mac_address,warranty_expiry,comments) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
        [clientIds[idx],sw.name||'',sw.zone||sw.location||'',sw.status||'Online',sw.model||'',sw.firmware||'',sw.ip_address||'',sw.mac||'',sw.warranty_expiry||null,sw.comments||'']);
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
      await pool.query(`INSERT INTO software (client_id, name, vendor, version, license_type, status, expiry_date, warranty_expiry, comments) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
        [clientIds[idx], sw.name||'', sw.vendor||'', sw.version||'', sw.license_type||'', sw.status||'Good', sw.expiry_date||null, sw.warranty_expiry||null, sw.comments||'']);
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
      await pool.query(`INSERT INTO stations (client_id,name,zone,status,make,model,apps,ip_address,install_date,warranty_expiry) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
        [clientIds[idx], s.name||'', s.zone||'', s.status||'Online', s.make||'', s.model||'', s.apps||'', s.ip_address||'', s.install_date||null, s.warranty_expiry||null]);
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
      await pool.query(`INSERT INTO monitors (client_id,name,zone,status,make,model,size,install_date,warranty_expiry) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
        [clientIds[idx], m.name||'', m.zone||'', m.status||'Online', m.make||'', m.model||'', m.size||'', m.install_date||null, m.warranty_expiry||null]);
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
      await pool.query(`INSERT INTO intrusion (client_id,name,zone,status,module,sensor_type,ip_address,warranty_expiry,comments) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
        [clientIds[idx], i.name||'', i.zone||'', i.status||'Online', i.module||'', i.sensor_type||'', i.ip_address||'', i.warranty_expiry||null, i.comments||'']);
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
      await pool.query(`INSERT INTO storage (client_id,name,zone,status,type,make,model,capacity,used,serial,warranty_expiry,comments) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
        [clientIds[idx], s.name||'', s.zone||'', s.status||'Online', s.type||'', s.make||'', s.model||'', s.capacity||'', s.used||'', s.serial||'', s.warranty_expiry||null, s.comments||'']);
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
  const { status, comments, name, zone, tech, reader, lock_type, ip_address, controller_type, door_swing, access_type, anti_passback, install_date, controller_warranty_expiry, reader_warranty_expiry, lock_warranty_expiry } = req.body;
  try {
    const userClientId = req.user.role === 'admin' ? null : req.user.client_id;
    const asset = await pool.query('SELECT name, client_id FROM doors WHERE id=$1', [id]);
    const assetName = asset.rows[0]?.name || id;
    const assetClientId = asset.rows[0]?.client_id;
    const assetClient = await getClientNameById(assetClientId);
    if (req.user.role === 'admin') {
      const query = userClientId ? `UPDATE doors SET name=COALESCE($1,name),zone=COALESCE($2,zone),status=COALESCE($3,status),tech=COALESCE($4,tech),reader=COALESCE($5,reader),lock_type=COALESCE($6,lock_type),ip_address=COALESCE($7,ip_address),controller_type=COALESCE($8,controller_type),door_swing=COALESCE($9,door_swing),access_type=COALESCE($10,access_type),anti_passback=COALESCE($11,anti_passback),install_date=$12,controller_warranty_expiry=$13,reader_warranty_expiry=$14,lock_warranty_expiry=$15,comments=COALESCE($16,comments),updated_at=CURRENT_TIMESTAMP WHERE id=$17 AND client_id=$18` : `UPDATE doors SET name=COALESCE($1,name),zone=COALESCE($2,zone),status=COALESCE($3,status),tech=COALESCE($4,tech),reader=COALESCE($5,reader),lock_type=COALESCE($6,lock_type),ip_address=COALESCE($7,ip_address),controller_type=COALESCE($8,controller_type),door_swing=COALESCE($9,door_swing),access_type=COALESCE($10,access_type),anti_passback=COALESCE($11,anti_passback),install_date=$12,controller_warranty_expiry=$13,reader_warranty_expiry=$14,lock_warranty_expiry=$15,comments=COALESCE($16,comments),updated_at=CURRENT_TIMESTAMP WHERE id=$17`;
      const params = userClientId ? [name,zone,status,tech,reader,lock_type,ip_address,controller_type,door_swing,access_type,anti_passback,install_date,controller_warranty_expiry,reader_warranty_expiry,lock_warranty_expiry,comments,id,userClientId] : [name,zone,status,tech,reader,lock_type,ip_address,controller_type,door_swing,access_type,anti_passback,install_date,controller_warranty_expiry,reader_warranty_expiry,lock_warranty_expiry,comments,id];
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
  const { status, comments, name, zone, make, model, capacity, used, health, apps, serial, warranty_expiry } = req.body;
  try {
    const userClientId = req.user.role === 'admin' ? null : req.user.client_id;
    const asset = await pool.query('SELECT name, client_id FROM servers WHERE id=$1', [id]);
    const assetName = asset.rows[0]?.name || id;
    const assetClientId = asset.rows[0]?.client_id;
    const assetClient = await getClientNameById(assetClientId);
    if (req.user.role === 'admin') {
      const query = userClientId ? 
        `UPDATE servers SET name=COALESCE($1,name),zone=COALESCE($2,zone),status=COALESCE($3,status),make=COALESCE($4,make),model=COALESCE($5,model),capacity=COALESCE($6,capacity),used=COALESCE($7,used),health=COALESCE($8,health),apps=COALESCE($9,apps),serial=COALESCE($10,serial),warranty_expiry=$11,comments=COALESCE($12,comments),updated_at=CURRENT_TIMESTAMP WHERE id=$13 AND client_id=$14` :
        `UPDATE servers SET name=COALESCE($1,name),zone=COALESCE($2,zone),status=COALESCE($3,status),make=COALESCE($4,make),model=COALESCE($5,model),capacity=COALESCE($6,capacity),used=COALESCE($7,used),health=COALESCE($8,health),apps=COALESCE($9,apps),serial=COALESCE($10,serial),warranty_expiry=$11,comments=COALESCE($12,comments),updated_at=CURRENT_TIMESTAMP WHERE id=$13`;
      const params = userClientId ? 
        [name,zone,status,make,model,capacity,used,health,apps,serial,warranty_expiry,comments,id,userClientId] : 
        [name,zone,status,make,model,capacity,used,health,apps,serial,warranty_expiry,comments,id];
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
  const { status, comments, name, zone, type, make, model, capacity, used, serial, warranty_expiry } = req.body;
  try {
    const userClientId = req.user.role === 'admin' ? null : req.user.client_id;
    const asset = await pool.query('SELECT name, client_id FROM storage WHERE id=$1', [id]);
    const assetName = asset.rows[0]?.name || id;
    const assetClientId = asset.rows[0]?.client_id;
    const assetClient = await getClientNameById(assetClientId);
    if (req.user.role === 'admin') {
      const query = userClientId ?
        `UPDATE storage SET name=COALESCE($1,name),zone=COALESCE($2,zone),status=COALESCE($3,status),type=COALESCE($4,type),make=COALESCE($5,make),model=COALESCE($6,model),capacity=COALESCE($7,capacity),used=COALESCE($8,used),serial=COALESCE($9,serial),warranty_expiry=$10,comments=COALESCE($11,comments),updated_at=CURRENT_TIMESTAMP WHERE id=$12 AND client_id=$13` :
        `UPDATE storage SET name=COALESCE($1,name),zone=COALESCE($2,zone),status=COALESCE($3,status),type=COALESCE($4,type),make=COALESCE($5,make),model=COALESCE($6,model),capacity=COALESCE($7,capacity),used=COALESCE($8,used),serial=COALESCE($9,serial),warranty_expiry=$10,comments=COALESCE($11,comments),updated_at=CURRENT_TIMESTAMP WHERE id=$12`;
      const params = userClientId ?
        [name,zone,status,type,make,model,capacity,used,serial,warranty_expiry,comments,id,userClientId] :
        [name,zone,status,type,make,model,capacity,used,serial,warranty_expiry,comments,id];
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
  const { status, comments, name, zone, model, firmware, ip_address, mac, warranty_expiry } = req.body;
  try {
    const userClientId = req.user.role === 'admin' ? null : req.user.client_id;
    const asset = await pool.query('SELECT name, client_id FROM switches WHERE id=$1', [id]);
    const assetName = asset.rows[0]?.name || id;
    const assetClientId = asset.rows[0]?.client_id;
    const assetClient = await getClientNameById(assetClientId);
    if (req.user.role === 'admin') {
      const query = userClientId ? `UPDATE switches SET name=COALESCE($1,name),zone=COALESCE($2,zone),status=COALESCE($3,status),model=COALESCE($4,model),firmware=COALESCE($5,firmware),ip_address=COALESCE($6,ip_address),mac_address=COALESCE($7,mac_address),warranty_expiry=$8,comments=COALESCE($9,comments),updated_at=CURRENT_TIMESTAMP WHERE id=$10 AND client_id=$11` : `UPDATE switches SET name=COALESCE($1,name),zone=COALESCE($2,zone),status=COALESCE($3,status),model=COALESCE($4,model),firmware=COALESCE($5,firmware),ip_address=COALESCE($6,ip_address),mac_address=COALESCE($7,mac_address),warranty_expiry=$8,comments=COALESCE($9,comments),updated_at=CURRENT_TIMESTAMP WHERE id=$10`;
      const params = userClientId ? [name,zone,status,model,firmware,ip_address,mac,warranty_expiry,comments,id,userClientId] : [name,zone,status,model,firmware,ip_address,mac,warranty_expiry,comments,id];
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
  const { status, comments, name, zone, module, sensor_type, ip_address, warranty_expiry } = req.body;
  try {
    const userClientId = req.user.role === 'admin' ? null : req.user.client_id;
    const asset = await pool.query('SELECT name, client_id FROM intrusion WHERE id=$1', [id]);
    const assetName = asset.rows[0]?.name || id;
    const assetClientId = asset.rows[0]?.client_id;
    const assetClient = await getClientNameById(assetClientId);
    let query, params;
    if (req.user.role === 'admin') {
      query = userClientId ?
        'UPDATE intrusion SET name=COALESCE($1,name),zone=COALESCE($2,zone),status=COALESCE($3,status),module=COALESCE($4,module),sensor_type=COALESCE($5,sensor_type),ip_address=COALESCE($6,ip_address),warranty_expiry=$7,comments=COALESCE($8,comments),updated_at=CURRENT_TIMESTAMP WHERE id=$9 AND client_id=$10' :
        'UPDATE intrusion SET name=COALESCE($1,name),zone=COALESCE($2,zone),status=COALESCE($3,status),module=COALESCE($4,module),sensor_type=COALESCE($5,sensor_type),ip_address=COALESCE($6,ip_address),warranty_expiry=$7,comments=COALESCE($8,comments),updated_at=CURRENT_TIMESTAMP WHERE id=$9';
      params = userClientId ?
        [name,zone,status,module,sensor_type,ip_address,warranty_expiry,comments,id,userClientId] :
        [name,zone,status,module,sensor_type,ip_address,warranty_expiry,comments,id];
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
// CSV EXPORTS
// ============================================================
// Built here rather than in the browser (antivirus flagged the old Blob
// downloads). The dashboard calls .../link with its Authorization header and
// gets back a one-time URL (60 s, single use) holding the finished file, then
// navigates to it so the browser does a normal download. Calling the export
// URL itself with an Authorization header returns the CSV directly. Rows are
// scoped exactly like the matching list route; staff may add ?client_id=.
const EXPORT_TYPES = {
  cameras: { table: 'cameras', order: 'zone, name', zoned: true, columns: ['name','zone','status','comments','model','manufacturer','resolution','archiver','ip_address','mac_address','warranty','date_cleaned'] },
  doors: { table: 'doors', order: 'zone,name', zoned: true, columns: ['name','zone','status','tech','reader','lock_type','door_swing','access_type','anti_passback','controller_type','ip_address','install_date','controller_warranty_expiry','reader_warranty_expiry','lock_warranty_expiry','comments'] },
  servers: { table: 'servers', order: 'zone,name', zoned: true, columns: ['name','zone','status','make','model','capacity','used','health','apps','serial','warranty_expiry','comments'] },
  switches: { table: 'switches', order: 'zone,name', zoned: true, columns: ['name','zone','status','model','firmware','ip_address','mac','warranty_expiry','comments'],
    // The CSV header stays 'mac' (what the importer reads); the column is mac_address.
    source: { mac: 'mac_address' } },
  storage: { table: 'storage', order: 'zone,name', zoned: true, columns: ['name','zone','status','type','make','model','capacity','used','serial','warranty_expiry','comments'] },
  intrusion: { table: 'intrusion', order: 'zone,name', zoned: true, columns: ['name','zone','status','module','sensor_type','ip_address','warranty_expiry','comments'] },
  stations: { table: 'stations', order: 'zone,name', zoned: true, columns: ['name','zone','status','make','model','apps','ip_address','install_date','warranty_expiry'] },
  monitors: { table: 'monitors', order: 'zone,name', zoned: true, columns: ['name','zone','status','make','model','size','install_date','warranty_expiry'] },
  software: { table: 'software', order: 'name', zoned: false, columns: ['name','vendor','version','license_type','status','expiry_date','warranty_expiry','comments'] },
  servicerequests: { table: 'service_requests', order: 'created_at DESC', zoned: false, file: 'service-requests', columns: ['sr_id','client','site','subject','category','priority','assigned_to','status','notes','received'] },
};
const EXPORT_LINK_TTL_MS = 60 * 1000;
const exportLinks = new Map(); // token -> { type, template, filename, csv, expires }
const EXPORT_DATE_COLUMNS = new Set(['warranty', 'warranty_expiry', 'controller_warranty_expiry', 'reader_warranty_expiry', 'lock_warranty_expiry', 'install_date', 'expiry_date', 'date_cleaned', 'received']);
const exportJamaicaDate = new Intl.DateTimeFormat('en-CA', { timeZone: 'America/Jamaica', year: 'numeric', month: '2-digit', day: '2-digit' });

// Dates go out as YYYY-MM-DD. pg reads a DATE column as local midnight, so a
// midnight value is that calendar day whatever the server's time zone; any
// other moment is the Jamaica day it falls on. Text that isn't a readable
// date is written unchanged.
function exportDate(v) {
  if (v === null || v === undefined || v === '') return '';
  if (v instanceof Date) {
    if (isNaN(v)) return '';
    if (!v.getHours() && !v.getMinutes() && !v.getSeconds() && !v.getMilliseconds()) {
      return v.getFullYear() + '-' + String(v.getMonth() + 1).padStart(2, '0') + '-' + String(v.getDate()).padStart(2, '0');
    }
    return exportJamaicaDate.format(v);
  }
  return parseExpiryDate(v) || String(v);
}

// A cell starting with = + - @ tab or CR gets a leading apostrophe so
// spreadsheets don't run it as a formula; the dashboard importer strips it.
function csvCell(v) {
  if (v === null || v === undefined) v = '';
  v = String(v);
  if (/^[=+\-@\t\r]/.test(v)) v = "'" + v;
  if (/[",\n\r]/.test(v)) return '"' + v.replace(/"/g, '""') + '"';
  return v;
}
function csvFile(rows) {
  return '﻿' + rows.map(r => r.map(csvCell).join(',')).join('\r\n');
}

async function buildExport(req, type, template) {
  const def = EXPORT_TYPES[type];
  const file = def.file || type;
  if (template) return { filename: file + '-template.csv', csv: csvFile([def.columns]), rows: 0 };
  let clientId = req.user.role === 'admin' ? null : req.user.client_id;
  if (!clientId && !isClientAccount(req) && /^\d+$/.test(String(req.query.client_id || ''))) clientId = Number(req.query.client_id);
  const result = await pool.query(
    `SELECT * FROM ${def.table}${clientId ? ' WHERE client_id=$1' : ''} ORDER BY ${def.order}`,
    clientId ? [clientId] : []
  );
  const rows = def.zoned ? filterByZoneAccess(result.rows, req) : result.rows;
  const out = [def.columns].concat(rows.map(r => def.columns.map(c => {
    const v = r[(def.source && def.source[c]) || c];
    if (EXPORT_DATE_COLUMNS.has(c)) return exportDate(v);
    return v !== null && typeof v === 'object' ? JSON.stringify(v) : v ?? '';
  })));
  const suffix = clientId ? '-' + String(await getClientNameById(clientId)).toLowerCase().replace(/[^a-z0-9]+/g, '') : '';
  return { filename: file + suffix + '-export.csv', csv: csvFile(out), rows: rows.length };
}

function sendCsv(res, filename, csv) {
  res.set('Content-Type', 'text/csv; charset=utf-8');
  res.set('Content-Disposition', `attachment; filename="${filename}"`);
  res.set('Cache-Control', 'no-store');
  res.send(csv);
}

function exportRoutes(template) {
  const path = '/api/export/:type' + (template ? '/template' : '');
  app.get(path + '/link', authMiddleware, async (req, res) => {
    if (!EXPORT_TYPES[req.params.type]) return res.status(404).json({ error: 'Unknown export type' });
    if (!dbConnected && !template) return res.status(503).json({ error: 'DB not connected' });
    try {
      const built = await buildExport(req, req.params.type, template);
      const now = Date.now();
      for (const [t, l] of exportLinks) if (l.expires <= now) exportLinks.delete(t);
      const token = crypto.randomBytes(24).toString('hex');
      exportLinks.set(token, { type: req.params.type, template, filename: built.filename, csv: built.csv, expires: now + EXPORT_LINK_TTL_MS });
      res.json({ url: path.replace(':type', req.params.type) + '?dl=' + token, rows: built.rows, filename: built.filename });
    } catch (err) { res.status(500).json({ error: err.message }); }
  });
  app.get(path, async (req, res, next) => {
    if (!EXPORT_TYPES[req.params.type]) return res.status(404).json({ error: 'Unknown export type' });
    if (req.query.dl === undefined) return next();
    const token = String(req.query.dl);
    const link = exportLinks.get(token);
    exportLinks.delete(token);
    if (!link || link.expires <= Date.now() || link.type !== req.params.type || link.template !== template) {
      return res.status(410).type('text/plain').send('This download link has expired or was already used. Export again from CAMS.');
    }
    sendCsv(res, link.filename, link.csv);
  }, authMiddleware, async (req, res) => {
    if (!dbConnected && !template) return res.status(503).json({ error: 'DB not connected' });
    try {
      const built = await buildExport(req, req.params.type, template);
      sendCsv(res, built.filename, built.csv);
    } catch (err) { res.status(500).json({ error: err.message }); }
  });
}
exportRoutes(false);
exportRoutes(true);

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
    // assigned_to is a comma-separated list; match the name anywhere in it.
    where.push(`${add(val('assigned_to'))} = ANY(regexp_split_to_array(assigned_to, '\\s*,\\s*'))`);
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

// SR-1000..SR-9999 at random, retried until unused; after 20 clashes it
// falls back to SR- and five digits.
async function newSrId() {
  for (let i = 0; i < 20; i++) {
    const srId = `SR-${Math.floor(Math.random() * 9000) + 1000}`;
    if (!(await pool.query('SELECT 1 FROM service_requests WHERE sr_id=$1 LIMIT 1', [srId])).rowCount) return srId;
  }
  return `SR-${Math.floor(Math.random() * 90000) + 10000}`;
}

app.post('/api/service-requests', authMiddleware, async (req, res) => {
  if (!dbConnected) return res.status(503).json({ error: 'DB not connected' });
  const { subject, site, category, priority, body, related_hardware } = req.body;
  const assignees = normaliseAssignedTo(req.body.assigned_to);
  if (assignees.error) return res.status(400).json({ error: assignees.error });
  const assigned_to = assignees.value || 'Unassigned';
  try {
    const srId = await newSrId();
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
      `INSERT INTO service_requests (client_id,sr_id,subject,client,site,category,priority,assigned_to,body,received,created_by,related_hardware) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) RETURNING *`,
      // received is today's date in Jamaica, not the database's (UTC) CURRENT_DATE.
      [clientId, srId, subject, client, site, category, priority, assigned_to, body, jamaicaToday(), req.user.username, JSON.stringify(related_hardware || [])]
    );
    await pool.query('INSERT INTO sr_history (sr_id,time,msg) VALUES ($1,$2,$3)', [result.rows[0].id, new Date().toLocaleTimeString(), 'Created by ' + req.user.username]);
    await logActivity(clientId, req.user.username, 'Created', 'SR ' + srId + ' created for ' + client);
    
    // Shared-mailbox token, not req.user.msToken (which expires after ~1h).
    const msToken = await getValidGraphToken();
    if (!msToken) console.error('Cannot send new-SR email — no Graph token available for the shared mailbox');
    if (msToken) {
      const emailBody = `<h2>New Service Request: ${srId}</h2><p><strong>Client:</strong> ${client}</p><p><strong>Site:</strong> ${site}</p><p><strong>Category:</strong> ${category}</p><p><strong>Priority:</strong> ${priority}</p><p><strong>Assigned To:</strong> ${assigned_to}</p><p><strong>Subject:</strong> ${subject}</p><p><strong>Description:</strong> ${body || 'No description'}</p><hr><p>View in CAMS: <a href="${process.env.APP_URL || "https://e-tech-cams.up.railway.app"}">Open Dashboard</a></p>`;
      await sendEmailNotification('support@e-techsystemsja.com', `[CAMS] New SR: ${srId} — ${subject}`, emailBody, `Bearer ${msToken}`);
      
      await emailNewAssignees(result.rows[0], parseAssignees(assigned_to), priority, msToken);
      await notifyRequestReceived(result.rows[0], msToken);
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
  const { priority, status } = req.body;
  let { notes } = req.body;
  const assignees = normaliseAssignedTo(req.body.assigned_to);
  if (assignees.error) return res.status(400).json({ error: assignees.error });
  const assigned_to = assignees.value; // undefined = leave as is
  const clientId = req.user.role === 'admin' ? null : req.user.client_id;
  try {
    const current = await pool.query('SELECT * FROM service_requests WHERE id=$1', [id]);
    const oldSr = current.rows[0];
    // A client account may only touch its own client's SRs.
    if (isClientAccount(req) && oldSr && oldSr.client_id !== req.user.client_id) return res.status(404).json({ error: 'Service request not found' });
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
    
    const change = assignees.list && oldSr && updateResult.rowCount > 0 ? assignmentChange(oldAssigned, assignees.list, req.user.username) : null;
    if (change && change.msg) {
      await pool.query('INSERT INTO sr_history (sr_id,time,msg) VALUES ($1,$2,$3)', [id, new Date().toLocaleTimeString(), change.msg]);
      if (change.added.length) {
        const msToken = await getValidGraphToken();
        if (!msToken) console.error('Cannot send assigned email — no Graph token available for the shared mailbox');
        await emailNewAssignees(oldSr, change.added, priority, msToken);
        if (msToken) await notifyTechnicianAssigned(oldSr, assigned_to, priority, msToken);
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
        const clientUsersNotified = await notifyClientUsers(sr.client_id, resolvedSubject, reportBody, graphToken);
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
  if (req.user.role !== 'admin' && req.user.role !== 'technician') return res.status(403).json({ error: 'E-Tech staff only' });
  if (!dbConnected) return res.status(503).json({ error: 'DB not connected' });
  const { id } = req.params;
  const assignees = normaliseAssignedTo(req.body.assigned_to);
  if (assignees.error) return res.status(400).json({ error: assignees.error });
  if (!assignees.list) return res.status(400).json({ error: 'assigned_to is required' });
  const assigned_to = assignees.value;
  try {
    const current = await pool.query('SELECT * FROM service_requests WHERE id=$1', [id]);
    if (!current.rows[0]) return res.status(404).json({ error: 'Service request not found' });
    const oldAssigned = current.rows[0].assigned_to;
    await pool.query('UPDATE service_requests SET assigned_to=$1,updated_at=CURRENT_TIMESTAMP WHERE id=$2', [assigned_to, id]);
    const change = assignmentChange(oldAssigned, assignees.list, req.user.username);
    if (change.msg) {
      await pool.query('INSERT INTO sr_history (sr_id,time,msg) VALUES ($1,$2,$3)', [id, new Date().toLocaleTimeString(), change.msg]);
      await logActivity(1, req.user.username, 'Assigned', 'SR ' + id + ' assigned to ' + assigned_to);
    }
    if (change.added.length) {
      const msToken = await getValidGraphToken();
      if (!msToken) console.error('Cannot send assigned email — no Graph token available for the shared mailbox');
      await emailNewAssignees(current.rows[0], change.added, null, msToken);
      if (msToken) await notifyTechnicianAssigned(current.rows[0], assigned_to, null, msToken);
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
    // The dashboard checks this on every load to decide on the walkthrough.
    const me = await pool.query('SELECT * FROM users WHERE id=$1', [req.user.id]);
    res.json({ ...result.rows[0], onboarding_required: onboardingRequired(me.rows[0] || req.user) });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ---- First-login walkthrough ----
// Client users (client_admin / client_user) see it until onboarded_at is set.
function onboardingRequired(u) {
  return (u.role === 'client_admin' || u.role === 'client_user') && !u.onboarded_at;
}

app.post('/api/onboarding/complete', authMiddleware, async (req, res) => {
  if (!isClientAccount(req)) return res.status(403).json({ error: 'Client accounts only' });
  if (!dbConnected) return res.status(503).json({ error: 'DB not connected' });
  if (!req.body || req.body.acknowledged !== true) return res.status(400).json({ error: 'Please confirm you understand how to use CAMS (acknowledged: true).' });
  try {
    // Only the first completion sets the time (and is logged).
    const result = await pool.query('UPDATE users SET onboarded_at=CURRENT_TIMESTAMP WHERE id=$1 AND onboarded_at IS NULL', [req.user.id]);
    if (result.rowCount) await logActivity(req.user.client_id, req.user.email, 'Onboarding', 'Completed CAMS walkthrough');
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/users/:id/reset-onboarding', authMiddleware, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  if (!dbConnected) return res.status(503).json({ error: 'DB not connected' });
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id < 1 || id > 2147483647) return res.status(404).json({ error: 'User not found' });
  try {
    const result = await pool.query('UPDATE users SET onboarded_at=NULL WHERE id=$1 RETURNING email,client_id', [id]);
    if (!result.rows[0]) return res.status(404).json({ error: 'User not found' });
    await logActivity(result.rows[0].client_id, req.user.username, 'Onboarding', `Walkthrough reset for ${result.rows[0].email}`);
    res.json({ success: true });
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
    const result = await pool.query('INSERT INTO clients (name,email,phone,address,logo_url,logo_full_url) VALUES ($1,$2,$3,$4,$5,$6) RETURNING *', [name,email ?? null,phone,address,req.body.logo_url||null,req.body.logo_full_url||null]);
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
  const newName = typeof req.body.name === 'string' ? req.body.name.trim() : req.body.name;
  if (newName !== undefined && !newName) return res.status(400).json({ error: 'Client name is required' });
  const renaming = typeof newName === 'string' && newName !== name;
  // Email and logos only change when their key is in the body, so a normal
  // edit never wipes them.
  const sets = ['phone=$1', 'address=$2'], params = [phone||'', address||''];
  if (Object.prototype.hasOwnProperty.call(req.body, 'email')) { params.push(email||''); sets.push(`email=$${params.length}`); }
  for (const key of LOGO_FIELDS) {
    if (Object.prototype.hasOwnProperty.call(req.body, key)) { params.push(req.body[key] || null); sets.push(`${key}=$${params.length}`); }
  }
  if (renaming) { params.push(newName); sets.push(`name=$${params.length}`); }
  params.push(name);
  // A rename also moves SRs that store the client by name, in one transaction.
  const db = await pool.connect();
  try {
    await db.query('BEGIN');
    if (renaming) {
      const taken = await db.query('SELECT 1 FROM clients WHERE LOWER(name)=LOWER($1) AND name<>$2 LIMIT 1', [newName, name]);
      if (taken.rowCount) { await db.query('ROLLBACK'); return res.status(409).json({ error: 'Another client already has that name' }); }
    }
    const result = await db.query(`UPDATE clients SET ${sets.join(',')},updated_at=CURRENT_TIMESTAMP WHERE name=$${params.length} RETURNING *`, params);
    if (result.rowCount === 0) { await db.query('ROLLBACK'); return res.status(404).json({ error: 'Client not found' }); }
    if (renaming) await db.query('UPDATE service_requests SET client=$1 WHERE client=$2', [newName, name]);
    await db.query('COMMIT');
    await logActivity(1, req.user.username, 'Updated', renaming ? `Client ${name} renamed to ${newName}` : 'Client ' + name + ' updated');
    res.json(result.rows[0]);
  } catch (err) {
    await db.query('ROLLBACK').catch(() => {});
    if (err.code === '23505') return res.status(409).json({ error: 'Another client already has that name' });
    res.status(500).json({ error: err.message });
  } finally { db.release(); }
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
    const activated = await pool.query('SELECT * FROM users WHERE id=$1', [userId]);
    res.json({ token, onboarding_required: onboardingRequired(activated.rows[0]), user: { id: userId, username: invite.email, email: invite.email, client_id: invite.client_id, client_name: clientName, role: invite.role, photo_url: null } });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ---- Forgot password (client accounts) ----
// Same token scheme as invites: the email carries a random token, only its
// SHA-256 is stored. A link lasts an hour and works once; asking again
// replaces any earlier unused link. Resetting signs out older sessions (see
// loadFreshUserPermissions).

const PASSWORD_RESET_MINUTES = 60;
const FORGOT_PASSWORD_MESSAGE = 'If that email has a CAMS account, a reset link is on its way.';

async function sendPasswordResetEmail(user) {
  const { token, tokenHash } = generateInviteToken();
  const expiresAt = new Date(Date.now() + PASSWORD_RESET_MINUTES * 60 * 1000);
  await pool.query('DELETE FROM password_resets WHERE user_id=$1 AND used_at IS NULL', [user.id]);
  await pool.query('INSERT INTO password_resets (user_id, token_hash, expires_at) VALUES ($1, $2, $3)', [user.id, tokenHash, expiresAt]);
  const appUrl = process.env.APP_URL || 'https://e-tech-cams.up.railway.app';
  const link = `${appUrl}/reset-password.html?token=${token}`;
  const expiry = expiresAt.toLocaleString('en-GB', { timeZone: 'America/Jamaica', day: 'numeric', month: 'long', year: 'numeric', hour: 'numeric', minute: '2-digit', hour12: true });
  const body = `<h2>Reset your CAMS password</h2><p>Someone asked to reset the password for <strong>${escapeHtml(user.email)}</strong> on E-Tech's Client Asset Management System.</p><p><a href="${escapeHtml(link)}">Click here to choose a new password</a></p><p>This link expires in 1 hour (${escapeHtml(expiry)}, Jamaica time) and works once.</p><hr><p style="color:#888;font-size:12px;">If you didn't ask for this, ignore this email. Your password won't change.</p>`;
  const graphToken = await getValidGraphToken();
  if (!graphToken) {
    console.error('Cannot send password reset email — no Graph token available for the shared mailbox');
    return false;
  }
  return sendEmailNotification(user.email, '[CAMS] Reset your password', body, `Bearer ${graphToken}`);
}

// Returns { reset } or { status, error } for a reset link token.
async function findPasswordReset(token) {
  const tokenHash = crypto.createHash('sha256').update(String(token)).digest('hex');
  const result = await pool.query(
    `SELECT r.id, r.user_id, r.expires_at, r.used_at, u.email, u.role, u.client_id, u.status
     FROM password_resets r JOIN users u ON u.id = r.user_id WHERE r.token_hash=$1`,
    [tokenHash]
  );
  const reset = result.rows[0];
  if (!reset) return { status: 404, error: 'This reset link was not found. Ask for a new one from the sign-in page.' };
  if (reset.used_at) return { status: 410, error: 'This reset link has already been used. Ask for a new one from the sign-in page.' };
  if (new Date(reset.expires_at) < new Date() || reset.status !== 'active') return { status: 410, error: 'This reset link has expired. Ask for a new one from the sign-in page.' };
  return { reset };
}

// Always the same answer, sent before any lookup, so it never reveals
// whether an email has an account.
app.post('/api/auth/forgot-password', passwordResetRateLimit, async (req, res) => {
  const email = typeof req.body?.email === 'string' ? req.body.email.trim().toLowerCase() : '';
  res.json({ message: FORGOT_PASSWORD_MESSAGE });
  if (!dbConnected || !EMAIL_ADDRESS_RE.test(email)) return;
  try {
    const result = await pool.query("SELECT id, email, client_id FROM users WHERE LOWER(email)=$1 AND status='active'", [email]);
    if (!result.rows[0]) return;
    await sendPasswordResetEmail(result.rows[0]);
    await logActivity(result.rows[0].client_id, result.rows[0].email, 'Password reset', 'Password reset link requested');
  } catch (err) {
    console.error('Forgot password failed:', err.message);
  }
});

app.get('/api/auth/reset-password/:token', passwordResetRateLimit, async (req, res) => {
  if (!dbConnected) return res.status(503).json({ error: 'DB not connected' });
  try {
    const found = await findPasswordReset(req.params.token);
    if (found.error) return res.status(found.status).json({ error: found.error });
    res.json({ email: found.reset.email });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/auth/reset-password/:token', passwordResetRateLimit, async (req, res) => {
  if (!dbConnected) return res.status(503).json({ error: 'DB not connected' });
  const { password } = req.body || {};
  if (typeof password !== 'string' || password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });
  try {
    const found = await findPasswordReset(req.params.token);
    if (found.error) return res.status(found.status).json({ error: found.error });
    const reset = found.reset;
    // Claim the link first so two submissions can't both use it.
    const claim = await pool.query('UPDATE password_resets SET used_at=CURRENT_TIMESTAMP WHERE id=$1 AND used_at IS NULL RETURNING id', [reset.id]);
    if (!claim.rowCount) return res.status(410).json({ error: 'This reset link has already been used. Ask for a new one from the sign-in page.' });
    const passwordHash = await bcrypt.hash(password, 12);
    // Whole seconds, because JWT iat is in seconds: the session issued below
    // is not older than this, so it stays signed in.
    const changedAt = new Date(Math.floor(Date.now() / 1000) * 1000);
    await pool.query('UPDATE users SET password_hash=$1, password_changed_at=$2 WHERE id=$3', [passwordHash, changedAt, reset.user_id]);
    await pool.query('DELETE FROM password_resets WHERE user_id=$1 AND used_at IS NULL', [reset.user_id]);
    await logActivity(reset.client_id, reset.email, 'Password reset', 'Password changed with a reset link');

    const token = jwt.sign({ id: reset.user_id, role: reset.role }, process.env.JWT_SECRET, { expiresIn: '42d' });
    const clientName = await getClientNameById(reset.client_id);
    const user = await pool.query('SELECT * FROM users WHERE id=$1', [reset.user_id]);
    res.json({ token, onboarding_required: onboardingRequired(user.rows[0]), user: { id: reset.user_id, username: reset.email, email: reset.email, client_id: reset.client_id, client_name: clientName, role: reset.role, photo_url: null } });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/users/:id/send-password-reset', authMiddleware, requireAdmin, async (req, res) => {
  const id = parseReportId(req.params.id);
  if (!id) return res.status(404).json({ error: 'User not found' });
  try {
    const result = await pool.query('SELECT id, email, client_id, status FROM users WHERE id=$1', [id]);
    const u = result.rows[0];
    if (!u) return res.status(404).json({ error: 'User not found' });
    if (u.status !== 'active') return res.status(400).json({ error: 'Only active users can be sent a password reset.' });
    if (!(await sendPasswordResetEmail(u))) return res.status(502).json({ error: "Couldn't send the email — check the support mailbox connection." });
    await logActivity(u.client_id, req.user.username, 'Password reset', `Sent a password reset link to ${u.email}`);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ---- E-Tech admin "Users" panel — cross-client ----

app.get('/api/users', authMiddleware, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  if (!dbConnected) return res.json([]);
  try {
    const users = await pool.query(
      `SELECT u.id,u.email,u.role,u.status,u.created_at,u.onboarded_at,u.client_id,c.name AS client_name,
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
  const { status, name, zone, make, model, apps, ip_address, install_date, warranty_expiry } = req.body;
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
      'UPDATE stations SET name=COALESCE($1,name),zone=COALESCE($2,zone),status=COALESCE($3,status),make=COALESCE($4,make),model=COALESCE($5,model),apps=COALESCE($6,apps),ip_address=COALESCE($7,ip_address),install_date=$8,warranty_expiry=$9,updated_at=CURRENT_TIMESTAMP WHERE id=$10 AND client_id=$11' :
      'UPDATE stations SET name=COALESCE($1,name),zone=COALESCE($2,zone),status=COALESCE($3,status),make=COALESCE($4,make),model=COALESCE($5,model),apps=COALESCE($6,apps),ip_address=COALESCE($7,ip_address),install_date=$8,warranty_expiry=$9,updated_at=CURRENT_TIMESTAMP WHERE id=$10';
    const params = userClientId ? [name,zone,status,make,model,apps,ip_address,install_date,warranty_expiry,id,userClientId] : [name,zone,status,make,model,apps,ip_address,install_date,warranty_expiry,id];
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
  const { status, name, zone, make, model, size, install_date, warranty_expiry } = req.body;
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
      'UPDATE monitors SET name=COALESCE($1,name),zone=COALESCE($2,zone),status=COALESCE($3,status),make=COALESCE($4,make),model=COALESCE($5,model),size=COALESCE($6,size),install_date=$7,warranty_expiry=$8,updated_at=CURRENT_TIMESTAMP WHERE id=$9 AND client_id=$10' :
      'UPDATE monitors SET name=COALESCE($1,name),zone=COALESCE($2,zone),status=COALESCE($3,status),make=COALESCE($4,make),model=COALESCE($5,model),size=COALESCE($6,size),install_date=$7,warranty_expiry=$8,updated_at=CURRENT_TIMESTAMP WHERE id=$9';
    const params = userClientId ? [name,zone,status,make,model,size,install_date,warranty_expiry,id,userClientId] : [name,zone,status,make,model,size,install_date,warranty_expiry,id];
    await pool.query(query, params);
    await logActivity(assetClientId || userClientId || 1, req.user.username, 'Updated', `Monitor ${assetName} updated (${assetClient})`);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ============================================================
// MONTHLY REPORTS
// ============================================================

// ============================================================
// MONTHLY REPORTS
// ============================================================
// Every report is built once, saved in `reports` (so it can be viewed,
// printed or re-sent later), then emailed one recipient at a time with a
// `report_deliveries` row per recipient. The scheduled set (1st of the month,
// 5:00 PM Jamaica, covering the previous month) is claimed through a partial
// unique index before anything is sent, so each client gets at most one
// scheduled report per month across restarts and multiple app instances.

const REPORT_TZ = 'America/Jamaica';
const REPORT_HOUR = 17;
const JAMAICA_UTC_OFFSET_HOURS = 5; // Jamaica has no daylight saving: always UTC-5
const MAX_REPORT_ATTEMPTS = 3;
const MAX_REPORT_RECIPIENTS = 20;

// Same statements as migrations/006_reports.sql.
const REPORT_SCHEMA = [
  `CREATE TABLE IF NOT EXISTS reports (
    id SERIAL PRIMARY KEY,
    kind TEXT NOT NULL CHECK (kind IN ('admin', 'client')),
    client_id INTEGER,
    period_start DATE NOT NULL,
    period_end DATE NOT NULL,
    subject TEXT NOT NULL DEFAULT '',
    html TEXT NOT NULL DEFAULT '',
    summary JSONB NOT NULL DEFAULT '{}',
    source TEXT NOT NULL CHECK (source IN ('scheduled', 'manual')),
    created_by TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  )`,
  `CREATE UNIQUE INDEX IF NOT EXISTS reports_one_scheduled_per_month ON reports (kind, COALESCE(client_id, 0), period_start) WHERE source = 'scheduled'`,
  `CREATE INDEX IF NOT EXISTS reports_created_at_idx ON reports (created_at DESC)`,
  `CREATE INDEX IF NOT EXISTS reports_client_idx ON reports (client_id, period_start DESC)`,
  `CREATE TABLE IF NOT EXISTS report_deliveries (
    id SERIAL PRIMARY KEY,
    report_id INTEGER NOT NULL REFERENCES reports(id) ON DELETE CASCADE,
    recipient TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('sent', 'failed')),
    error TEXT,
    attempts INTEGER NOT NULL DEFAULT 1,
    sent_by TEXT,
    last_attempt_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  )`,
  `CREATE UNIQUE INDEX IF NOT EXISTS report_deliveries_report_recipient ON report_deliveries (report_id, recipient)`,
  `CREATE INDEX IF NOT EXISTS report_deliveries_status_idx ON report_deliveries (status, created_at)`,
  `CREATE TABLE IF NOT EXISTS client_report_settings (
    client_id INTEGER PRIMARY KEY REFERENCES clients(id) ON DELETE CASCADE,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    include_users BOOLEAN NOT NULL DEFAULT TRUE,
    excluded_user_ids INTEGER[] NOT NULL DEFAULT '{}',
    extra_recipients TEXT[] NOT NULL DEFAULT '{}',
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  )`,
  `CREATE TABLE IF NOT EXISTS report_admin_settings (
    id INTEGER PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    extra_recipients TEXT[] NOT NULL DEFAULT '{}',
    installed_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  )`,
  // installed_at marks when stored reports began. Catch-up only sends months
  // that fell due after it, so the first deploy doesn't re-send a month the
  // old code already emailed.
  `INSERT INTO report_admin_settings (id) VALUES (1) ON CONFLICT (id) DO NOTHING`,
];

async function runSchema(statements) {
  for (const sql of statements) await pool.query(sql);
}

function ensureReportTables() {
  return runSchema(REPORT_SCHEMA);
}

// Same statements as migrations/007_password_reset_expiry_alerts.sql.
const PASSWORD_RESET_SCHEMA = [
  `CREATE TABLE IF NOT EXISTS password_resets (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TIMESTAMP NOT NULL,
    used_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  )`,
  `CREATE INDEX IF NOT EXISTS password_resets_user_idx ON password_resets (user_id)`,
  `ALTER TABLE users ADD COLUMN IF NOT EXISTS password_changed_at TIMESTAMP`,
];

const EXPIRY_ALERT_SCHEMA = [
  `CREATE TABLE IF NOT EXISTS expiry_alerts_sent (
    id SERIAL PRIMARY KEY,
    asset_table TEXT NOT NULL,
    asset_id INTEGER NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('warranty', 'licence', 'warranty-controller', 'warranty-reader', 'warranty-lock')),
    expiry_date DATE NOT NULL,
    threshold INTEGER NOT NULL CHECK (threshold IN (60, 30)),
    report_id INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (asset_table, asset_id, kind, expiry_date, threshold)
  )`,
  `ALTER TABLE client_report_settings ADD COLUMN IF NOT EXISTS expiry_alerts BOOLEAN NOT NULL DEFAULT TRUE`,
  `ALTER TABLE report_admin_settings ADD COLUMN IF NOT EXISTS expiry_last_run DATE`,
  // reports.kind gains 'expiry' (the daily warranty and licence digests).
  `DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'reports_kind_check' AND pg_get_constraintdef(oid) LIKE '%expiry%') THEN
      ALTER TABLE reports DROP CONSTRAINT IF EXISTS reports_kind_check;
      ALTER TABLE reports ADD CONSTRAINT reports_kind_check CHECK (kind IN ('admin', 'client', 'expiry'));
    END IF;
  END $$`,
  // Door parts are alerted separately (also in migrations/008): a kind CHECK
  // from before the split is replaced with one that allows the part kinds.
  `DO $$
  DECLARE c RECORD; dropped BOOLEAN := FALSE;
  BEGIN
    FOR c IN SELECT conname FROM pg_constraint WHERE conrelid = 'expiry_alerts_sent'::regclass AND contype = 'c'
        AND pg_get_constraintdef(oid) LIKE '%kind%' AND pg_get_constraintdef(oid) NOT LIKE '%warranty-lock%' LOOP
      EXECUTE format('ALTER TABLE expiry_alerts_sent DROP CONSTRAINT %I', c.conname);
      dropped := TRUE;
    END LOOP;
    IF dropped THEN
      ALTER TABLE expiry_alerts_sent ADD CONSTRAINT expiry_alerts_sent_kind_check
        CHECK (kind IN ('warranty', 'licence', 'warranty-controller', 'warranty-reader', 'warranty-lock'));
    END IF;
  END $$`,
];

// Same statements as migrations/008_door_component_warranties.sql. The copy of
// the old single warranty_expiry into the three part columns runs only in the
// run that creates them, so a part cleared later is never refilled; a value
// that isn't a readable YYYY-MM-DD date is left for staff to enter by hand.
const DOOR_WARRANTY_SCHEMA = [
  `DO $$
  DECLARE r RECORD;
  BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'doors' AND column_name = 'controller_warranty_expiry') THEN
      ALTER TABLE doors ADD COLUMN controller_warranty_expiry DATE;
      ALTER TABLE doors ADD COLUMN IF NOT EXISTS reader_warranty_expiry DATE;
      ALTER TABLE doors ADD COLUMN IF NOT EXISTS lock_warranty_expiry DATE;
      FOR r IN SELECT id, substring(warranty_expiry::text from '^[0-9]{4}-[0-9]{1,2}-[0-9]{1,2}') AS w FROM doors
          WHERE warranty_expiry IS NOT NULL AND controller_warranty_expiry IS NULL AND reader_warranty_expiry IS NULL AND lock_warranty_expiry IS NULL LOOP
        CONTINUE WHEN r.w IS NULL;
        BEGIN
          UPDATE doors SET controller_warranty_expiry = r.w::date, reader_warranty_expiry = r.w::date, lock_warranty_expiry = r.w::date WHERE id = r.id;
        EXCEPTION WHEN others THEN NULL;
        END;
      END LOOP;
    END IF;
  END $$`,
  `ALTER TABLE doors ADD COLUMN IF NOT EXISTS reader_warranty_expiry DATE`,
  `ALTER TABLE doors ADD COLUMN IF NOT EXISTS lock_warranty_expiry DATE`,
];

function jamaicaParts(date = new Date()) {
  const parts = {};
  new Intl.DateTimeFormat('en-US', { timeZone: REPORT_TZ, year: 'numeric', month: 'numeric', day: 'numeric', hour: 'numeric', hourCycle: 'h23' })
    .formatToParts(date).forEach(p => { parts[p.type] = Number(p.value); });
  return { year: parts.year, month: parts.month, day: parts.day, hour: parts.hour };
}

// 5:00 PM Jamaica on the 1st of the month after the given one (month is
// 1-based; Date.UTC rolls month 12 over into January).
function monthlyReportDueAt(year, month) {
  return new Date(Date.UTC(year, month, 1, REPORT_HOUR + JAMAICA_UTC_OFFSET_HOURS));
}

function nextMonthlyReportAt(now = new Date()) {
  const j = jamaicaParts(now);
  const thisMonth = monthlyReportDueAt(j.year, j.month - 1);
  return thisMonth > now ? thisMonth : monthlyReportDueAt(j.year, j.month);
}

// A calendar month (month is 1-based). With no arguments it is the previous
// month — e.g. a report sent on the 1st of February covers all of January.
// Date's month arithmetic handles the January/December year rollover.
function getMonthRange(year, month) {
  if (year == null || month == null) {
    const now = new Date();
    year = now.getFullYear();
    month = now.getMonth(); // 0-based current month = 1-based previous month
  }
  const start = new Date(year, month - 1, 1, 0, 0, 0, 0);
  const end = new Date(year, month, 0, 23, 59, 59, 999);
  const pad = n => String(n).padStart(2, '0');
  const y = start.getFullYear(), m = start.getMonth() + 1;
  return { start, end, year: y, month: m, period: `${y}-${pad(m)}`, periodStart: `${y}-${pad(m)}-01`, periodEnd: `${y}-${pad(m)}-${pad(end.getDate())}` };
}

// The month the scheduled reports cover right now: the one before the
// current Jamaica month.
function previousReportPeriod(now = new Date()) {
  const j = jamaicaParts(now);
  return getMonthRange(j.year, j.month - 1);
}

function formatDateRange(start, end) {
  const options = { day: 'numeric', month: 'long', year: 'numeric' };
  return `${start.toLocaleDateString('en-GB', options)} — ${end.toLocaleDateString('en-GB', options)}`;
}

// Lowercased, trimmed and de-duplicated, keeping the first occurrence's order.
function normaliseEmails(list) {
  return [...new Set((list || []).filter(e => typeof e === 'string' && e.trim()).map(e => e.trim().toLowerCase()))];
}

// Returns { emails } or { error } for a list of addresses typed by an admin.
function validateReportEmails(v) {
  if (v != null && !Array.isArray(v) && typeof v !== 'string') return { error: 'Recipients must be a list of email addresses.' };
  const emails = normaliseEmails(parseRecipients(v));
  const bad = emails.filter(a => !EMAIL_ADDRESS_RE.test(a));
  if (bad.length) return { error: `Not a valid email address: ${bad.join(', ')}` };
  if (emails.length > MAX_REPORT_RECIPIENTS) return { error: `Too many addresses — the limit is ${MAX_REPORT_RECIPIENTS}.` };
  return { emails };
}

// A client's monthly report recipients under its settings (no settings row =
// the defaults): nobody if reports are off; otherwise the contact email, the
// client's active users unless include_users is off (minus any excluded
// ones), plus any extra recipients.
async function clientRecipients(clientId) {
  const result = await pool.query(
    `SELECT c.email, s.enabled, s.include_users, s.excluded_user_ids, s.extra_recipients
     FROM clients c LEFT JOIN client_report_settings s ON s.client_id = c.id WHERE c.id = $1`,
    [clientId]
  );
  const row = result.rows[0];
  if (!row || row.enabled === false) return [];
  let users = [];
  if (row.include_users !== false) {
    const u = await pool.query(
      "SELECT DISTINCT LOWER(email) AS email FROM users WHERE client_id=$1 AND status='active' AND id <> ALL($2::int[])",
      [clientId, row.excluded_user_ids || []]
    );
    users = u.rows.map(r => r.email);
  }
  return normaliseEmails([row.email, ...users, ...(row.extra_recipients || [])]);
}

// support@ always gets the admin report, plus any extra recipients.
async function adminReportExtras() {
  const result = await pool.query('SELECT extra_recipients FROM report_admin_settings WHERE id = 1');
  return result.rows[0]?.extra_recipients || [];
}

async function adminRecipients() {
  return normaliseEmails([ADMIN_EMAIL, ...(await adminReportExtras())]);
}

async function buildClientReport(clientId, range) {
  const { start, end } = range;
  const dateRangeStr = formatDateRange(start, end);

  const clientResult = await pool.query('SELECT name FROM clients WHERE id=$1', [clientId]);
  if (!clientResult.rows[0]) throw new Error(`Client ${clientId} not found`);
  const clientName = clientResult.rows[0].name;
  const clientNameHtml = escapeHtml(clientName);

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
      srTable += `<tr><td>${escapeHtml(sr.sr_id)}</td><td>${escapeHtml(sr.subject)}</td><td>${escapeHtml(sr.priority)}</td><td>${escapeHtml(sr.status)}</td><td>${escapeHtml(sr.assigned_to || 'Unassigned')}</td><td>${createdDate}</td></tr>`;
    });
    srTable += '</table>';
  } else {
    srTable = '<p>No service requests were created or updated during this period.</p>';
  }

  const html = `
    <div style="font-family:Arial,sans-serif;max-width:650px;margin:0 auto;">
      <h2 style="color:#1a3a5c;">CAMS Monthly Report</h2>
      <p><strong>Client:</strong> ${clientNameHtml}</p>
      <p><strong>Period:</strong> ${dateRangeStr}</p>
      <hr>
      <p>Dear ${clientNameHtml} Team,</p>
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

  return {
    subject: `[CAMS] Monthly Report — ${clientName} — ${dateRangeStr}`,
    html,
    summary: { clientName, srsCreated, srsResolved, openSRs: openSRs.rows.length, highPriorityOpen, totalAssets, onlineAssets, offlineAssets, healthPct: Number(healthPct) }
  };
}

async function buildAdminReport(range) {
  const { start, end } = range;
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

    clientTable += `<tr><td>${escapeHtml(client.name)}</td><td>${cTotal}</td><td>${cOnline}</td><td>${cOffline}</td><td>${cHealth}%</td><td>${cSRsCreated}</td><td>${cSRsResolved}</td><td>${cOpen}</td></tr>`;

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
      hpTable += `<tr><td>${escapeHtml(sr.sr_id)}</td><td>${escapeHtml(sr.client)}</td><td>${escapeHtml(sr.subject)}</td><td>${escapeHtml(sr.assigned_to || 'Unassigned')}</td><td>${createdDate}</td></tr>`;
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
      activityTable += `<tr><td>${logDate}</td><td>${escapeHtml(log.username)}</td><td>${escapeHtml(log.action)}</td><td>${escapeHtml(log.detail)}</td></tr>`;
    });
    activityTable += '</table>';
  }

  const html = `
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
      ${lowestHealthClient && lowestHealth < 95 ? `<p><strong>${escapeHtml(lowestHealthClient)}</strong> has the lowest asset health at <strong>${lowestHealth}%</strong> and may need additional attention.</p>` : ''}
      ${highPriorityOpen.length > 0 ? `<h3 style="color:#cc0000;">Open High Priority SRs</h3><p>These require immediate action:</p>${hpTable}` : '<p>No high priority SRs are currently open.</p>'}
      ${activityLog.rows.length > 0 ? `<h3 style="color:#1a3a5c;">Notable Activity (Last Month)</h3>${activityTable}` : ''}
      <p>View full dashboard: <a href="${process.env.APP_URL || "https://e-tech-cams.up.railway.app"}">Open CAMS</a></p>
    </div>`;

  return {
    subject: `[CAMS] Monthly Admin Report — ${dateRangeStr}`,
    html,
    summary: { totalClients: clients.length, srsCreated, srsResolved, openSRs: openSRs.rows.length, highPriorityOpen: highPriorityOpen.length, totalAssets, onlineAssets, offlineAssets, healthPct: Number(healthPct) }
  };
}

function buildReport(kind, clientId, range) {
  return kind === 'admin' ? buildAdminReport(range) : buildClientReport(clientId, range);
}

// Sends one stored report to one address. Returns null on success, or the error.
async function sendStoredReport(report, to, token) {
  try {
    if (!token) throw new Error('Shared mailbox not connected');
    await postGraphMail(to, report.subject, report.html, `Bearer ${token}`);
    return null;
  } catch (err) {
    const error = err.response?.data?.error?.message || err.message || 'Send failed';
    console.error(`Report ${report.id} to ${to} failed:`, error);
    return String(error).slice(0, 500);
  }
}

// One email per recipient via the shared mailbox token, recording a delivery
// row for each (a repeat send to the same address updates its row).
async function sendReport(reportId, recipients, sentBy) {
  const result = await pool.query('SELECT id, subject, html FROM reports WHERE id=$1', [reportId]);
  const report = result.rows[0];
  if (!report) throw new Error('Report not found');
  const list = normaliseEmails(recipients);
  const token = list.length ? await getValidGraphToken() : null;
  let sent = 0;
  for (const to of list) {
    const error = await sendStoredReport(report, to, token);
    if (!error) sent++;
    await pool.query(
      `INSERT INTO report_deliveries (report_id, recipient, status, error, attempts, sent_by, last_attempt_at)
       VALUES ($1, $2, $3, $4, 1, $5, CURRENT_TIMESTAMP)
       ON CONFLICT (report_id, recipient) DO UPDATE SET status = EXCLUDED.status, error = EXCLUDED.error,
         attempts = report_deliveries.attempts + 1, sent_by = EXCLUDED.sent_by, last_attempt_at = CURRENT_TIMESTAMP`,
      [report.id, to, error ? 'failed' : 'sent', error, sentBy]
    );
  }
  return { sent, total: list.length };
}

async function saveReport(kind, clientId, range, source, createdBy) {
  const built = await buildReport(kind, clientId, range);
  const result = await pool.query(
    `INSERT INTO reports (kind, client_id, period_start, period_end, subject, html, summary, source, created_by)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id`,
    [kind, clientId, range.periodStart, range.periodEnd, built.subject, built.html, JSON.stringify(built.summary), source, createdBy]
  );
  return { id: result.rows[0].id, ...built };
}

// Scheduled report for one client (or the admin report): claim the month via
// the unique index, build, save, send. Returns null if it was already claimed.
async function runScheduledReport(kind, clientId, range, recipients) {
  const claim = await pool.query(
    `INSERT INTO reports (kind, client_id, period_start, period_end, source, created_by)
     VALUES ($1, $2, $3, $4, 'scheduled', 'Scheduled') ON CONFLICT DO NOTHING RETURNING id`,
    [kind, clientId, range.periodStart, range.periodEnd]
  );
  const id = claim.rows[0]?.id;
  if (!id) return null;
  try {
    const built = await buildReport(kind, clientId, range);
    await pool.query('UPDATE reports SET subject=$2, html=$3, summary=$4 WHERE id=$1', [id, built.subject, built.html, JSON.stringify(built.summary)]);
  } catch (err) {
    // Release the claim so the hourly catch-up can try again.
    await pool.query('DELETE FROM reports WHERE id=$1', [id]).catch(() => {});
    throw err;
  }
  return sendReport(id, recipients, 'Scheduled');
}

let monthlyReportsRunning = false;

// The scheduled monthly set: the admin report, then each client with at
// least one recipient.
async function runMonthlyReports(range = previousReportPeriod()) {
  if (!dbConnected) {
    console.log('⚠️ Reports skipped: DB not connected');
    return { sent: false, reason: 'Database not connected' };
  }
  if (monthlyReportsRunning) return { sent: false, reason: 'Monthly reports are already being sent' };
  monthlyReportsRunning = true;
  console.log(`📊 Running monthly reports for ${range.period}...`);
  let clientsEmailed = 0;
  try {
    try {
      const admin = await runScheduledReport('admin', null, range, await adminRecipients());
      if (admin) console.log(`✅ Admin report sent to ${admin.sent} of ${admin.total} recipient(s)`);
    } catch (err) {
      console.error('❌ Admin report failed:', err.message);
    }
    const clients = await pool.query('SELECT id,name FROM clients ORDER BY id');
    for (const client of clients.rows) {
      try {
        const recipients = await clientRecipients(client.id);
        if (!recipients.length) continue;
        const result = await runScheduledReport('client', client.id, range, recipients);
        if (!result) continue;
        clientsEmailed++;
        console.log(`✅ Client report for ${client.name} sent to ${result.sent} of ${result.total} recipient(s)`);
      } catch (err) {
        console.error(`❌ Client report for ${client.name} failed:`, err.message);
      }
    }
    console.log('✅ Monthly reports completed');
    return { sent: true, clientsEmailed };
  } catch (err) {
    console.error('❌ Report generation failed:', err.message);
    return { sent: false, reason: err.message };
  } finally {
    monthlyReportsRunning = false;
  }
}

// After 5:00 PM on the 1st (Jamaica), sends the previous month's scheduled
// reports if they haven't gone yet — e.g. the app was down at 5:00 PM. Only
// months that fell due after stored reports began are caught up.
async function catchUpMonthlyReports(now = new Date()) {
  const range = previousReportPeriod(now);
  const dueAt = monthlyReportDueAt(range.year, range.month);
  if (now < dueAt) return;
  const check = await pool.query(
    `SELECT (SELECT installed_at FROM report_admin_settings WHERE id = 1) AS installed_at,
            EXISTS (SELECT 1 FROM reports WHERE source='scheduled' AND kind='admin' AND period_start=$1) AS done`,
    [range.periodStart]
  );
  const { installed_at, done } = check.rows[0];
  if (done || !installed_at || new Date(installed_at) > dueAt) return;
  console.log(`⏰ Catching up the ${range.period} monthly reports`);
  await runMonthlyReports(range);
}

// Re-sends failed deliveries from the last 48 hours, up to MAX_REPORT_ATTEMPTS
// attempts in all. Each row is claimed by bumping its attempt count first, so
// two app instances never send the same retry. Waits while the mailbox is
// disconnected rather than using up attempts.
async function retryFailedReportDeliveries() {
  const token = await getValidGraphToken();
  if (!token) return;
  const due = await pool.query(
    `SELECT d.id, d.attempts, d.recipient, r.id AS report_id, r.subject, r.html
     FROM report_deliveries d JOIN reports r ON r.id = d.report_id
     WHERE d.status = 'failed' AND d.attempts < $1 AND d.created_at > CURRENT_TIMESTAMP - INTERVAL '48 hours'
     ORDER BY d.id`,
    [MAX_REPORT_ATTEMPTS]
  );
  for (const d of due.rows) {
    const claim = await pool.query(
      "UPDATE report_deliveries SET attempts = attempts + 1, last_attempt_at = CURRENT_TIMESTAMP WHERE id=$1 AND status='failed' AND attempts=$2 RETURNING id",
      [d.id, d.attempts]
    );
    if (!claim.rowCount) continue;
    const error = await sendStoredReport({ id: d.report_id, subject: d.subject, html: d.html }, d.recipient, token);
    await pool.query('UPDATE report_deliveries SET status=$2, error=$3 WHERE id=$1', [d.id, error ? 'failed' : 'sent', error]);
  }
}

// ============================================================
// WARRANTY & LICENCE EXPIRY ALERTS
// ============================================================
// Daily from 8:00 AM Jamaica (the hourly checker below, so a missed 8:00 is
// caught up): any item whose warranty or licence is 60 or fewer days away
// gets one alert at 60 days and one at 30, each recorded in
// expiry_alerts_sent against that expiry date — so a changed date starts
// fresh. An item already inside a window gets only its most urgent
// threshold; expired items get nothing. Alerts go out as one digest per
// client plus one staff digest, saved in `reports` as kind 'expiry' and sent
// with sendReport (so deliveries, retries and resends work like reports).

const EXPIRY_HOUR = 8;
const EXPIRY_WINDOW_DAYS = 60;
const EXPIRY_SOURCES = [
  { table: 'cameras', type: 'Camera', column: 'warranty', kind: 'warranty' },
  { table: 'doors', type: 'Door', column: 'controller_warranty_expiry', kind: 'warranty-controller', part: 'controller' },
  { table: 'doors', type: 'Door', column: 'reader_warranty_expiry', kind: 'warranty-reader', part: 'reader' },
  { table: 'doors', type: 'Door', column: 'lock_warranty_expiry', kind: 'warranty-lock', part: 'lock' },
  { table: 'servers', type: 'Server', column: 'warranty_expiry', kind: 'warranty' },
  { table: 'switches', type: 'Switch', column: 'warranty_expiry', kind: 'warranty' },
  { table: 'storage', type: 'Storage device', column: 'warranty_expiry', kind: 'warranty' },
  { table: 'intrusion', type: 'Intrusion point', column: 'warranty_expiry', kind: 'warranty' },
  { table: 'stations', type: 'Station', column: 'warranty_expiry', kind: 'warranty' },
  { table: 'monitors', type: 'Monitor', column: 'warranty_expiry', kind: 'warranty' },
  { table: 'software', type: 'Software', column: 'expiry_date', kind: 'licence' },
  { table: 'software', type: 'Software', column: 'warranty_expiry', kind: 'warranty' },
];

function ymdString(y, m, d) {
  const date = new Date(Date.UTC(y, m - 1, d));
  if (y < 1900 || y > 2200 || date.getUTCFullYear() !== y || date.getUTCMonth() !== m - 1 || date.getUTCDate() !== d) return null;
  return `${y}-${String(m).padStart(2, '0')}-${String(d).padStart(2, '0')}`;
}

// 'YYYY-MM-DD' from a date or timestamp column, or text typed in as
// 2027-03-12, 12/03/2027 (day first unless that's impossible) or
// 12 March 2027. Anything else is null.
function parseExpiryDate(value) {
  const s = String(value).trim();
  let m = /^(\d{4})[-/.](\d{1,2})[-/.](\d{1,2})(?:$|[T\s])/.exec(s);
  if (m) return ymdString(+m[1], +m[2], +m[3]);
  m = /^(\d{1,2})[-/.](\d{1,2})[-/.](\d{4})$/.exec(s);
  if (m) return +m[2] > 12 ? ymdString(+m[3], +m[1], +m[2]) : ymdString(+m[3], +m[2], +m[1]);
  if (/[a-z]{3}/i.test(s) && /\d{4}/.test(s)) {
    const t = new Date(s);
    if (!isNaN(t)) return ymdString(t.getFullYear(), t.getMonth() + 1, t.getDate());
  }
  return null;
}

function daysUntil(fromYmd, toYmd) {
  return Math.round((Date.parse(toYmd + 'T00:00:00Z') - Date.parse(fromYmd + 'T00:00:00Z')) / 86400000);
}

function jamaicaToday(now = new Date()) {
  const j = jamaicaParts(now);
  return ymdString(j.year, j.month, j.day);
}

function formatYmd(ymd) {
  return new Date(ymd + 'T12:00:00Z').toLocaleDateString('en-GB', { timeZone: 'UTC', day: 'numeric', month: 'long', year: 'numeric' });
}

// Every warranty and licence date that parses, with days left from today.
// Rows are read as JSON so a missing column or a text date never breaks it.
async function loadExpiryItems(today) {
  const clients = await pool.query('SELECT id, name FROM clients');
  const clientNames = Object.fromEntries(clients.rows.map(c => [c.id, c.name]));
  const rowsByTable = {};
  const items = [];
  let skipped = 0;
  for (const src of EXPIRY_SOURCES) {
    if (!rowsByTable[src.table]) {
      try {
        rowsByTable[src.table] = (await pool.query(`SELECT to_jsonb(t) AS r FROM ${src.table} t`)).rows.map(x => x.r);
      } catch (err) {
        console.error(`⚠️ Expiry check could not read ${src.table}:`, err.message);
        rowsByTable[src.table] = [];
      }
    }
    for (const r of rowsByTable[src.table]) {
      const raw = r[src.column];
      if (raw == null || String(raw).trim() === '') continue;
      const expiry = parseExpiryDate(raw);
      if (!expiry) { skipped++; continue; }
      items.push({
        asset_table: src.table, asset_id: r.id, client_id: r.client_id ?? null,
        client_name: clientNames[r.client_id] || r.client || 'Unknown client',
        name: (r.name || `${src.type} #${r.id}`) + (src.part ? ` — ${src.part} warranty` : ''), type: src.type, site: r.zone || r.site || '',
        kind: src.kind, expiry_date: expiry, days_left: daysUntil(today, expiry)
      });
    }
  }
  if (skipped) console.log(`⚠️ Expiry check skipped ${skipped} date${skipped === 1 ? '' : 's'} it couldn't read`);
  return { items, skipped };
}

function sortExpiryItems(items) {
  return items.sort((a, b) => a.days_left - b.days_left || a.client_name.localeCompare(b.client_name) || a.name.localeCompare(b.name));
}

function expiryTableHtml(items) {
  let html = `<table border="1" cellpadding="8" cellspacing="0" style="border-collapse:collapse;width:100%;margin-top:12px;">
      <tr style="background:#f0f0f0;"><th>Name</th><th>Type</th><th>Site</th><th>Expiring</th><th>Expiry date</th><th>Days left</th></tr>`;
  for (const i of items) {
    html += `<tr><td>${escapeHtml(i.name)}</td><td>${escapeHtml(i.type)}</td><td>${escapeHtml(i.site || '—')}</td><td>${i.kind === 'licence' ? 'Licence' : 'Warranty'}</td><td>${escapeHtml(formatYmd(i.expiry_date))}</td><td>${i.days_left === 0 ? 'Today' : i.days_left}</td></tr>`;
  }
  return html + '</table>';
}

function buildExpiryDigest(clientName, items, today) {
  const appUrl = process.env.APP_URL || 'https://e-tech-cams.up.railway.app';
  let body;
  if (clientName) {
    body = `<p><strong>Client:</strong> ${escapeHtml(clientName)}</p>
      <p>These warranties and licences expire soon:</p>
      ${expiryTableHtml(items)}`;
  } else {
    const groups = {};
    for (const i of items) (groups[i.client_name] = groups[i.client_name] || []).push(i);
    body = `<p>Warranties and licences reaching 60 or 30 days left today, across all clients:</p>` +
      Object.keys(groups).sort((a, b) => a.localeCompare(b)).map(name => `<h3 style="color:#1a3a5c;">${escapeHtml(name)}</h3>${expiryTableHtml(groups[name])}`).join('');
  }
  const html = `
    <div style="font-family:Arial,sans-serif;max-width:650px;margin:0 auto;">
      <h2 style="color:#1a3a5c;">Warranty &amp; licence reminders</h2>
      <p><strong>Date:</strong> ${escapeHtml(formatYmd(today))}</p>
      ${body}
      <p>Contact E-Tech to discuss renewals.</p>
      <p>View full dashboard: <a href="${escapeHtml(appUrl)}">Open CAMS</a></p>
      <p style="color:#666;font-size:12px;">— E-Tech Systems Support</p>
    </div>`;
  return {
    subject: `[CAMS] Warranty & licence reminders — ${clientName || 'All clients'}`,
    html,
    summary: { date: today, items: items.length, warranty: items.filter(i => i.kind !== 'licence').length, licence: items.filter(i => i.kind === 'licence').length }
  };
}

// Saves a scheduled expiry digest (claimed through the unique index, so one
// per client per day) and sends it. Returns the report id, or null.
async function saveExpiryDigest(clientId, clientName, items, today, recipients) {
  const built = buildExpiryDigest(clientName, items, today);
  const claim = await pool.query(
    `INSERT INTO reports (kind, client_id, period_start, period_end, subject, html, summary, source, created_by)
     VALUES ('expiry', $1, $2, $2, $3, $4, $5, 'scheduled', 'Scheduled') ON CONFLICT DO NOTHING RETURNING id`,
    [clientId, today, built.subject, built.html, JSON.stringify(built.summary)]
  );
  const id = claim.rows[0]?.id;
  if (!id) return null;
  await sendReport(id, recipients, 'Scheduled');
  return id;
}

let expiryAlertsRunning = false;

async function runExpiryAlerts(now = new Date()) {
  if (!dbConnected || expiryAlertsRunning || jamaicaParts(now).hour < EXPIRY_HOUR) return null;
  const today = jamaicaToday(now);
  // Claim today, so the check runs once a day across restarts and instances.
  const claim = await pool.query(
    'UPDATE report_admin_settings SET expiry_last_run=$1 WHERE id=1 AND (expiry_last_run IS NULL OR expiry_last_run < $1::date) RETURNING id',
    [today]
  );
  if (!claim.rowCount) return null;
  expiryAlertsRunning = true;
  try {
    const { items } = await loadExpiryItems(today);
    const inWindow = items.filter(i => i.days_left >= 0 && i.days_left <= EXPIRY_WINDOW_DAYS);
    const already = await pool.query(
      "SELECT asset_table, asset_id, kind, to_char(expiry_date, 'YYYY-MM-DD') AS expiry_date, threshold FROM expiry_alerts_sent WHERE expiry_date >= $1::date",
      [today]
    );
    const key = (i, t) => [i.asset_table, i.asset_id, i.kind, i.expiry_date, t].join('|');
    const sentKeys = new Set(already.rows.map(r => key(r, r.threshold)));
    // A door alert sent before the per-part split covers each part with that date.
    for (const r of already.rows) {
      if (r.asset_table === 'doors' && r.kind === 'warranty') {
        for (const k of ['warranty-controller', 'warranty-reader', 'warranty-lock']) sentKeys.add(key({ ...r, kind: k }, r.threshold));
      }
    }
    const due = sortExpiryItems(inWindow.filter(i => !sentKeys.has(key(i, i.days_left <= 30 ? 30 : 60))));
    if (!due.length) return { items: 0 };

    const byClient = {};
    for (const i of due) if (i.client_id != null) (byClient[i.client_id] = byClient[i.client_id] || []).push(i);
    const optedOut = new Set((await pool.query('SELECT client_id FROM client_report_settings WHERE expiry_alerts = FALSE')).rows.map(r => r.client_id));
    let clientDigests = 0;
    for (const clientId of Object.keys(byClient).map(Number)) {
      if (optedOut.has(clientId)) continue;
      try {
        const recipients = await clientRecipients(clientId);
        if (!recipients.length) continue;
        if (await saveExpiryDigest(clientId, byClient[clientId][0].client_name, byClient[clientId], today, recipients)) clientDigests++;
      } catch (err) {
        console.error(`❌ Expiry digest for client ${clientId} failed:`, err.message);
      }
    }
    const staffReportId = await saveExpiryDigest(null, null, due, today, await adminRecipients());

    // Record the alert; an item that went straight to 30 days also counts as
    // alerted at 60, so it never gets a late 60-day alert.
    for (const i of due) {
      const thresholds = i.days_left <= 30 ? [30, 60] : [60];
      for (const t of thresholds) {
        await pool.query(
          `INSERT INTO expiry_alerts_sent (asset_table, asset_id, kind, expiry_date, threshold, report_id)
           VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT DO NOTHING`,
          [i.asset_table, i.asset_id, i.kind, i.expiry_date, t, staffReportId]
        );
      }
    }
    console.log(`✅ Expiry alerts: ${due.length} item(s), ${clientDigests} client digest(s)`);
    return { items: due.length, clientDigests };
  } finally {
    expiryAlertsRunning = false;
  }
}

async function runReportMaintenance() {
  if (!dbConnected) return;
  try {
    await catchUpMonthlyReports();
  } catch (err) {
    console.error('❌ Monthly report catch-up failed:', err.message);
  }
  try {
    await runExpiryAlerts();
  } catch (err) {
    console.error('❌ Expiry alerts failed:', err.message);
  }
  try {
    await retryFailedReportDeliveries();
  } catch (err) {
    console.error('❌ Report retries failed:', err.message);
  }
}

// 5:00 PM Jamaica time on the 1st of every month — by then the previous
// calendar month has fully ended.
cron.schedule('0 17 1 * *', () => {
  runMonthlyReports();
}, {
  timezone: REPORT_TZ
});

// Hourly: catch up a missed monthly send and retry failed deliveries.
cron.schedule('0 * * * *', () => {
  runReportMaintenance();
}, {
  timezone: REPORT_TZ
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
// state -> { verifier, expires }: each sign-in started here must come back
// with its own state within 10 minutes. In memory: a rare, one-off action.
const pendingGraphAuth = new Map();
const GRAPH_AUTH_TTL_MS = 10 * 60 * 1000;
function graphAuthPage(title, message) {
  return `<html><body style="font-family:sans-serif;padding:40px;"><h2>${escapeHtml(title)}</h2>${message ? `<p>${escapeHtml(message)}</p>` : ''}</body></html>`;
}

// Visit this URL directly (no manual URL-building needed) to start connecting
// the shared mailbox. Generates the required PKCE challenge and redirects to
// Microsoft automatically.
app.get('/api/admin/graph-auth/start', (req, res) => {
  const verifier = base64URLEncode(crypto.randomBytes(32));
  const state = base64URLEncode(crypto.randomBytes(24));
  const now = Date.now();
  for (const [s, p] of pendingGraphAuth) if (p.expires <= now) pendingGraphAuth.delete(s);
  pendingGraphAuth.set(state, { verifier, expires: now + GRAPH_AUTH_TTL_MS });
  const challenge = base64URLEncode(crypto.createHash('sha256').update(verifier).digest());
  const redirectUri = `${req.protocol}://${req.get('host')}/api/admin/graph-auth/callback`;
  const authUrl = `https://login.microsoftonline.com/${MS_TENANT_ID_SERVER}/oauth2/v2.0/authorize?` +
    `client_id=${MS_CLIENT_ID_SERVER}&response_type=code&redirect_uri=${encodeURIComponent(redirectUri)}` +
    `&scope=${encodeURIComponent(GRAPH_SCOPES)}&response_mode=query` +
    `&code_challenge=${challenge}&code_challenge_method=S256&state=${encodeURIComponent(state)}`;
  res.redirect(authUrl);
});

app.get('/api/admin/graph-auth/callback', async (req, res) => {
  const { code, error, error_description, state } = req.query;
  const redirectUri = `${req.protocol}://${req.get('host')}/api/admin/graph-auth/callback`;

  const pending = typeof state === 'string' ? pendingGraphAuth.get(state) : null;
  if (pending) pendingGraphAuth.delete(state);
  if (!pending || pending.expires <= Date.now()) {
    return res.status(400).send(graphAuthPage('❌ Sign-in link expired or invalid', 'Start connecting the mailbox again.'));
  }
  if (error) {
    return res.send(graphAuthPage('❌ Microsoft returned an error', `${error}: ${error_description || ''}`));
  }
  if (!code) {
    return res.send(graphAuthPage('No authorization code received'));
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
        code_verifier: pending.verifier
      }),
      { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
    );
    const { access_token, refresh_token, expires_in } = response.data;
    if (!refresh_token) {
      return res.send(graphAuthPage('⚠️ No refresh_token returned', 'Make sure the sign-in request included the offline_access scope.'));
    }
    // Only the shared mailbox's own tokens are saved.
    const me = (await axios.get('https://graph.microsoft.com/v1.0/me', { headers: { Authorization: `Bearer ${access_token}` } })).data;
    const signedIn = String(me?.mail || me?.userPrincipalName || '').trim().toLowerCase();
    if (signedIn !== SHARED_MAILBOX.toLowerCase()) {
      return res.status(403).send(graphAuthPage(`Sign in as ${SHARED_MAILBOX}`, `You signed in as ${signedIn || 'an unknown account'}. Nothing was saved.`));
    }
    await saveGraphAuth(access_token, refresh_token, expires_in);
    res.send(graphAuthPage('✅ Shared mailbox connected', 'Reports will now refresh their own Graph access automatically. You can close this tab.'));
  } catch (err) {
    res.send(graphAuthPage('❌ Token exchange failed', err.response?.data?.error_description || err.message));
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

async function graphAuthStatus() {
  const stored = await getStoredGraphAuth();
  if (!stored || !stored.access_token) return { connected: false };
  return { connected: true, expiresAt: stored.expires_at, hasRefreshToken: !!stored.refresh_token };
}

app.get('/api/admin/graph-auth/status', authMiddleware, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  res.json(await graphAuthStatus());
});

// ============================================================
// REPORTS API
// ============================================================

function requireAdmin(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  next();
}

function parseReportId(v) {
  return /^\d{1,9}$/.test(String(v)) ? Number(v) : null;
}

function reportPeriodLabel(range) {
  return range.start.toLocaleDateString('en-GB', { month: 'long', year: 'numeric' });
}

const REPORT_STATUS_SQL = `CASE WHEN COALESCE(d.total, 0) = 0 THEN 'not_sent' WHEN d.sent = d.total THEN 'sent' WHEN d.sent = 0 THEN 'failed' ELSE 'partial' END`;
const REPORT_STATUSES = ['sent', 'partial', 'failed', 'not_sent'];

async function loadReport(id) {
  const result = await pool.query(
    `SELECT r.id, r.kind, r.client_id, c.name AS client_name, to_char(r.period_start, 'YYYY-MM-DD') AS period_start,
            to_char(r.period_end, 'YYYY-MM-DD') AS period_end, r.subject, r.html, r.summary, r.source, r.created_by, r.created_at
     FROM reports r LEFT JOIN clients c ON c.id = r.client_id WHERE r.id = $1`,
    [id]
  );
  if (!result.rows[0]) return null;
  const deliveries = await pool.query(
    'SELECT id, recipient, status, error, attempts, sent_by, last_attempt_at, created_at FROM report_deliveries WHERE report_id=$1 ORDER BY created_at, id',
    [id]
  );
  return { ...result.rows[0], deliveries: deliveries.rows };
}

// Manual reports for one past month: the admin report and/or the given
// clients, each saved and, if send is set, emailed to its current recipients.
async function generateReports({ range, clients, includeAdmin, send, createdBy, skipClientsWithoutRecipients }) {
  const created = [];
  if (includeAdmin) {
    const report = await saveReport('admin', null, range, 'manual', createdBy);
    const delivery = send ? await sendReport(report.id, await adminRecipients(), createdBy) : null;
    created.push({ ...report, kind: 'admin', client_id: null, client_name: null, period_start: range.periodStart, delivery });
  }
  for (const client of clients) {
    const recipients = await clientRecipients(client.id);
    if (skipClientsWithoutRecipients && !recipients.length) continue;
    const report = await saveReport('client', client.id, range, 'manual', createdBy);
    const delivery = send ? await sendReport(report.id, recipients, createdBy) : null;
    created.push({ ...report, kind: 'client', client_id: client.id, client_name: client.name, period_start: range.periodStart, delivery });
  }
  return created;
}

app.get('/api/reports', authMiddleware, requireAdmin, async (req, res) => {
  const where = [], params = [];
  const { month, kind, client_id, status } = req.query;
  if (month) {
    if (!/^\d{4}-(0[1-9]|1[0-2])$/.test(month)) return res.status(400).json({ error: 'month must be YYYY-MM' });
    params.push(`${month}-01`); where.push(`period_start = $${params.length}::date`);
  }
  if (kind) {
    if (!['admin', 'client', 'expiry'].includes(kind)) return res.status(400).json({ error: 'kind must be admin, client or expiry' });
    params.push(kind); where.push(`kind = $${params.length}`);
  }
  if (client_id) {
    const id = parseReportId(client_id);
    if (!id) return res.status(400).json({ error: 'Invalid client_id' });
    params.push(id); where.push(`client_id = $${params.length}`);
  }
  if (status) {
    if (!REPORT_STATUSES.includes(status)) return res.status(400).json({ error: 'Invalid status' });
    params.push(status); where.push(`status = $${params.length}`);
  }
  const page = Math.max(1, parseInt(req.query.page, 10) || 1);
  const pageSize = Math.min(100, Math.max(1, parseInt(req.query.page_size, 10) || 25));
  params.push(pageSize, (page - 1) * pageSize);
  try {
    const result = await pool.query(
      `SELECT *, COUNT(*) OVER()::int AS full_count FROM (
         SELECT r.id, r.kind, r.client_id, c.name AS client_name, r.period_start, to_char(r.period_start, 'YYYY-MM-DD') AS period,
                r.subject, r.source, r.created_by, r.created_at, COALESCE(d.sent, 0)::int AS sent, COALESCE(d.total, 0)::int AS total,
                ${REPORT_STATUS_SQL} AS status
         FROM reports r
         LEFT JOIN clients c ON c.id = r.client_id
         LEFT JOIN (SELECT report_id, COUNT(*) AS total, COUNT(*) FILTER (WHERE status = 'sent') AS sent FROM report_deliveries GROUP BY report_id) d ON d.report_id = r.id
       ) x ${where.length ? 'WHERE ' + where.join(' AND ') : ''}
       ORDER BY created_at DESC, id DESC LIMIT $${params.length - 1} OFFSET $${params.length}`,
      params
    );
    const total = result.rows[0]?.full_count || 0;
    const reports = result.rows.map(({ full_count, period_start, period, ...r }) => ({ ...r, period_start: period }));
    res.json({ reports, total, page, pageSize });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/reports/overview', authMiddleware, requireAdmin, async (req, res) => {
  try {
    const last = await pool.query(
      `SELECT to_char(period_start, 'YYYY-MM-DD') AS period_start, MIN(created_at) AS at FROM reports
       WHERE source = 'scheduled' AND kind IN ('admin', 'client') GROUP BY period_start ORDER BY period_start DESC LIMIT 1`
    );
    let lastReport = null;
    if (last.rows[0]) {
      const counts = await pool.query(
        `SELECT COUNT(*)::int AS total, COUNT(*) FILTER (WHERE d.status = 'sent')::int AS sent, COUNT(*) FILTER (WHERE d.status = 'failed')::int AS failed
         FROM report_deliveries d JOIN reports r ON r.id = d.report_id WHERE r.source = 'scheduled' AND r.kind IN ('admin', 'client') AND r.period_start = $1::date`,
        [last.rows[0].period_start]
      );
      lastReport = { ...last.rows[0], ...counts.rows[0] };
    }
    const failures = await pool.query(
      `SELECT COUNT(*)::int AS failures_30d,
              COUNT(*) FILTER (WHERE d.last_attempt_at > CURRENT_TIMESTAMP - INTERVAL '7 days')::int AS failures_7d,
              COUNT(*) FILTER (WHERE d.last_attempt_at > CURRENT_TIMESTAMP - INTERVAL '7 days' AND r.source = 'scheduled')::int AS scheduled_failures_7d
       FROM report_deliveries d JOIN reports r ON r.id = d.report_id
       WHERE d.status = 'failed' AND d.last_attempt_at > CURRENT_TIMESTAMP - INTERVAL '30 days'`
    );
    res.json({
      last: lastReport,
      next_at: nextMonthlyReportAt().toISOString(),
      mailbox: await graphAuthStatus(),
      ...failures.rows[0]
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/reports/generate', authMiddleware, requireAdmin, async (req, res) => {
  const { period, client_ids, include_admin, send } = req.body || {};
  const m = /^(\d{4})-(0[1-9]|1[0-2])$/.exec(String(period || ''));
  if (!m || Number(m[1]) < 2000) return res.status(400).json({ error: 'Pick a month (YYYY-MM).' });
  const now = jamaicaParts();
  if (Number(m[1]) * 12 + Number(m[2]) >= now.year * 12 + now.month) {
    return res.status(400).json({ error: 'Reports can only be made for a month that has ended.' });
  }
  try {
    let clients = [];
    if (client_ids === 'all') {
      clients = (await pool.query('SELECT id, name FROM clients ORDER BY name')).rows;
    } else if (Array.isArray(client_ids)) {
      const ids = [...new Set(client_ids.map(parseReportId))];
      if (ids.some(id => !id)) return res.status(400).json({ error: 'Invalid client id.' });
      clients = ids.length ? (await pool.query('SELECT id, name FROM clients WHERE id = ANY($1::int[]) ORDER BY name', [ids])).rows : [];
      if (clients.length !== ids.length) return res.status(400).json({ error: 'Unknown client id.' });
    } else if (client_ids != null) {
      return res.status(400).json({ error: "client_ids must be a list of ids or 'all'." });
    }
    if (!clients.length && include_admin !== true) return res.status(400).json({ error: 'Choose at least one client or the admin report.' });

    const range = getMonthRange(Number(m[1]), Number(m[2]));
    const reports = await generateReports({ range, clients, includeAdmin: include_admin === true, send: send === true, createdBy: req.user.username });
    const names = reports.map(r => r.kind === 'admin' ? 'admin' : r.client_name).join(', ');
    const failed = reports.reduce((n, r) => n + (r.delivery ? r.delivery.total - r.delivery.sent : 0), 0);
    await logActivity(1, req.user.username, 'Report', `${send === true ? 'Generated and sent' : 'Generated (not sent)'} ${reportPeriodLabel(range)} report${reports.length === 1 ? '' : 's'}: ${names}` + (failed ? ` — ${failed} deliver${failed === 1 ? 'y' : 'ies'} failed` : ''));
    res.json({ reports });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Every warranty or licence expiring within 60 days, across all clients.
app.get('/api/reports/expiring', authMiddleware, requireAdmin, async (req, res) => {
  try {
    const { items, skipped } = await loadExpiryItems(jamaicaToday());
    res.json({ items: sortExpiryItems(items.filter(i => i.days_left >= 0 && i.days_left <= EXPIRY_WINDOW_DAYS)), skipped });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/reports/:id', authMiddleware, requireAdmin, async (req, res) => {
  const id = parseReportId(req.params.id);
  if (!id) return res.status(404).json({ error: 'Report not found' });
  try {
    const report = await loadReport(id);
    if (!report) return res.status(404).json({ error: 'Report not found' });
    res.json(report);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/reports/:id/send', authMiddleware, requireAdmin, async (req, res) => {
  const id = parseReportId(req.params.id);
  if (!id) return res.status(404).json({ error: 'Report not found' });
  const { mode, extra } = req.body || {};
  if (!['all', 'failed', 'extra'].includes(mode)) return res.status(400).json({ error: "mode must be 'all', 'failed' or 'extra'" });
  try {
    const report = await loadReport(id);
    if (!report) return res.status(404).json({ error: 'Report not found' });
    let recipients;
    if (mode === 'extra') {
      const v = validateReportEmails(extra);
      if (v.error) return res.status(400).json({ error: v.error });
      recipients = v.emails;
    } else if (mode === 'failed') {
      recipients = report.deliveries.filter(d => d.status === 'failed').map(d => d.recipient);
    } else {
      // Everyone it went to before; a report never sent goes to the current recipients.
      recipients = report.deliveries.length ? report.deliveries.map(d => d.recipient)
        : report.client_id ? await clientRecipients(report.client_id) : await adminRecipients();
    }
    if (!recipients.length) return res.status(400).json({ error: mode === 'failed' ? 'No failed recipients to retry.' : 'No recipients to send to.' });
    const result = await sendReport(id, recipients, req.user.username);
    const label = mode === 'failed' ? 'Resent failed deliveries of' : mode === 'extra' ? 'Sent' : report.deliveries.length ? 'Resent' : 'Sent';
    await logActivity(report.client_id || 1, req.user.username, 'Report', `${label} "${report.subject}"${mode === 'extra' ? ' to ' + recipients.join(', ') : ''} — ${result.sent} of ${result.total} sent`);
    res.json({ ...result, report: await loadReport(id) });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Kept for existing callers: the previous month's admin report and every
// client with recipients, generated and sent like a manual report.
app.post('/api/reports/run', authMiddleware, requireAdmin, async (req, res) => {
  try {
    const clients = (await pool.query('SELECT id, name FROM clients ORDER BY id')).rows;
    const range = previousReportPeriod();
    const reports = await generateReports({ range, clients, includeAdmin: true, send: true, createdBy: req.user.username, skipClientsWithoutRecipients: true });
    const clientsEmailed = reports.filter(r => r.kind === 'client').length;
    const failed = reports.reduce((n, r) => n + r.delivery.total - r.delivery.sent, 0);
    await logActivity(1, req.user.username, 'Report', `Generated and sent ${reportPeriodLabel(range)} reports: admin + ${clientsEmailed} client(s)` + (failed ? ` — ${failed} deliver${failed === 1 ? 'y' : 'ies'} failed` : ''));
    if (!failed) {
      res.json({ success: true, message: `Reports actually sent to admin + ${clientsEmailed} client(s)` });
    } else {
      res.status(200).json({ success: false, message: 'Some reports were NOT sent', reason: `${failed} deliver${failed === 1 ? 'y' : 'ies'} failed — they are retried hourly; see Tools → Reports` });
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

async function loadClientReportSettings(clientId) {
  const result = await pool.query(
    `SELECT c.id, c.name, c.email, s.enabled, s.include_users, s.excluded_user_ids, s.extra_recipients, s.expiry_alerts
     FROM clients c LEFT JOIN client_report_settings s ON s.client_id = c.id WHERE c.id = $1`,
    [clientId]
  );
  const row = result.rows[0];
  if (!row) return null;
  const users = await pool.query("SELECT id, email, role FROM users WHERE client_id=$1 AND status='active' ORDER BY LOWER(email)", [clientId]);
  return {
    client_id: row.id, client_name: row.name, contact_email: row.email || '',
    enabled: row.enabled !== false, include_users: row.include_users !== false, expiry_alerts: row.expiry_alerts !== false,
    excluded_user_ids: row.excluded_user_ids || [], extra_recipients: row.extra_recipients || [],
    users: users.rows, recipients: await clientRecipients(clientId)
  };
}

async function loadAdminReportSettings() {
  return { always: [ADMIN_EMAIL], extra_recipients: await adminReportExtras(), recipients: await adminRecipients() };
}

app.get('/api/report-settings/admin', authMiddleware, requireAdmin, async (req, res) => {
  try { res.json(await loadAdminReportSettings()); } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/report-settings/admin', authMiddleware, requireAdmin, async (req, res) => {
  const v = validateReportEmails((req.body || {}).extra_recipients);
  if (v.error) return res.status(400).json({ error: v.error });
  const extras = v.emails.filter(e => e !== ADMIN_EMAIL.toLowerCase());
  try {
    await pool.query(
      `INSERT INTO report_admin_settings (id, extra_recipients, updated_at) VALUES (1, $1, CURRENT_TIMESTAMP)
       ON CONFLICT (id) DO UPDATE SET extra_recipients = $1, updated_at = CURRENT_TIMESTAMP`,
      [extras]
    );
    await logActivity(1, req.user.username, 'Report', `Admin report extra recipients set to ${extras.length ? extras.join(', ') : 'none'}`);
    res.json(await loadAdminReportSettings());
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/report-settings/:clientId', authMiddleware, requireAdmin, async (req, res) => {
  const id = parseReportId(req.params.clientId);
  if (!id) return res.status(404).json({ error: 'Client not found' });
  try {
    const settings = await loadClientReportSettings(id);
    if (!settings) return res.status(404).json({ error: 'Client not found' });
    res.json(settings);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/report-settings/:clientId', authMiddleware, requireAdmin, async (req, res) => {
  const id = parseReportId(req.params.clientId);
  if (!id) return res.status(404).json({ error: 'Client not found' });
  const { enabled, include_users, excluded_user_ids, extra_recipients, expiry_alerts } = req.body || {};
  if (typeof enabled !== 'boolean' || typeof include_users !== 'boolean') return res.status(400).json({ error: 'enabled and include_users must be true or false.' });
  if (expiry_alerts != null && typeof expiry_alerts !== 'boolean') return res.status(400).json({ error: 'expiry_alerts must be true or false.' });
  if (excluded_user_ids != null && (!Array.isArray(excluded_user_ids) || excluded_user_ids.some(u => !parseReportId(u)))) {
    return res.status(400).json({ error: 'excluded_user_ids must be a list of user ids.' });
  }
  const v = validateReportEmails(extra_recipients);
  if (v.error) return res.status(400).json({ error: v.error });
  try {
    const client = await pool.query('SELECT name FROM clients WHERE id=$1', [id]);
    if (!client.rows[0]) return res.status(404).json({ error: 'Client not found' });
    const excluded = [...new Set((excluded_user_ids || []).map(Number))];
    await pool.query(
      `INSERT INTO client_report_settings (client_id, enabled, include_users, excluded_user_ids, extra_recipients, expiry_alerts, updated_at)
       VALUES ($1, $2, $3, $4, $5, COALESCE($6, TRUE), CURRENT_TIMESTAMP)
       ON CONFLICT (client_id) DO UPDATE SET enabled = $2, include_users = $3, excluded_user_ids = $4, extra_recipients = $5,
         expiry_alerts = COALESCE($6, client_report_settings.expiry_alerts), updated_at = CURRENT_TIMESTAMP`,
      [id, enabled, include_users, excluded, v.emails, typeof expiry_alerts === 'boolean' ? expiry_alerts : null]
    );
    const settings = await loadClientReportSettings(id);
    await logActivity(id, req.user.username, 'Report', `Monthly report recipients for ${client.rows[0].name} updated: ` +
      (enabled ? `${settings.recipients.length} recipient${settings.recipients.length === 1 ? '' : 's'}` : 'reports turned off'));
    res.json(settings);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Client logins: their own client's reports that reached at least one
// recipient. No delivery details or addresses.
const MY_REPORTS_SQL = `SELECT r.id, to_char(r.period_start, 'YYYY-MM-DD') AS period_start, to_char(r.period_end, 'YYYY-MM-DD') AS period_end,
    r.kind, r.subject, r.created_at%s
  FROM reports r
  WHERE r.kind IN ('client', 'expiry') AND r.client_id = $1
    AND EXISTS (SELECT 1 FROM report_deliveries d WHERE d.report_id = r.id AND d.status = 'sent')`;

app.get('/api/my-reports', authMiddleware, async (req, res) => {
  if (!isClientAccount(req)) return res.status(403).json({ error: 'Not authorized' });
  try {
    const result = await pool.query(MY_REPORTS_SQL.replace('%s', '') + ' ORDER BY r.period_start DESC, r.created_at DESC', [req.user.client_id]);
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/my-reports/:id', authMiddleware, async (req, res) => {
  if (!isClientAccount(req)) return res.status(403).json({ error: 'Not authorized' });
  const id = parseReportId(req.params.id);
  if (!id) return res.status(404).json({ error: 'Report not found' });
  try {
    const result = await pool.query(MY_REPORTS_SQL.replace('%s', ', r.html') + ' AND r.id = $2', [req.user.client_id, id]);
    if (!result.rows[0]) return res.status(404).json({ error: 'Report not found' });
    res.json(result.rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
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
