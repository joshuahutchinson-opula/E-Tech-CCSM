// ============================================================
// CCSM BACKEND — Full API
// ============================================================

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const path = require('path');
require('dotenv').config();

const app = express();
app.set('trust proxy', 1);
const PORT = process.env.PORT || 3000;

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  console.error('❌ FATAL: JWT_SECRET environment variable is not set. Refusing to start.');
  console.error('   Set JWT_SECRET in Railway → Variables before deploying.');
  process.exit(1);
}

const pool = process.env.DATABASE_URL
  ? new Pool({
      connectionString: process.env.DATABASE_URL,
      ssl: { rejectUnauthorized: false },
      max: 20,
      idleTimeoutMillis: 30000,
      connectionTimeoutMillis: 2000,
    })
  : new Pool({
      host: process.env.DB_HOST || 'localhost',
      port: process.env.DB_PORT || 5432,
      user: process.env.DB_USER || 'postgres',
      password: process.env.DB_PASSWORD || 'postgres',
      database: process.env.DB_NAME || 'ccsm',
      max: 20,
      idleTimeoutMillis: 30000,
      connectionTimeoutMillis: 2000,
    });

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'"],
      scriptSrcAttr: ["'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://cdn.jsdelivr.net", "https://fonts.gstatic.com", "data:"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'", "https:"],
    },
  },
}));

app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: '10mb' }));

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  trustProxy: true,
  message: { error: 'Too many requests, please try again later.' }
});
app.use('/api/', limiter);

const authenticate = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'No token provided' });
  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ error: 'Invalid token' });
  }
};

function requireRole(...allowedRoles) {
  return (req, res, next) => {
    if (!req.user || !req.user.role) return res.status(403).json({ error: 'No role on token' });
    if (!allowedRoles.includes(req.user.role)) return res.status(403).json({ error: 'Insufficient permissions' });
    next();
  };
}

// ── DATABASE INIT ─────────────────────────────────────────
async function initDatabase() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        role VARCHAR(20) DEFAULT 'Technician',
        email VARCHAR(100),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
      CREATE TABLE IF NOT EXISTS cameras (
        id SERIAL PRIMARY KEY, name VARCHAR(100) NOT NULL, zone VARCHAR(50), status VARCHAR(20) DEFAULT 'Unknown',
        ip_address VARCHAR(15), username VARCHAR(50), model VARCHAR(100), resolution VARCHAR(50),
        comments TEXT, last_seen TIMESTAMP, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(name, ip_address)
      );
      CREATE TABLE IF NOT EXISTS doors (
        id SERIAL PRIMARY KEY, name VARCHAR(100) NOT NULL UNIQUE, site VARCHAR(100), client VARCHAR(20),
        reader VARCHAR(100), lock_type VARCHAR(50), powered VARCHAR(20), status VARCHAR(20) DEFAULT 'Offline',
        tech VARCHAR(50), ip_address VARCHAR(15), controller VARCHAR(100), last_service VARCHAR(50),
        history JSONB DEFAULT '[]', created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
      CREATE TABLE IF NOT EXISTS servers (
        id SERIAL PRIMARY KEY, location VARCHAR(100), serial VARCHAR(50) NOT NULL UNIQUE, capacity VARCHAR(20),
        used VARCHAR(20), health VARCHAR(100), apps TEXT, status VARCHAR(20) DEFAULT 'ONLINE',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
      CREATE TABLE IF NOT EXISTS switches (
        id SERIAL PRIMARY KEY, name VARCHAR(100) NOT NULL UNIQUE, location VARCHAR(100), model VARCHAR(100),
        ip_address VARCHAR(15), firmware VARCHAR(20), username VARCHAR(50), password VARCHAR(100), mac VARCHAR(20),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
      CREATE TABLE IF NOT EXISTS tickets (
        id VARCHAR(20) PRIMARY KEY, client VARCHAR(20), site VARCHAR(100), subject VARCHAR(255) NOT NULL,
        from_email VARCHAR(100), category VARCHAR(50), priority VARCHAR(20) DEFAULT 'Medium', status VARCHAR(20) DEFAULT 'Open',
        assigned VARCHAR(50), received VARCHAR(50), body TEXT, notes TEXT, hardware JSONB DEFAULT '[]',
        history JSONB DEFAULT '[]', attachments JSONB DEFAULT '[]',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
      CREATE TABLE IF NOT EXISTS audit_logs (
        id SERIAL PRIMARY KEY, time VARCHAR(20), username VARCHAR(50), action VARCHAR(50), target TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
      CREATE TABLE IF NOT EXISTS emails (
        id VARCHAR(20) PRIMARY KEY, from_name VARCHAR(100), from_email VARCHAR(100), to_email VARCHAR(100),
        subject VARCHAR(255), body TEXT, date VARCHAR(50), attachments JSONB DEFAULT '[]',
        is_sr BOOLEAN DEFAULT false, sr_linked VARCHAR(20), urgent BOOLEAN DEFAULT false, client VARCHAR(20),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
      CREATE TABLE IF NOT EXISTS dashboard_snapshots (
        id SERIAL PRIMARY KEY, snapshot_date DATE NOT NULL UNIQUE, cameras_defective INT, doors_offline INT,
        servers_online INT, servers_total INT, switches_online INT, switches_total INT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    const adminCheck = await pool.query("SELECT * FROM users WHERE username = 'admin'");
    if (adminCheck.rows.length === 0) {
      const hashed = await bcrypt.hash('admin123', 10);
      await pool.query("INSERT INTO users (username, password_hash, role, email) VALUES ($1, $2, $3, $4)", ['admin', hashed, 'Administrator', 'admin@etechsystems.com']);
      console.log('✅ Default admin created: admin / admin123');
    }
    console.log('✅ Database initialized');
  } catch (error) {
    console.error('❌ Database init error:', error);
  }
}

// ── SEED DATA ─────────────────────────────────────────────
async function seedData() {
  try {
    const camerasCheck = await pool.query("SELECT COUNT(*) FROM cameras");
    if (parseInt(camerasCheck.rows[0].count) === 0) {
      console.log('🌱 Seeding cameras...');
      const cameras = [
        ['HM3 PTZ','NORTH','Defective','172.17.102.218','admin','Pelco P2820-ESR','1920x1080 (2MP)',''],
        ['HM4 PTZ','NORTH','Online','172.17.102.219','admin','Pelco P2820-ESR','1920x1080 (2MP)',''],
        ['B3 PTZ','SOUTH','Online','10.19.1.110','root','AXIS Q6075-E','1080p',''],
        ['D4 PTZ','SOUTH','Online','10.19.1.120','root','AXIS Q6075-E','1080p',''],
        ['A7 PTZ','SOUTH','Online','10.19.1.130','root','AXIS Q6075-E','1080p','']
      ];
      for (const cam of cameras) {
        await pool.query(`INSERT INTO cameras (name, zone, status, ip_address, username, model, resolution, comments) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT (name, ip_address) DO NOTHING`, cam);
      }
      console.log('✅ Cameras seeded');
    }

    const doorsCheck = await pool.query("SELECT COUNT(*) FROM doors");
    if (parseInt(doorsCheck.rows[0].count) === 0) {
      console.log('🌱 Seeding doors...');
      const doors = [
        ['Second Entrance Staff Entrance 2','Second Entrance','KFTL','eyeLock (Biometric)','Turnstile','Not In Use','Offline','Marvin Grant','10.19.1.100','eyeLock Panel 2','6/3/2026'],
        ['Second Entrance Staff Exit 1','Second Entrance','KFTL','eyeLock (Biometric)','Turnstile','Not In Use','Offline','Marvin Grant','10.19.1.101','eyeLock Panel 1','6/3/2026'],
        ['Second Entrance Staff Entrance 1','Second Entrance','KFTL','eyeLock (Biometric)','Turnstile','Not In Use','Offline','Marvin Grant','10.19.1.102','eyeLock Panel 3','6/3/2026'],
        ['Second Entrance Staff Exit 2','Second Entrance','KFTL','eyeLock (Biometric)','Turnstile','Not In Use','Offline','Marvin Grant','10.19.1.103','eyeLock Panel 4','6/3/2026']
      ];
      for (const door of doors) {
        await pool.query(`INSERT INTO doors (name, site, client, reader, lock_type, powered, status, tech, ip_address, controller, last_service, history) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::jsonb) ON CONFLICT (name) DO NOTHING`, [...door.slice(0,11), '[{"date":"Jun 18, 2026","event":"Reader replacement","tech":"Marvin Grant"}]']);
      }
      console.log('✅ Doors seeded');
    }

    const serversCheck = await pool.query("SELECT COUNT(*) FROM servers");
    if (parseInt(serversCheck.rows[0].count) === 0) {
      console.log('🌱 Seeding servers...');
      const servers = [
        ['Kingport','J1013DDR','6.11TB','1.4TB','Good (23%)','Ocularis DM5, LPR','ONLINE'],
        ['Kingport','J1013DDV','6.11TB','1.4TB','Good, Failed drive','Ocularis DM6, Eyelock','ONLINE'],
        ['Kingport','J1013DDX','45TB','178GB','Excellent','—','ONLINE']
      ];
      for (const srv of servers) {
        await pool.query(`INSERT INTO servers (location, serial, capacity, used, health, apps, status) VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (serial) DO NOTHING`, srv);
      }
      console.log('✅ Servers seeded');
    }

    const switchesCheck = await pool.query("SELECT COUNT(*) FROM switches");
    if (parseInt(switchesCheck.rows[0].count) === 0) {
      console.log('🌱 Seeding switches...');
      const switches = [
        ['Main Entrance','Security Office','AXIS T8508','10.19.1.21','6.54.2739','root','$upp@rt@202O','AC:CC:8E:FA:4B:1B'],
        ['2nd entrance','SAL Duty Office','AXIS T8516','10.19.1.23','6.54.2739','root','$upp@rt@202O','AC:CC:8E:B6:DF:99']
      ];
      for (const sw of switches) {
        await pool.query(`INSERT INTO switches (name, location, model, ip_address, firmware, username, password, mac) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT (name) DO NOTHING`, sw);
      }
      console.log('✅ Switches seeded');
    }

    const ticketsCheck = await pool.query("SELECT COUNT(*) FROM tickets");
    if (parseInt(ticketsCheck.rows[0].count) === 0) {
      console.log('🌱 Seeding tickets...');
      const tickets = [
        ['SR-1847','KFTL','NORTH Zone','Replace defective cameras','facilities@kftl.com','Camera','High','Open','Shanice Vernon','Jun 13, 2026','Camera replacements needed.','','[]','[{"time":"14:22","msg":"Created"}]','[]'],
        ['SR-1848','KWL','Tinson Pen','Firmware check needed','security@kwl.com','Network','Medium','Open','Shanice Vernon','Jun 15, 2026','Firmware check needed.','','[]','[{"time":"11:05","msg":"Created"}]','[]'],
        ['SR-1849','KFTL','Second Entrance','Turnstiles offline','it@kftl.com','Access Control','High','In Progress','Marvin Grant','Jun 10, 2026','All turnstiles offline.','','[]','[{"time":"16:48","msg":"Created"}]','[]'],
        ['SR-1850','KFTL','Kingport','Server failed drive','marvin.grant@etechsystems.com','Server','Medium','Open','Shavine','Jun 8, 2026','Failed drive on J1013DDV.','','[]','[{"time":"09:12","msg":"Created"}]','[]']
      ];
      for (const ticket of tickets) {
        await pool.query(`INSERT INTO tickets (id, client, site, subject, from_email, category, priority, status, assigned, received, body, notes, hardware, history, attachments) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13::jsonb,$14::jsonb,$15::jsonb)`, ticket);
      }
      console.log('✅ Tickets seeded');
    }

    const auditCheck = await pool.query("SELECT COUNT(*) FROM audit_logs");
    if (parseInt(auditCheck.rows[0].count) === 0) {
      console.log('🌱 Seeding audit logs...');
      const auditEntries = [
        ['14:32','Shanice Vernon','updated','SR-1847 → In Progress'],
        ['13:50','Marvin Grant','updated','HM3 PTZ comment → Defective'],
        ['12:00','System','converted','David Chen → SR-1848'],
        ['11:30','System','sync','Camera_Maintenance_2025.csv ✅'],
        ['10:45','System','sync','Access_Control_Survey.csv ⚠️']
      ];
      for (const entry of auditEntries) {
        await pool.query(`INSERT INTO audit_logs (time, username, action, target) VALUES ($1,$2,$3,$4)`, entry);
      }
      console.log('✅ Audit logs seeded');
    }

    const emailsCheck = await pool.query("SELECT COUNT(*) FROM emails");
    if (parseInt(emailsCheck.rows[0].count) === 0) {
      console.log('🌱 Seeding emails...');
      const emails = [
        ['e1','David Chen','facilities@kftl.com','support@etechsystems.com','Replace defective cameras - NORTH zone','We need camera replacements in NORTH zone.','Jun 15, 2026 14:22','[]',true,'SR-1847',true,'KFTL'],
        ['e2','Andrea Williams','security@kwl.com','support@etechsystems.com','URGENT: 5 Cameras Offline','5 cameras down at Tinson Pen.','Jun 15, 2026 11:05','[]',true,'SR-1848',true,'KWL'],
        ['e3','IT Department','it@kftl.com','support@etechsystems.com','ASAP: Access Doors Offline','All turnstiles offline.','Jun 14, 2026 16:48','[]',true,'SR-1849',true,'KFTL'],
        ['e4','Marvin Grant','marvin.grant@etechsystems.com','support@etechsystems.com','Server drive failure follow-up','Swapped bad drive on J1013DDV.','Jun 8, 2026 09:30','[]',true,'SR-1850',false,'KFTL']
      ];
      for (const email of emails) {
        await pool.query(`INSERT INTO emails (id, from_name, from_email, to_email, subject, body, date, attachments, is_sr, sr_linked, urgent, client) VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9,$10,$11,$12) ON CONFLICT (id) DO NOTHING`, email);
      }
      console.log('✅ Emails seeded');
    }

    console.log('✅ Seed data complete');
  } catch (error) {
    console.error('❌ Seed error:', error);
  }
}

// ═══════════════════════════════════════════════════════════
// ── ROUTES ────────────────────────────────────────────────
// ═══════════════════════════════════════════════════════════

// ── AUTH ─────────────────────────────────────────────────
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    if (result.rows.length === 0) return res.status(401).json({ error: 'Invalid credentials' });
    const user = result.rows[0];
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(401).json({ error: 'Invalid credentials' });
    const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '24h' });
    res.json({ token, user: { id: user.id, username: user.username, role: user.role, email: user.email } });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ── MICROSOFT OAUTH TOKEN EXCHANGE ──────────────────────
app.post('/api/auth/microsoft', async (req, res) => {
  try {
    const { code } = req.body;
    if (!code) return res.status(400).json({ error: 'Authorization code required' });

    const clientId = process.env.MS_CLIENT_ID || 'e87a6592-aaa5-4a13-9c85-8dbc8e9cd7b2';
    const redirectUri = process.env.MS_REDIRECT_URI || 'https://e-tech-ccsm-production-19f0.up.railway.app';
    const tenantId = process.env.MS_TENANT_ID || '799ae988-9d3d-40d3-bf5c-93197f5d8d44';

    const tokenResponse = await fetch(
      `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/token`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          client_id: clientId,
          scope: 'https://graph.microsoft.com/Sites.Read.All Files.Read.All User.Read',
          code: code,
          redirect_uri: redirectUri,
          grant_type: 'authorization_code'
        }).toString()
      }
    );

    const data = await tokenResponse.json();
    if (data.error) {
      console.error('Token exchange error:', data);
      return res.status(400).json({ error: data.error_description || data.error });
    }

    res.json(data);
  } catch (error) {
    console.error('Microsoft auth proxy error:', error);
    res.status(500).json({ error: 'Token exchange failed' });
  }
});

// ── SHAREPOINT INTEGRATION ──────────────────────────────
function getFileType(filename) {
  const ext = filename.split('.').pop().toLowerCase();
  const types = { csv: 'csv', xlsx: 'xlsx', xls: 'xlsx', docx: 'docx', doc: 'docx', pdf: 'pdf', txt: 'txt', jpg: 'image', jpeg: 'image', png: 'image' };
  return types[ext] || 'file';
}

function formatFileSize(bytes) {
  if (!bytes) return '—';
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / 1048576).toFixed(1) + ' MB';
}

async function fetchSharePointFiles(accessToken) {
  try {
    const siteResponse = await fetch(
      'https://graph.microsoft.com/v1.0/sites/etechsystemsltd.sharepoint.com:/sites/Share',
      { headers: { Authorization: 'Bearer ' + accessToken } }
    );
    const siteData = await siteResponse.json();

    const driveResponse = await fetch(
      'https://graph.microsoft.com/v1.0/sites/' + siteData.id + '/drives',
      { headers: { Authorization: 'Bearer ' + accessToken } }
    );
    const drives = await driveResponse.json();
    const documentsDrive = drives.value.find(function(d) { return d.name === 'Documents'; });

    const folderPath = '/E-Tech Maintenance';
    const childrenResponse = await fetch(
      'https://graph.microsoft.com/v1.0/drives/' + documentsDrive.id + '/root:' + encodeURIComponent(folderPath) + ':/children',
      { headers: { Authorization: 'Bearer ' + accessToken } }
    );
    const folderData = await childrenResponse.json();

    const allFiles = [];
    for (let i = 0; i < folderData.value.length; i++) {
      const item = folderData.value[i];
      if (item.folder) {
        const subResponse = await fetch(
          'https://graph.microsoft.com/v1.0/drives/' + documentsDrive.id + '/items/' + item.id + '/children',
          { headers: { Authorization: 'Bearer ' + accessToken } }
        );
        const subData = await subResponse.json();
        for (let j = 0; j < subData.value.length; j++) {
          const file = subData.value[j];
          if (!file.folder) {
            allFiles.push({
              name: file.name,
              type: getFileType(file.name),
              size: formatFileSize(file.size),
              modified: new Date(file.lastModifiedDateTime).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' }),
              downloadUrl: file['@microsoft.graph.downloadUrl'],
              client: item.name,
              status: 'synced'
            });
          }
        }
      } else {
        allFiles.push({
          name: item.name,
          type: getFileType(item.name),
          size: formatFileSize(item.size),
          modified: new Date(item.lastModifiedDateTime).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' }),
          downloadUrl: item['@microsoft.graph.downloadUrl'],
          client: 'Root',
          status: 'synced'
        });
      }
    }
    return allFiles;
  } catch (error) {
    console.error('SharePoint fetch error:', error);
    return null;
  }
}

app.get('/api/sharepoint/sync', authenticate, async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    const graphToken = authHeader ? authHeader.split(' ')[1] : null;
    if (!graphToken) return res.status(401).json({ error: 'Microsoft Graph token required' });

    const files = await fetchSharePointFiles(graphToken);
    if (!files) return res.status(500).json({ error: 'Failed to fetch SharePoint files' });

    res.json({ data: files, count: files.length });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/sharepoint/file', authenticate, async (req, res) => {
  try {
    const { url } = req.query;
    if (!url) return res.status(400).json({ error: 'File URL required' });

    const authHeader = req.headers.authorization;
    const graphToken = authHeader ? authHeader.split(' ')[1] : null;

    const fileResponse = await fetch(url, { headers: { Authorization: 'Bearer ' + graphToken } });
    const contentType = fileResponse.headers.get('content-type') || '';
    const text = await fileResponse.text();

    res.json({ data: text, contentType });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ── CAMERAS ─────────────────────────────────────────────
app.get('/api/cameras', authenticate, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM cameras ORDER BY zone, name');
    res.json({ data: result.rows });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/cameras/:name', authenticate, async (req, res) => {
  try {
    const { name } = req.params;
    const { comments, status, model, resolution } = req.body;
    const fields = []; const values = []; let counter = 1;
    if (comments !== undefined) { fields.push('comments = $' + counter); values.push(comments); counter++; }
    if (status !== undefined) { fields.push('status = $' + counter); values.push(status); counter++; }
    if (model !== undefined) { fields.push('model = $' + counter); values.push(model); counter++; }
    if (resolution !== undefined) { fields.push('resolution = $' + counter); values.push(resolution); counter++; }
    fields.push('updated_at = CURRENT_TIMESTAMP');
    values.push(name);
    await pool.query('UPDATE cameras SET ' + fields.join(', ') + ' WHERE name = $' + counter, values);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ── DOORS ─────────────────────────────────────────────────
app.get('/api/doors', authenticate, async (req, res) => {
  try {
    const result = await pool.query('SELECT *, lock_type AS lock, ip_address AS ip, last_service AS date FROM doors ORDER BY site, name');
    res.json({ data: result.rows });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/doors/:name', authenticate, async (req, res) => {
  try {
    const { name } = req.params;
    const { status, tech } = req.body;
    if (status !== undefined) await pool.query('UPDATE doors SET status = $1, updated_at = CURRENT_TIMESTAMP WHERE name = $2', [status, name]);
    if (tech !== undefined) await pool.query('UPDATE doors SET tech = $1, updated_at = CURRENT_TIMESTAMP WHERE name = $2', [tech, name]);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ── SERVERS ──────────────────────────────────────────────
app.get('/api/servers', authenticate, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM servers ORDER BY location, serial');
    res.json({ data: result.rows });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ── SWITCHES ─────────────────────────────────────────────
app.get('/api/switches', authenticate, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM switches ORDER BY location, name');
    const masked = result.rows.map(function(row) { return { ...row, password: row.password ? '••••••••' : null }; });
    res.json({ data: masked });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/switches/:id/reveal-password', authenticate, async (req, res) => {
  try {
    const { id } = req.params;
    const result = await pool.query('SELECT id, name, password FROM switches WHERE id = $1', [id]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'Switch not found' });
    const now = new Date();
    const timeStr = now.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
    await pool.query('INSERT INTO audit_logs (time, username, action, target) VALUES ($1, $2, $3, $4)', [timeStr, req.user.username, 'revealed credential', 'Switch ' + result.rows[0].name + ' password']);
    res.json({ password: result.rows[0].password });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ── TICKETS ──────────────────────────────────────────────
app.get('/api/tickets', authenticate, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM tickets ORDER BY created_at DESC');
    res.json({ data: result.rows });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/tickets', authenticate, async (req, res) => {
  try {
    const { id, client, site, subject, from_email, category, priority, status, assigned, received, body, notes, hardware, history, attachments } = req.body;
    await pool.query(
      'INSERT INTO tickets (id, client, site, subject, from_email, category, priority, status, assigned, received, body, notes, hardware, history, attachments) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13::jsonb,$14::jsonb,$15::jsonb)',
      [id, client, site, subject, from_email, category, priority, status, assigned, received, body, notes, JSON.stringify(hardware || []), JSON.stringify(history || []), JSON.stringify(attachments || [])]
    );
    res.json({ success: true, id });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/tickets/:id', authenticate, async (req, res) => {
  try {
    const { id } = req.params;
    const { status, assigned, notes, priority, category } = req.body;
    const fields = []; const values = []; let counter = 1;
    if (status !== undefined) { fields.push('status = $' + counter); values.push(status); counter++; }
    if (assigned !== undefined) { fields.push('assigned = $' + counter); values.push(assigned); counter++; }
    if (notes !== undefined) { fields.push('notes = $' + counter); values.push(notes); counter++; }
    if (priority !== undefined) { fields.push('priority = $' + counter); values.push(priority); counter++; }
    if (category !== undefined) { fields.push('category = $' + counter); values.push(category); counter++; }
    fields.push('updated_at = CURRENT_TIMESTAMP');
    values.push(id);
    await pool.query('UPDATE tickets SET ' + fields.join(', ') + ' WHERE id = $' + counter, values);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ── AUDIT LOG ────────────────────────────────────────────
app.get('/api/audit', authenticate, async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 50;
    const result = await pool.query('SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT $1', [limit]);
    res.json({ data: result.rows });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/audit', authenticate, async (req, res) => {
  try {
    const { user, action, target } = req.body;
    const now = new Date();
    const timeStr = now.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
    await pool.query('INSERT INTO audit_logs (time, username, action, target) VALUES ($1, $2, $3, $4)', [timeStr, user || req.user.username, action, target]);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ── INBOX ────────────────────────────────────────────────
app.get('/api/inbox', authenticate, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM emails ORDER BY created_at DESC');
    res.json({ data: result.rows });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ── DASHBOARD TRENDS ─────────────────────────────────────
app.get('/api/dashboard/trends', authenticate, async (req, res) => {
  try {
    const [camRes, doorRes, srvRes, swRes] = await Promise.all([
      pool.query("SELECT COUNT(*) FROM cameras WHERE status IN ('Defective','Offline')"),
      pool.query("SELECT COUNT(*) FROM doors WHERE status = 'Offline'"),
      pool.query("SELECT COUNT(*) FILTER (WHERE status = 'ONLINE') AS online, COUNT(*) AS total FROM servers"),
      pool.query("SELECT COUNT(*) AS total FROM switches")
    ]);
    const camerasDefective = parseInt(camRes.rows[0].count);
    const doorsOffline = parseInt(doorRes.rows[0].count);
    const serversOnline = parseInt(srvRes.rows[0].online);
    const serversTotal = parseInt(srvRes.rows[0].total);
    const switchesTotal = parseInt(swRes.rows[0].total);

    await pool.query(
      'INSERT INTO dashboard_snapshots (snapshot_date, cameras_defective, doors_offline, servers_online, servers_total, switches_total) VALUES (CURRENT_DATE, $1, $2, $3, $4, $5) ON CONFLICT (snapshot_date) DO UPDATE SET cameras_defective = $1, doors_offline = $2, servers_online = $3, servers_total = $4, switches_total = $5',
      [camerasDefective, doorsOffline, serversOnline, serversTotal, switchesTotal]
    );

    const baseline = await pool.query("SELECT * FROM dashboard_snapshots WHERE snapshot_date <= CURRENT_DATE - INTERVAL '7 days' ORDER BY snapshot_date DESC LIMIT 1");

    function pctChange(current, past) {
      if (past === null || past === undefined || past === 0) return null;
      return Math.round(((current - past) / past) * 100);
    }

    const base = baseline.rows[0] || null;
    res.json({
      data: {
        camerasDefective: { value: camerasDefective, trendPct: base ? pctChange(camerasDefective, base.cameras_defective) : null },
        doorsOffline: { value: doorsOffline, trendPct: base ? pctChange(doorsOffline, base.doors_offline) : null },
        serversOnline: { value: serversOnline, total: serversTotal, trendPct: base ? pctChange(serversOnline, base.servers_online) : null },
        switchesTotal: { value: switchesTotal, trendPct: base ? pctChange(switchesTotal, base.switches_total) : null },
        comparisonAvailable: !!base,
        comparisonPeriodDays: 7
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ── HEALTH CHECK ────────────────────────────────────────
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// ── SERVE FRONTEND ───────────────────────────────────────
app.use(express.static(__dirname));
app.get('*', (req, res, next) => {
  if (req.path.startsWith('/api/')) return next();
  res.sendFile(path.join(__dirname, 'index.html'));
});

// ── ERROR HANDLER ──────────────────────────────────────
app.use((err, req, res, next) => {
  console.error('❌ Error:', err.stack);
  res.status(500).json({ error: err.message || 'Internal server error' });
});

// ── START SERVER ────────────────────────────────────────
async function startServer() {
  try {
    await initDatabase();
    await seedData();
    app.listen(PORT, () => {
      console.log('✅ CCSM Backend running on http://localhost:' + PORT);
      console.log('📡 API endpoint: http://localhost:' + PORT + '/api');
      console.log('🔑 Default login: admin / admin123');
    });
  } catch (error) {
    console.error('❌ Failed to start server:', error.message);
    process.exit(1);
  }
}

startServer();

process.on('SIGTERM', async () => { console.log('🛑 Shutting down...'); await pool.end(); process.exit(0); });
process.on('SIGINT', async () => { console.log('🛑 Shutting down...'); await pool.end(); process.exit(0); });
