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
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'ccsm-super-secret-key-2026';

// ── DATABASE CONNECTION ──────────────────────────────────
// On Railway, the Postgres plugin provides a single DATABASE_URL var.
// Locally, falls back to individual DB_* vars (e.g. from a .env file).
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

// ── MIDDLEWARE ────────────────────────────────────────────
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
app.use(cors({
  origin: true, // reflects the request's Origin — allows any frontend (file://, static host, etc.) to call this API
  credentials: true
}));
app.use(express.json({ limit: '10mb' }));

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { error: 'Too many requests, please try again later.' }
});
app.use('/api/', limiter);

// ── AUTH MIDDLEWARE ──────────────────────────────────────
const authenticate = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    return res.status(401).json({ error: 'No token provided' });
  }

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ error: 'Invalid token' });
  }
};

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
        id SERIAL PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        zone VARCHAR(50),
        status VARCHAR(20) DEFAULT 'Unknown',
        ip_address VARCHAR(15),
        username VARCHAR(50),
        model VARCHAR(100),
        comments TEXT,
        last_seen TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS doors (
        id SERIAL PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        site VARCHAR(100),
        client VARCHAR(20),
        reader VARCHAR(100),
        lock_type VARCHAR(50),
        powered VARCHAR(20),
        status VARCHAR(20) DEFAULT 'Offline',
        tech VARCHAR(50),
        ip_address VARCHAR(15),
        controller VARCHAR(100),
        last_service VARCHAR(50),
        history JSONB DEFAULT '[]',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS servers (
        id SERIAL PRIMARY KEY,
        location VARCHAR(100),
        serial VARCHAR(50) NOT NULL,
        capacity VARCHAR(20),
        used VARCHAR(20),
        health VARCHAR(100),
        apps TEXT,
        status VARCHAR(20) DEFAULT 'ONLINE',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS switches (
        id SERIAL PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        location VARCHAR(100),
        model VARCHAR(100),
        ip_address VARCHAR(15),
        firmware VARCHAR(20),
        username VARCHAR(50),
        password VARCHAR(100),
        mac VARCHAR(20),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS tickets (
        id VARCHAR(20) PRIMARY KEY,
        client VARCHAR(20),
        site VARCHAR(100),
        subject VARCHAR(255) NOT NULL,
        from_email VARCHAR(100),
        category VARCHAR(50),
        priority VARCHAR(20) DEFAULT 'Medium',
        status VARCHAR(20) DEFAULT 'Open',
        assigned VARCHAR(50),
        received VARCHAR(50),
        body TEXT,
        notes TEXT,
        hardware JSONB DEFAULT '[]',
        history JSONB DEFAULT '[]',
        attachments JSONB DEFAULT '[]',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS audit_logs (
        id SERIAL PRIMARY KEY,
        time VARCHAR(20),
        username VARCHAR(50),
        action VARCHAR(50),
        target TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS emails (
        id VARCHAR(20) PRIMARY KEY,
        from_name VARCHAR(100),
        from_email VARCHAR(100),
        to_email VARCHAR(100),
        subject VARCHAR(255),
        body TEXT,
        date VARCHAR(50),
        attachments JSONB DEFAULT '[]',
        is_sr BOOLEAN DEFAULT false,
        sr_linked VARCHAR(20),
        urgent BOOLEAN DEFAULT false,
        client VARCHAR(20),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE INDEX IF NOT EXISTS idx_cameras_zone ON cameras(zone);
      CREATE INDEX IF NOT EXISTS idx_cameras_status ON cameras(status);
      CREATE INDEX IF NOT EXISTS idx_doors_site ON doors(site);
      CREATE INDEX IF NOT EXISTS idx_doors_status ON doors(status);
      CREATE INDEX IF NOT EXISTS idx_tickets_status ON tickets(status);
      CREATE INDEX IF NOT EXISTS idx_tickets_client ON tickets(client);
      CREATE INDEX IF NOT EXISTS idx_audit_username ON audit_logs(username);
      CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_logs(created_at);
    `);

    const adminCheck = await pool.query("SELECT * FROM users WHERE username = 'admin'");
    if (adminCheck.rows.length === 0) {
      const hashed = await bcrypt.hash('admin123', 10);
      await pool.query(
        "INSERT INTO users (username, password_hash, role, email) VALUES ($1, $2, $3, $4)",
        ['admin', hashed, 'Administrator', 'admin@etechsystems.com']
      );
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
    if (parseInt(camerasCheck.rows[0].count) > 0) return;

    console.log('🌱 Seeding data...');

    const cameras = [
      ['HM3 PTZ', 'NORTH', 'Defective', '10.19.1.150', 'root', 'Pelco P2820-ESR', 'Defective'],
      ['HM10 PTZ', 'NORTH', 'Defective', '10.19.1.158', 'root', 'Pelco P2820-ESR', 'Keeps resetting'],
      ['HM11 PTZ', 'NORTH', 'Defective', '10.19.1.159', 'root', 'Pelco P2820-ESR', 'Keeps resetting'],
      ['N25 PTZ', 'NORTH', 'Defective', '10.19.1.175', 'root', 'Pelco P2820-ESR', 'Defective'],
      ['B3 PTZ', 'SOUTH', 'Online', '10.19.1.110', 'root', 'Axis', 'Confirmed June 8th'],
      ['D4 PTZ', 'SOUTH', 'Online', '10.19.1.120', 'root', 'Axis', 'Confirmed June 8th'],
      ['A7 PTZ', 'SOUTH', 'Defective', '10.19.1.130', 'root', 'Axis', 'Defective'],
      ['A8 PTZ', 'SOUTH', 'Defective', '10.19.1.131', 'root', 'Axis', 'Defective'],
      ['A9 PTZ Context Stream', 'SOUTH', 'Defective', '10.19.1.132', 'root', 'Axis', 'Defective'],
      ['A13 PTZ Stream 1', 'SOUTH', 'Defective', '10.19.1.136', 'root', 'Axis', 'Defective'],
      ['C1 PTZ (243)', 'SOUTH', 'Defective', '10.19.1.140', 'root', 'Axis', 'Defective'],
      ['W1', 'WEST', 'No Power', '10.19.1.180', 'root', 'Axis', 'No power/network at Pole'],
      ['W2', 'WEST', 'No Power', '10.19.1.182', 'root', 'Axis', 'Connected to W1'],
      ['WB1 PTZ', 'WEST', 'Defective', '10.19.1.185', 'root', 'Axis', 'Replace with P-series'],
      ['Manager Car Park PTZ', 'NORTH', 'Defective', '10.19.1.50', 'root', 'Pelco P2820-ESR', 'Defective'],
      ['Visitor Car Park PTZ 2', 'NORTH', 'Defective', '10.19.1.52', 'root', 'Pelco P2820-ESR', 'Defective'],
      ['SW Corner Perim PTZ', 'NORTH', 'Defective', '10.19.1.53', 'root', 'Pelco P2820-ESR', 'To be replaced'],
      ['A1 PTZ', 'NORTH', 'Online', '172.17.103.30', 'admin', 'Pelco P2820-ESR', 'Active PTZ camera'],
      ['A2 PTZ', 'NORTH', 'Online', '172.17.103.31', 'admin', 'Pelco P2820-ESR', 'Active PTZ camera'],
      ['A3 PTZ', 'NORTH', 'Online', '172.17.103.32', 'root', 'Axis PTZ', 'Active PTZ camera'],
      ['B1', 'WEST', 'Online', '172.17.103.43', 'administrator', 'Avigilon 5.0C-H5A-DP2', 'Avigilon fixed camera'],
      ['B2', 'WEST', 'Online', '172.17.103.45', 'administrator', 'Avigilon 5.0C-H5A-DP2', 'Avigilon fixed camera'],
      ['C1', 'SOUTH', 'Online', '172.17.103.71', 'administrator', 'Avigilon 5.0C-H5A-DP2', 'Avigilon fixed camera'],
      ['C2', 'SOUTH', 'Online', '172.17.103.72', 'administrator', 'Avigilon 5.0C-H5A-DP2', 'Avigilon fixed camera'],
      ['D1', 'EAST', 'Online', '172.17.103.87', 'administrator', 'Avigilon 5.0C-H5A-DP2', 'Avigilon fixed camera'],
      ['D2', 'EAST', 'Online', '172.17.103.88', 'administrator', 'Avigilon 5.0C-H5A-DP2', 'Avigilon fixed camera'],
      ['HM4 PTZ', 'NORTH', 'Online', '172.17.102.219', 'admin', 'Pelco P2820-ESR', 'Pelco PTZ camera']
    ];

    for (const cam of cameras) {
      await pool.query(
        `INSERT INTO cameras (name, zone, status, ip_address, username, model, comments)
         VALUES ($1, $2, $3, $4, $5, $6, $7)`,
        cam
      );
    }

    const doors = [
      ['Second Entrance Staff Entrance 2', 'Second Entrance', 'KFTL', 'eyeLock (Biometric)', 'Turnstile', 'Not In Use', 'Offline', 'Marvin Grant', '10.19.1.100', 'eyeLock Panel 2', '6/3/2026'],
      ['Second Entrance Staff Exit 1', 'Second Entrance', 'KFTL', 'eyeLock (Biometric)', 'Turnstile', 'Not In Use', 'Offline', 'Marvin Grant', '10.19.1.101', 'eyeLock Panel 1', '6/3/2026'],
      ['Second Entrance Staff Entrance 1', 'Second Entrance', 'KFTL', 'eyeLock (Biometric)', 'Turnstile', 'Not In Use', 'Offline', 'Marvin Grant', '10.19.1.102', 'eyeLock Panel 3', '6/3/2026'],
      ['Second Entrance Staff Exit 2', 'Second Entrance', 'KFTL', 'eyeLock (Biometric)', 'Turnstile', 'Not In Use', 'Offline', 'Marvin Grant', '10.19.1.103', 'eyeLock Panel 4', '6/3/2026']
    ];

    for (const door of doors) {
      await pool.query(
        `INSERT INTO doors (name, site, client, reader, lock_type, powered, status, tech, ip_address, controller, last_service, history)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12::jsonb)`,
        [...door.slice(0, 11), '[{"date":"Jun 18, 2026","event":"Reader replacement","tech":"Marvin Grant"}]']
      );
    }

    const servers = [
      ['Kingport', 'J1013DDR', '6.11TB', '1.4TB', 'Good (23%)', 'Ocularis DM5, LPR', 'ONLINE'],
      ['Kingport', '9B0F842', '930GB', '74GB', 'Good', 'Ocularis, LPR', 'ONLINE'],
      ['Kingport', 'J1013DDV', '6.11TB', '1.4TB', 'Good, Failed drive', 'Ocularis DM6, Eyelock', 'ONLINE'],
      ['Kingport', 'J1013N50', '32TB', '—', 'Good', '—', 'ONLINE'],
      ['Kingport', 'J1013DDW', '6.11TB', '1.4TB', 'Good (23%)', 'Ocularis DM4, Access Control', 'ONLINE'],
      ['Kingport', 'J1013N4Z', '32TB', '—', 'Good', '—', 'ONLINE'],
      ['Kingport', 'J1013DDT', '6.11TB', '1.37TB', 'Good (23%)', 'Node in Failure', 'ONLINE'],
      ['Kingport', 'J1013N4Y', '—', '32TB', 'Good', '—', 'ONLINE'],
      ['Kingport', 'J1013DDX', '45TB', '178GB', 'Excellent', '—', 'ONLINE']
    ];

    for (const srv of servers) {
      await pool.query(
        `INSERT INTO servers (location, serial, capacity, used, health, apps, status)
         VALUES ($1, $2, $3, $4, $5, $6, $7)`,
        srv
      );
    }

    const switches = [
      ['Main Entrance', 'Security Office', 'AXIS T8508', '10.19.1.21', '6.54.2739', 'root', '$upp@rt@202O', 'AC:CC:8E:FA:4B:1B'],
      ['2nd entrance', 'SAL Duty Office', 'AXIS T8516', '10.19.1.23', '6.54.2739', 'root', '$upp@rt@202O', 'AC:CC:8E:B6:DF:99'],
      ['Exit gate', 'Gate Pass Office', 'AXIS T8516', '10.19.1.22', '6.54.2739', 'root', '$upp@rt@202O', 'AC:CC:8E:B6:DD:5F'],
      ['LPR Overview', 'Gate Pass Office', 'AXIS T8516', '10.19.1.32', '6.54.2739', 'root', '$upp@rt@202O', 'AC:CC:8E:B6:DD:26'],
      ['CarPark 4/Berth 4', 'Car Park 4 wall', 'AXIS T8508', '10.19.1.38', '6.54.2739', 'root', '$upp@rt@202O', 'AC:CC:8E:FA:4F:A9'],
      ['Berth 5 Warehouse A', 'Upstairs', 'AXIS T8516', '10.19.1.26', '6.54.2739', 'root', '$upp@rt@202O', 'AC:CC:8E:D7:8D:13'],
      ['Berth 5 Warehouse B', 'Stripping Office', 'AXIS T8508', '10.19.1.37', '6.54.2739', 'root', '$upp@rt@202O', 'AC:CC:8E:FA:4B:10'],
      ['Berth 5 rear east', 'rear of warehouse', 'AXIS T8504-R', '10.19.1.119', '7.10.1595', 'root', '$upp@rt@202O', 'AC:CC:8E:FA:E2:DF'],
      ['Berth 1 perimeter-A', 'Berth 1 Corner Wall', 'AXIS T8508', '10.19.1.35', '6.54.2739', 'root', '$upp@rt@202O', 'AC:CC:8E:FA:4B:31'],
      ['Berth 1 perimeter-B', 'Berth 1 Middle Wall', 'AXIS T8508', '10.19.1.36', '6.54.2739', 'root', '$upp@rt@202O', 'AC:CC:8E:FA:4F:B4'],
      ['Warehouse 2 A', 'Upstairs', 'AXIS T8516', '10.19.1.27', '6.54.2739', 'root', '$upp@rt@202O', 'AC:CC:8E:B6:DD:39'],
      ['Warehouse 2 B', 'Down stairs', 'AXIS T8508', '10.19.1.30', '6.54.2739', 'root', '$upp@rt@202O', 'AC:CC:8E:FA:49:9A'],
      ['Warehouse 1', 'Warehouse1/Spectrum', 'AXIS T8516', '10.19.1.20', '6.54.2739', 'root', '$upp@rt@202O', 'AC:CC:8E:B6:DD:72'],
      ['Berth 8 B', 'Berth 8 East/West', 'AXIS T8504-R', '10.19.1.33', '7.10.1595', 'root', '$upp@rt@202O', 'AC:CC:8E:FA:E3:1E'],
      ['Berth 8 A', 'Berth 8 Perimeter', 'TL-SG2210P', '10.19.1.39', '5.20.20', 'admin', '$upp@rt@2020', 'BO:19:21::20:FF:F2']
    ];

    for (const sw of switches) {
      await pool.query(
        `INSERT INTO switches (name, location, model, ip_address, firmware, username, password, mac)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
        sw
      );
    }

    const tickets = [
      ['SR-1847', 'KFTL', 'NORTH Zone', 'Replace defective cameras - NORTH zone', 'facilities@kftl.com', 'Camera', 'High', 'Open', 'Shanice Vernon', 'Jun 13, 2026', 'We need camera replacements in NORTH zone.', '', '[]', '[{"time":"14:22","msg":"Created — assigned to Shanice (day shift)"}]', '[]'],
      ['SR-1848', 'KWL', 'Tinson Pen', 'Tinson Pen switches need firmware check', 'security@kwl.com', 'Network', 'Medium', 'Open', 'Shanice Vernon', 'Jun 15, 2026', 'Tinson Pen switches need firmware check.', '', '[]', '[{"time":"11:05","msg":"Created — assigned to Shanice (day shift)"}]', '[]'],
      ['SR-1849', 'KFTL', 'Second Entrance', 'All 4 turnstiles offline', 'it@kftl.com', 'Access Control', 'High', 'In Progress', 'Marvin Grant', 'Jun 10, 2026', 'All turnstiles offline.', '', '[]', '[{"time":"16:48","msg":"Created — assigned to Shavine (night shift)"},{"time":"17:00","msg":"Escalated to Marvin Grant for on-site repair"}]', '[]'],
      ['SR-1850', 'KFTL', 'Kingport', 'Server J1013DDV failed drive', 'marvin.grant@etechsystems.com', 'Server', 'Medium', 'Open', 'Shavine', 'Jun 8, 2026', 'Server J1013DDV has failed drive.', '', '[]', '[{"time":"09:12","msg":"Created — assigned to Shavine (night shift)"}]', '[]']
    ];

    for (const ticket of tickets) {
      await pool.query(
        `INSERT INTO tickets (id, client, site, subject, from_email, category, priority, status, assigned, received, body, notes, hardware, history, attachments)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13::jsonb, $14::jsonb, $15::jsonb)`,
        ticket
      );
    }

    const auditEntries = [
      ['14:32', 'Shanice Vernon', 'updated', 'SR-1847 → In Progress'],
      ['13:50', 'Marvin Grant', 'updated', 'HM3 PTZ comment → "Defective"'],
      ['12:00', 'System', 'converted', 'David Chen → SR-1848'],
      ['11:30', 'System', 'sync', 'Camera_Maintenance_2025.csv ✅'],
      ['10:45', 'System', 'sync', 'Access_Control_Survey.csv ⚠️']
    ];

    for (const entry of auditEntries) {
      await pool.query(
        `INSERT INTO audit_logs (time, username, action, target)
         VALUES ($1, $2, $3, $4)`,
        entry
      );
    }

    const emails = [
      ['e1', 'David Chen', 'facilities@kftl.com', 'support@etechsystems.com', 'Replace defective cameras - NORTH zone', 'We need camera replacements.', 'Jun 15, 2026 14:22', '[]', true, 'SR-1847', true, 'KFTL'],
      ['e2', 'Andrea Williams', 'security@kwl.com', 'support@etechsystems.com', 'URGENT: 5 Cameras Offline - Tinson Pen', '5 cameras down at Tinson Pen.', 'Jun 15, 2026 11:05', '[]', true, 'SR-1848', true, 'KWL'],
      ['e3', 'IT Department', 'it@kftl.com', 'support@etechsystems.com', 'ASAP: Access Doors - Second Entrance Offline', 'Turnstiles offline.', 'Jun 14, 2026 16:48', '[]', true, 'SR-1849', true, 'KFTL']
    ];

    for (const email of emails) {
      await pool.query(
        `INSERT INTO emails (id, from_name, from_email, to_email, subject, body, date, attachments, is_sr, sr_linked, urgent, client)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9, $10, $11, $12)`,
        email
      );
    }

    console.log('✅ Seed data complete');
  } catch (error) {
    console.error('❌ Seed error:', error);
  }
}

// ── ROUTES ────────────────────────────────────────────────

// ── AUTH ─────────────────────────────────────────────────
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password required' });
    }

    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const user = result.rows[0];
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({
      token,
      user: { id: user.id, username: user.username, role: user.role, email: user.email }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/auth/microsoft/login', (req, res) => {
  res.json({ message: 'Microsoft OAuth login', url: 'https://login.microsoftonline.com/...' });
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
    const { comments, status } = req.body;

    if (comments !== undefined) {
      await pool.query(
        'UPDATE cameras SET comments = $1, updated_at = CURRENT_TIMESTAMP WHERE name = $2',
        [comments, name]
      );
    }
    if (status !== undefined) {
      await pool.query(
        'UPDATE cameras SET status = $1, updated_at = CURRENT_TIMESTAMP WHERE name = $2',
        [status, name]
      );
    }
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ── DOORS ─────────────────────────────────────────────────
app.get('/api/doors', authenticate, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM doors ORDER BY site, name');
    res.json({ data: result.rows });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/doors/:name', authenticate, async (req, res) => {
  try {
    const { name } = req.params;
    const { status, tech } = req.body;

    if (status !== undefined) {
      await pool.query(
        'UPDATE doors SET status = $1, updated_at = CURRENT_TIMESTAMP WHERE name = $2',
        [status, name]
      );
    }
    if (tech !== undefined) {
      await pool.query(
        'UPDATE doors SET tech = $1, updated_at = CURRENT_TIMESTAMP WHERE name = $2',
        [tech, name]
      );
    }
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
    res.json({ data: result.rows });
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

app.get('/api/tickets/:id', authenticate, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM tickets WHERE id = $1', [req.params.id]);
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Ticket not found' });
    }
    res.json({ data: result.rows[0] });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/tickets', authenticate, async (req, res) => {
  try {
    const { id, client, site, subject, from_email, category, priority, status, assigned, received, body, notes, hardware, history, attachments } = req.body;

    await pool.query(
      `INSERT INTO tickets 
       (id, client, site, subject, from_email, category, priority, status, assigned, received, body, notes, hardware, history, attachments)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13::jsonb, $14::jsonb, $15::jsonb)`,
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

    const fields = [];
    const values = [];
    let counter = 1;

    if (status !== undefined) { fields.push(`status = $${counter}`); values.push(status); counter++; }
    if (assigned !== undefined) { fields.push(`assigned = $${counter}`); values.push(assigned); counter++; }
    if (notes !== undefined) { fields.push(`notes = $${counter}`); values.push(notes); counter++; }
    if (priority !== undefined) { fields.push(`priority = $${counter}`); values.push(priority); counter++; }
    if (category !== undefined) { fields.push(`category = $${counter}`); values.push(category); counter++; }

    fields.push(`updated_at = CURRENT_TIMESTAMP`);
    values.push(id);

    if (fields.length > 0) {
      await pool.query(
        `UPDATE tickets SET ${fields.join(', ')} WHERE id = $${counter}`,
        values
      );
    }

    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ── AUDIT LOG ────────────────────────────────────────────
app.get('/api/audit', authenticate, async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 50;
    const result = await pool.query(
      'SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT $1',
      [limit]
    );
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

    await pool.query(
      'INSERT INTO audit_logs (time, username, action, target) VALUES ($1, $2, $3, $4)',
      [timeStr, user || req.user.username, action, target]
    );

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

// ── SEED ENDPOINT ───────────────────────────────────────
app.post('/api/seed', authenticate, async (req, res) => {
  try {
    await seedData();
    res.json({ success: true, message: 'Database seeded' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ── HEALTH CHECK ────────────────────────────────────────
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// ── SERVE FRONTEND ───────────────────────────────────────
const path = require('path');
app.use(express.static(__dirname));
app.get('*', (req, res, next) => {
  if (req.path.startsWith('/api/')) return next();
  res.sendFile(path.join(__dirname, 'E-Tech CCSM Prototype.html'));
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
      console.log(`✅ CCSM Backend running on http://localhost:${PORT}`);
      console.log(`📡 API endpoint: http://localhost:${PORT}/api`);
      console.log(`🔑 Default login: admin / admin123`);
      console.log(`📊 Database: ${process.env.DB_NAME || 'ccsm'}`);
    });
  } catch (error) {
    console.error('❌ Failed to start server:', error.message);
    process.exit(1);
  }
}

startServer();

// ── GRACEFUL SHUTDOWN ──────────────────────────────────
process.on('SIGTERM', async () => {
  console.log('🛑 Shutting down...');
  await pool.end();
  process.exit(0);
});

process.on('SIGINT', async () => {
  console.log('🛑 Shutting down...');
  await pool.end();
  process.exit(0);
});
