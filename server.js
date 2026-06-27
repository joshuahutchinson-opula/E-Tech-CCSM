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
        id SERIAL PRIMARY KEY, username VARCHAR(50) UNIQUE NOT NULL, password_hash VARCHAR(255) NOT NULL,
        role VARCHAR(20) DEFAULT 'Technician', email VARCHAR(100), created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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
        access_direction VARCHAR(10) DEFAULT 'In', history JSONB DEFAULT '[]', comments TEXT DEFAULT '',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
      CREATE TABLE IF NOT EXISTS servers (
        id SERIAL PRIMARY KEY, location VARCHAR(100), serial VARCHAR(50) NOT NULL UNIQUE, capacity VARCHAR(20),
        used VARCHAR(20), health VARCHAR(100), apps TEXT, status VARCHAR(20) DEFAULT 'ONLINE', comments TEXT DEFAULT '',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
      CREATE TABLE IF NOT EXISTS switches (
        id SERIAL PRIMARY KEY, name VARCHAR(100) NOT NULL UNIQUE, location VARCHAR(100), model VARCHAR(100),
        ip_address VARCHAR(15), firmware VARCHAR(20), username VARCHAR(50), password VARCHAR(100), mac VARCHAR(20), comments TEXT DEFAULT '',
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
        // ── ADMIN/HR — Still Cameras ──
        ['ATM Walkway','ADMIN/HR','Online','','admin','','',''],
        ['Board N Ceo Secretary','ADMIN/HR','Online','','admin','','',''],
        ['Executive 2nd Fl Exit Stair Lower Case','ADMIN/HR','Online','','admin','','',''],
        ['Executive 2nd Fl Exit Stair Top Case','ADMIN/HR','Online','','admin','','',''],
        ['HR Meeting Rm Passage','ADMIN/HR','Online','','admin','','','Camera refocused'],
        ['HR Waiting Area','ADMIN/HR','Online','','admin','','',''],
        ['Lobby HR','ADMIN/HR','Online','','admin','','',''],
        ['Meeting RM Passage','ADMIN/HR','Online','','admin','','',''],
        ['Payroll Walkway','ADMIN/HR','Online','','admin','','',''],
        ['Planning Main Entry','ADMIN/HR','Online','','admin','','',''],
        ['Procurement Passage','ADMIN/HR','Online','','admin','','',''],

        // ── ENGINEERING — Still Cameras ──
        ['Bathroom Passage 1','ENGINEERING','Online','','admin','','',''],
        ['Bathroom Passage 2','ENGINEERING','Online','','admin','','',''],
        ['Battery Shop','ENGINEERING','Online','','admin','','','Lift Required'],
        ['Data Center A','ENGINEERING','Online','','admin','','',''],
        ['F Changing Room Exit Passage','ENGINEERING','Online','','admin','','',''],
        ['Eng Workshop 3','ENGINEERING','Online','','admin','','','Lift Required'],
        ['Eng Rear Passage','ENGINEERING','Online','','admin','','',''],
        ['Engineering East Stair','ENGINEERING','Online','','admin','','',''],
        ['Engineering West Stair','ENGINEERING','Online','','admin','','',''],
        ['IT Entry','ENGINEERING','Online','','admin','','',''],
        ['IT Exit','ENGINEERING','Online','','admin','','',''],
        ['IT Stairwell','ENGINEERING','Online','','admin','','',''],
        ['Engineering Lunch Room','ENGINEERING','Online','','admin','','',''],
        ['Engineering Entry','ENGINEERING','Online','','admin','','',''],
        ['Engineering Gym','ENGINEERING','Online','','admin','','',''],
        ['Training Room East','ENGINEERING','Online','','admin','','',''],
        ['Training Room West','ENGINEERING','Online','','admin','','',''],
        ['Eng Lunch RM Kitchen','ENGINEERING','Online','','admin','','',''],
        ['Engineering Entry Passage','ENGINEERING','Online','','admin','','',''],
        ['Tyre Shop','ENGINEERING','Online','','admin','','','Lift Required'],

        // ── HIGH MAST — Still Cameras ──
        ['HM5(11)','HIGH MAST','Online','','admin','','','Camera had default IP reconfigured'],
        ['HM5(134)','HIGH MAST','Online','','admin','','','Camera lens damaged'],
        ['HM8','HIGH MAST','Online','','admin','','',''],
        ['HM14','HIGH MAST','Online','','admin','','',''],
        ['HM23','HIGH MAST','Online','','admin','','',''],
        ['HM24A','HIGH MAST','Defective','','admin','','','No Fibre link'],
        ['Manager Car Park Dome','HIGH MAST','Online','','admin','','','Camera lens Damaged'],
        ['N30','HIGH MAST','Online','','admin','','','Pole'],
        ['N31','HIGH MAST','Online','','admin','','','Camera needs to be reset, POE replaced'],
        ['N33','HIGH MAST','Online','','admin','','',''],
        ['N34','HIGH MAST','Online','','admin','','',''],
        ['HM14 PTZ 2','HIGH MAST','Online','','admin','','','To be added to genetec(172.17.103.200)'],

        // ── NORTH TERMINAL PERIMETER — Still Cameras ──
        ['N Fence','NORTH TERMINAL PERIMETER','Online','','admin','','','Analytics Applied'],
        ['East West Corner Perimeter Rest Bay','NORTH TERMINAL PERIMETER','Online','','admin','','','Analytics Applied'],
        ['N Terminal NW Corner','NORTH TERMINAL PERIMETER','Online','','admin','','','Analytics Applied'],
        ['North South Corner Rest Bay','NORTH TERMINAL PERIMETER','Online','','admin','','','Analytics Applied'],
        ['PPE Store Perim N','NORTH TERMINAL PERIMETER','Online','','admin','','','Analytics Applied'],
        ['PPE Store Perim S','NORTH TERMINAL PERIMETER','Online','','admin','','','Analytics Applied'],
        ['Wharfage Perim','NORTH TERMINAL PERIMETER','Defective','','admin','','','replacement needed'],

        // ── NORTH TERMINAL PERIMETER — PTZ Cameras ──
        ['HR Tower 1 PTZ','NORTH TERMINAL PERIMETER','Online','','admin','','',''],
        ['HR Tower 2 PTZ','NORTH TERMINAL PERIMETER','Online','','admin','','',''],
        ['PPE Store Perim PTZ','NORTH TERMINAL PERIMETER','Online','','admin','','',''],
        ['Wharfage Perim N Exit Gate PTZ','NORTH TERMINAL PERIMETER','Online','','admin','','',''],

        // ── PTZ CAMERAS ──
        ['Berth 9 PTZ','PTZ','Online','','admin','','',''],
        ['HM3 PTZ','PTZ','Defective','','admin','','','POE added, camera shows signs of being defective'],
        ['HM4 PTZ','PTZ','Online','','admin','','',''],
        ['HM5 PTZ','PTZ','Online','','admin','','',''],
        ['HM8 PTZ','PTZ','Online','','admin','','',''],
        ['HM10 PTZ','PTZ','Online','','admin','','','Camera is reconfigured, had default IP'],
        ['HM11 PTZ','PTZ','Online','','admin','','',''],
        ['HM14 PTZ','PTZ','Online','','admin','','',''],
        ['HM23 PTZ','PTZ','Defective','','admin','','','Cables ends were corroded. Ends recrimped. Camera is online. Camera remained online for a week, second checks revealed the camera is over heating. Camera is deemed defective'],
        ['HM24A PTZ','PTZ','Defective','','admin','','','No Fibre link'],
        ['HM28 PTZ','PTZ','Online','','admin','','',''],
        ['Manager Car Park PTZ','PTZ','Defective','','admin','','','Defective'],
        ['N Terminal NW Corner PTZ','PTZ','Online','','admin','','',''],
        ['N25 PTZ','PTZ','Defective','','admin','','','Defective'],
        ['N30 PTZ','PTZ','Online','','admin','','','Reset needs to be done'],
        ['N31 PTZ- Context','PTZ','Defective','','admin','','','POE injector changed, Camera needs reset, maybe defective'],
        ['N34 PTZ - Context','PTZ','Defective','','admin','','','Defective'],
        ['Visitor Car Park PTZ 1','PTZ','Online','','admin','','',''],
        ['Visitor Car Park PTZ 2','PTZ','Defective','','admin','','','REPLACEMENT/AXIS Q6318-LE 60HZ to be installed'],

                // ── LDL WAREHOUSE (Rows 108-128) ──
        ['LDL Warehouse - J3','LDL Warehouse','Online','10.1.7.133','root','Axis P1427-E','5 MP','Cleaned'],
        ['LDL Warehouse - E1','LDL Warehouse','Online','10.1.7.134','root','Axis P1405-E','1.3 MP','Cleaned'],
        ['LDL Warehouse - E2','LDL Warehouse','Online','10.1.7.135','root','Axis P1427-E','5 MP','Cleaned'],
        ['LDL Warehouse - D2','LDL Warehouse','Online','10.1.7.136','root','Axis P1405-E','1.3 MP','Cleaned'],
        ['LDL Warehouse - J2','LDL Warehouse','Online','10.1.7.137','root','Axis P1427-E','5 MP','Cleaned'],
        ['LDL Warehouse - D3','LDL Warehouse','Online','10.1.7.138','root','Axis P1405-E','1.3 MP','Cleaned'],
        ['LDL Warehouse - JW1','LDL Warehouse','Online','10.1.7.139','root','Axis P1427-E','5 MP','Obstrusted by racks need to be relocated'],
        ['LDL Warehouse - JW2','LDL Warehouse','Online','10.1.7.140','root','Axis P1427-E','5 MP','Obstrusted by racks need to be relocated'],
        ['LDL Warehouse - JW3','LDL Warehouse','Online','10.1.7.141','root','Axis P1427-E','5 MP','Cleaned'],
        ['LDL Warehouse - JW4','LDL Warehouse','Online','10.1.7.142','root','Axis P1427-E','5 MP','Obstrusted by racks need to be relocated'],
        ['LDL Warehouse - Power Room','LDL Warehouse','Online','10.1.7.153','root','Axis P1405-E','1.3 MP','Cleaned'],
        ['LDL Warehouse - Damage Repair 1','LDL Warehouse','Online','10.1.7.143','root','Axis P1427-E','5 MP','Cleaned'],
        ['LDL Warehouse - Damage Repair 2','LDL Warehouse','Online','10.1.7.144','root','Axis P1427-E','5 MP','Cleaned'],
        ['LDL Warehouse - Damage Repair 3','LDL Warehouse','Online','10.1.7.145','root','Axis P1427-E','5 MP','Cleaned'],
        ['LDL Warehouse - JWest Shutter','LDL Warehouse','Online','10.1.7.146','root','Axis P1427-E','5 MP','Cleaned'],
        ['LDL Warehouse - JC2','LDL Warehouse','Online','10.1.7.147','root','Axis P1427-E','5 MP','Obstrusted by racks need to be relocated'],
        ['LDL Warehouse - JC1','LDL Warehouse','Online','10.1.7.148','root','Axis P1427-E','5 MP','Cleaned'],
        ['LDL Warehouse - JC3','LDL Warehouse','Online','10.1.7.149','root','Axis P1427-E','5 MP','Obstrusted by racks need to be relocated'],
        ['LDL Warehouse - Dock Shutter 1','LDL Warehouse','Online','10.1.7.150','admin','Arecont Vision 12176DN','5 MP','Forklift wasnt avalabile'],
        ['LDL Warehouse - Dock Shutter 2','LDL Warehouse','Online','10.1.7.151','admin','Arecont Vision 12176DN','5 MP','Forklift wasnt avalabile'],
        ['LDL Warehouse - Dock Shutter 3','LDL Warehouse','Online','10.1.7.152','admin','Arecont Vision 12176DN','5 MP','Forklift wasnt avalabile'],

        // ── LDL NEW WAREHOUSE (Rows 154-162) ──
        ['LDL Warehouse entrance','LDL Warehouse','Online','10.1.7.167','root','Axis P1405-E','1.3 MP','Cleaned'],
        ['LDL Warehouse -Dock Shutter 4','LDL Warehouse','Online','10.1.7.161','admin','Arecont Vision 12176DN','5 MP','Forklift wasnt avalabile'],
        ['LDL Warehouse -Dock Shutter 5','LDL Warehouse','Online','10.1.7.162','admin','Arecont Vision 12176DN','5 MP','Forklift wasnt avalabile'],
        ['LDL Warehouse Cashier Boothe','LDL Warehouse','Online','10.1.7.169','root','Axis P1405-E','1.3 MP','Cleaned'],
        ['LDL Warehouse Cashier windows','LDL Warehouse','Online','10.1.7.168','root','Axis P1405-E','1.3 MP','Cleaned'],
        ['LDL Warehouse -Dock Shutter 6','LDL Warehouse','Online','10.1.7.163','admin','Arecont Vision 12176DN','5 MP','Forklift wasnt avalabile'],
        ['LDL Warehouse -Dock Shutter 7','LDL Warehouse','Online','10.1.7.164','admin','Arecont Vision 12176DN','5 MP','Forklift wasnt avalabile'],
        ['LDL Warehouse -Dock Shutter 8','LDL Warehouse','Online','10.1.7.165','admin','Arecont Vision 12176DN','5 MP','Forklift wasnt avalabile'],
        ['LDL Warehouse -Dock Shutter 9','LDL Warehouse','Defective','10.1.7.166','admin','Arecont Vision 12176DN','5 MP','Forklift wasnt avalabile - Not Focused'],
        ['LDL Warehouse - Repacking','LDL Warehouse','Online','10.1.7.171','root','Axis P1427-LE','5 MP','Cleaned'],

        // ── LIQUID PLANT — Original Cameras (Rows 19-39) ──
        ['Front Lobby','Liquid Plant','Online','10.1.7.64','Admin','Arecont Vision 2146DN','1.3 MP','Cleaned'],
        ['Time Clock','Liquid Plant','Online','10.1.7.63','Admin','Arecont Vision 1145DN','1.3 MP','Cleaned'],
        ['Finish Goods Staging Area','Liquid Plant','Online','10.1.7.62','Admin','Arecont Vision 5145DN','5 MP','Cleaned'],
        ['Processing Room Cam 1','Liquid Plant','Online','10.1.7.61','Admin','Arecont Vision 1145DN','1.3 MP','View block by new machine'],
        ['Processing Room Cam 2','Liquid Plant','Online','10.1.7.60','Admin','Arecont Vision 1145DN','1.3 MP','View block by new machine'],
        ['RO Plant','Liquid Plant','Online','10.1.7.59','Admin','Arecont Vision 5145DN','1.3 MP','Cleaned'],
        ['Filling Room Cam 1','Liquid Plant','Online','10.1.7.58','Admin','Arecont Vision 1145DN','1.3 MP','Cleaned'],
        ['Filling Room Cam 2','Liquid Plant','Online','10.1.7.57','Admin','Arecont Vision 1145DN','1.3 MP','Cleaned'],
        ['Large Bottle Line','Liquid Plant','Online','10.1.7.56','Admin','Arecont Vision 5145DN','5 MP','Cleaned'],
        ['LML Shutter','Liquid Plant','Online','10.1.7.55','Admin','Arecont Vision 5145DN','1.3 MP','Cleaned'],
        ['Blow Mold Fire Door & Shutter','Liquid Plant','Online','10.1.7.53','Admin','Arecont Vision 5145DN','1.3 MP','Cleaned'],
        ['Utilies Room Emergency Exit','Liquid Plant','Online','10.1.7.52','Admin','Arecont Vision 5145DN','1.3 MP','Cleaned'],
        ['Sacmi conveyor line','Liquid Plant','Online','10.1.7.50','Admin','Arecont Vision 5145DN','5 MP','Cleaned'],
        ['Inside Stores','Liquid Plant','Online','10.1.7.70','Admin','Arecont Vision 5145DN','1.3 MP','Cleaned'],
        ['Stores & Sacmi Entrance','Liquid Plant','Online','10.1.7.69','Admin','Arecont Vision 5145DN','1.3 MP','Cleaned'],
        ['Emergency Exit Door','Liquid Plant','Online','10.1.7.68','Admin','Arecont Vision 5145DN','1.3 MP','Cleaned'],
        ['Palletizing','Liquid Plant','Online','10.1.7.65','Admin','Arecont Vision 5145DN','1.3 MP','Cleaned'],

        // ── LIQUID PLANT — Additions (Rows 129-134) ──
        ['Sacmi combo','Liquid Plant','Online','10.1.7.154','root','Axis P1427','5 MP','Cleaned'],
        ['Sacmi Paturizer','Liquid Plant','Online','10.1.7.155','root','Axis P1427','5 MP','Cleaned'],
        ['SBO Blow mold','Liquid Plant','Online','10.1.7.156','root','Axis P1427','5 MP','Cleaned'],
        ['Utilies Room','Liquid Plant','Online','10.1.7.157','root','Axis P1427','5 MP','Cleaned'],
        ['Sacmi Palletizer','Liquid Plant','Online','10.1.7.158','root','Axis P1427','5 MP','Cleaned'],
        ['Blow mold','Liquid Plant','Online','10.1.7.159','root','Axis P1427','5 MP','Cleaned'],
      ];
      for (const cam of cameras) {
        await pool.query(`INSERT INTO cameras (name, zone, status, ip_address, username, model, resolution, comments) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT (name, ip_address) DO NOTHING`, cam);
      }
      console.log('✅ Cameras seeded (' + cameras.length + ' cameras)');
    }
    
    // ── SEED DOORS ──────────────────────────────────
    const doorsCheck = await pool.query("SELECT COUNT(*) FROM doors");
    if (parseInt(doorsCheck.rows[0].count) === 0) {
      console.log('🌱 Seeding doors...');
      const doors = [
        // ── Original KFTL Doors ──
               ['Second Entrance Staff Entrance 2','Second Entrance','KFTL','eyeLock (Biometric)','Turnstile','Not In Use','Offline','Marvin Grant','10.19.1.100','eyeLock Panel 2','6/3/2026','In','[{"date":"Jun 18, 2026","event":"Reader replacement","tech":"Marvin Grant"}]',''],
        ['Second Entrance Staff Exit 1','Second Entrance','KFTL','eyeLock (Biometric)','Turnstile','Not In Use','Offline','Marvin Grant','10.19.1.101','eyeLock Panel 1','6/3/2026','Out','[{"date":"Jun 18, 2026","event":"Reader replacement","tech":"Marvin Grant"}]',''],
        ['Second Entrance Staff Entrance 1','Second Entrance','KFTL','eyeLock (Biometric)','Turnstile','Not In Use','Offline','Marvin Grant','10.19.1.102','eyeLock Panel 3','6/3/2026','In','[{"date":"Jun 18, 2026","event":"Reader replacement","tech":"Marvin Grant"}]',''],
        ['Second Entrance Staff Exit 2','Second Entrance','KFTL','eyeLock (Biometric)','Turnstile','Not In Use','Offline','Marvin Grant','10.19.1.103','eyeLock Panel 4','6/3/2026','Out','[{"date":"Jun 18, 2026","event":"Reader replacement","tech":"Marvin Grant"}]',''],

        // ── Lasco LML B Liquid Plant Doors ──
        ['Batching room','LML B Liquid Plant','Lasco','—','—','Not In Use','Offline','Unassigned','','','','In','[{"date":"Jun 25, 2026","event":"Assessed","tech":"Unassigned"}]','No longer use, equipment has been removed'],
        ['Blow mold entrance 1','LML B Liquid Plant','Lasco','eyeLock (Biometric)','Maglock 600','Yes','Online','Unassigned','','','','In','[{"date":"Jun 25, 2026","event":"Assessed","tech":"Unassigned"}]','Door needs repair, door drop'],
        ['Blow mold entrance 2','LML B Liquid Plant','Lasco','eyeLock (Biometric)','Maglock 600','Yes','Online','Unassigned','','','','In','[{"date":"Jun 25, 2026","event":"Assessed","tech":"Unassigned"}]','Door needs repair, door drop'],
        ['Chemistry lab','LML B Liquid Plant','Lasco','eyeLock (Biometric)','Maglock 600','Yes','Online','Unassigned','','','','In','[{"date":"Jun 25, 2026","event":"Assessed","tech":"Unassigned"}]',''],
        ['Electrical room to utilites','LML B Liquid Plant','Lasco','eyeLock (Biometric)','Maglock 1200','Yes','Online','Unassigned','','','','In','[{"date":"Jun 25, 2026","event":"Assessed","tech":"Unassigned"}]',''],
        ['Utilites to electrical room','LML B Liquid Plant','Lasco','eyeLock (Biometric)','—','Yes','Online','Unassigned','','','','Out','[{"date":"Jun 25, 2026","event":"Assessed","tech":"Unassigned"}]',''],
        ['Entrance to upstairs offices - IN','LML B Liquid Plant','Lasco','eyeLock (Biometric)','Maglock 600','Yes','Online','Unassigned','','','','In','[{"date":"Jun 25, 2026","event":"Assessed","tech":"Unassigned"}]',''],
        ['Entrance to upstairs offices - OUT','LML B Liquid Plant','Lasco','eyeLock (Biometric)','—','Yes','Online','Unassigned','','','','Out','[{"date":"Jun 25, 2026","event":"Assessed","tech":"Unassigned"}]',''],
        ['Filling room 1','LML B Liquid Plant','Lasco','eyeLock (Biometric)','Maglock 600','Yes','Online','Unassigned','','','','In','[{"date":"Jun 25, 2026","event":"Assessed","tech":"Unassigned"}]',''],
        ['Filling room 2','LML B Liquid Plant','Lasco','eyeLock (Biometric)','Maglock 600','Yes','Online','Unassigned','','','','In','[{"date":"Jun 25, 2026","event":"Assessed","tech":"Unassigned"}]',''],
        ['Filling room 3','LML B Liquid Plant','Lasco','eyeLock (Biometric)','Maglock 600','Yes','Online','Unassigned','','','','In','[{"date":"Jun 25, 2026","event":"Assessed","tech":"Unassigned"}]',''],
        ['Filling room 4','LML B Liquid Plant','Lasco','eyeLock (Biometric)','Maglock 600','Yes','Online','Unassigned','','','','In','[{"date":"Jun 25, 2026","event":"Assessed","tech":"Unassigned"}]',''],
        ['Guest access - IN','LML B Liquid Plant','Lasco','eyeLock (Biometric)','Maglock 600','Yes','Online','Unassigned','','','','In','[{"date":"Jun 25, 2026","event":"Assessed","tech":"Unassigned"}]',''],
        ['Guest access - OUT','LML B Liquid Plant','Lasco','eyeLock (Biometric)','—','Yes','Online','Unassigned','','','','Out','[{"date":"Jun 25, 2026","event":"Assessed","tech":"Unassigned"}]',''],
        ['Lobby','LML B Liquid Plant','Lasco','eyeLock (Biometric)','Maglock 600','Yes','Online','Unassigned','','','','In','[{"date":"Jun 25, 2026","event":"Assessed","tech":"Unassigned"}]',''],
        ['Microbiology lab','LML B Liquid Plant','Lasco','eyeLock (Biometric)','Maglock 600','Yes','Online','Unassigned','','','','In','[{"date":"Jun 25, 2026","event":"Assessed","tech":"Unassigned"}]',''],
        ['Prep Room','LML B Liquid Plant','Lasco','eyeLock (Biometric)','Maglock 600','Yes','Online','Unassigned','','','','In','[{"date":"Jun 25, 2026","event":"Assessed","tech":"Unassigned"}]',''],
        ['Processing room 1','LML B Liquid Plant','Lasco','—','—','Not In Use','Offline','Unassigned','','','','In','[{"date":"Jun 25, 2026","event":"Assessed","tech":"Unassigned"}]','No longer use, equipment has been removed'],
        ['Processing room 2','LML B Liquid Plant','Lasco','eyeLock (Biometric)','Maglock 600','Yes','Online','Unassigned','','','','In','[{"date":"Jun 25, 2026","event":"Assessed","tech":"Unassigned"}]',''],
        ['Product dev lab','LML B Liquid Plant','Lasco','eyeLock (Biometric)','Maglock 600','Yes','Online','Unassigned','','','','In','[{"date":"Jun 25, 2026","event":"Assessed","tech":"Unassigned"}]',''],
        ['Production floor - IN','LML B Liquid Plant','Lasco','eyeLock (Biometric)','Maglock 600','Yes','Online','Unassigned','','','','In','[{"date":"Jun 25, 2026","event":"Assessed","tech":"Unassigned"}]',''],
        ['Production floor - OUT','LML B Liquid Plant','Lasco','eyeLock (Biometric)','—','Yes','Online','Unassigned','','','','Out','[{"date":"Jun 25, 2026","event":"Assessed","tech":"Unassigned"}]',''],
        ['QA office','LML B Liquid Plant','Lasco','eyeLock (Biometric)','Maglock 600','Yes','Online','Unassigned','','','','In','[{"date":"Jun 25, 2026","event":"Assessed","tech":"Unassigned"}]',''],
        ['Shop and spare parts','LML B Liquid Plant','Lasco','eyeLock (Biometric)','Maglock 600','Yes','Online','Unassigned','','','','In','[{"date":"Jun 25, 2026","event":"Assessed","tech":"Unassigned"}]','']
      ];
      for (const door of doors) {
        await pool.query(`INSERT INTO doors (name, site, client, reader, lock_type, powered, status, tech, ip_address, controller, last_service, access_direction, history, comments) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13::jsonb,$14) ON CONFLICT (name) DO NOTHING`, door);
      }
      console.log('✅ Doors seeded (' + doors.length + ' doors)');
    }

    // ── SEED SERVERS ──────────────────────────────────
    const serversCheck = await pool.query("SELECT COUNT(*) FROM servers");
    if (parseInt(serversCheck.rows[0].count) === 0) {
      console.log('🌱 Seeding servers...');
      const servers = [
        ['Kingport','J1013DDR','6.11TB','1.4TB','Good (23%)','Ocularis DM5, LPR','ONLINE'],
        ['Kingport','9B0F842','930GB','74GB','Good','Ocularis, LPR','ONLINE'],
        ['Kingport','J1013DDV','6.11TB','1.4TB','Good, Failed drive','Ocularis DM6, Eyelock','ONLINE'],
        ['Kingport','J1013N50','32TB','—','Good','—','ONLINE'],
        ['Kingport','J1013DDW','6.11TB','1.4TB','Good (23%)','Ocularis DM4, Access Control','ONLINE'],
        ['Kingport','J1013N4Z','32TB','—','Good','—','ONLINE'],
        ['Kingport','J1013DDT','6.11TB','1.37TB','Good (23%)','Node in Failure','ONLINE'],
        ['Kingport','J1013N4Y','—','32TB','Good','—','ONLINE'],
        ['Kingport','J1013DDX','45TB','178GB','Excellent','—','ONLINE']
      ];
      for (const srv of servers) {
        await pool.query(`INSERT INTO servers (location, serial, capacity, used, health, apps, status) VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (serial) DO NOTHING`, srv);
      }
      console.log('✅ Servers seeded');
    }

    // ── SEED SWITCHES ──────────────────────────────────
    const switchesCheck = await pool.query("SELECT COUNT(*) FROM switches");
    if (parseInt(switchesCheck.rows[0].count) === 0) {
      console.log('🌱 Seeding switches...');
      const switches = [
        ['Main Entrance','Security Office','AXIS T8508','10.19.1.21','6.54.2739','root','$upp@rt@202O','AC:CC:8E:FA:4B:1B'],
        ['2nd entrance','SAL Duty Office','AXIS T8516','10.19.1.23','6.54.2739','root','$upp@rt@202O','AC:CC:8E:B6:DF:99'],
        ['Exit gate','Gate Pass Office','AXIS T8516','10.19.1.22','6.54.2739','root','$upp@rt@202O','AC:CC:8E:B6:DD:5F'],
        ['LPR Overview','Gate Pass Office','AXIS T8516','10.19.1.32','6.54.2739','root','$upp@rt@202O','AC:CC:8E:B6:DD:26'],
        ['CarPark 4/Berth 4','Car Park 4 wall','AXIS T8508','10.19.1.38','6.54.2739','root','$upp@rt@202O','AC:CC:8E:FA:4F:A9'],
        ['Berth 5 Warehouse A','Upstairs','AXIS T8516','10.19.1.26','6.54.2739','root','$upp@rt@202O','AC:CC:8E:D7:8D:13'],
        ['Berth 5 Warehouse B','Stripping Office','AXIS T8508','10.19.1.37','6.54.2739','root','$upp@rt@202O','AC:CC:8E:FA:4B:10'],
        ['Berth 5 rear east','rear of warehouse','AXIS T8504-R','10.19.1.119','7.10.1595','root','$upp@rt@202O','AC:CC:8E:FA:E2:DF'],
        ['Berth 1 perimeter-A','Berth 1 Corner Wall','AXIS T8508','10.19.1.35','6.54.2739','root','$upp@rt@202O','AC:CC:8E:FA:4B:31'],
        ['Berth 1 perimeter-B','Berth 1 Middle Wall','AXIS T8508','10.19.1.36','6.54.2739','root','$upp@rt@202O','AC:CC:8E:FA:4F:B4'],
        ['Warehouse 2 A','Upstairs','AXIS T8516','10.19.1.27','6.54.2739','root','$upp@rt@202O','AC:CC:8E:B6:DD:39'],
        ['Warehouse 2 B','Down stairs','AXIS T8508','10.19.1.30','6.54.2739','root','$upp@rt@202O','AC:CC:8E:FA:49:9A'],
        ['Warehouse 1','Warehouse1/Spectrum','AXIS T8516','10.19.1.20','6.54.2739','root','$upp@rt@202O','AC:CC:8E:B6:DD:72'],
        ['Berth 8 B','Berth 8 East/West','AXIS T8504-R','10.19.1.33','7.10.1595','root','$upp@rt@202O','AC:CC:8E:FA:E3:1E'],
        ['Berth 8 A','Berth 8 Perimeter','TL-SG2210P','10.19.1.39','5.20.20','admin','$upp@rt@2020','BO:19:21::20:FF:F2']
      ];
      for (const sw of switches) {
        await pool.query(`INSERT INTO switches (name, location, model, ip_address, firmware, username, password, mac) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT (name) DO NOTHING`, sw);
      }
      console.log('✅ Switches seeded');
    }
    
    // ── SEED TICKETS ──────────────────────────────────
    const ticketsCheck = await pool.query("SELECT COUNT(*) FROM tickets");
    if (parseInt(ticketsCheck.rows[0].count) === 0) {
      console.log('🌱 Seeding tickets...');
      const tickets = [
        // ── Original Tickets ──
        ['SR-1847','KFTL','NORTH Zone','Replace defective cameras - NORTH zone','facilities@kftl.com','Camera','High','Open','Shanice Vernon','Jun 13, 2026','We need camera replacements in NORTH zone.','','[]','[{"time":"14:22","msg":"Created — assigned to Shanice (day shift)"}]','[]'],
        ['SR-1848','KWL','Tinson Pen','Tinson Pen switches need firmware check','security@kwl.com','Network','Medium','Open','Shanice Vernon','Jun 15, 2026','Tinson Pen switches need firmware check.','','[]','[{"time":"11:05","msg":"Created — assigned to Shanice (day shift)"}]','[]'],
        ['SR-1849','KFTL','Second Entrance','All 4 turnstiles offline','it@kftl.com','Access Control','High','In Progress','Marvin Grant','Jun 10, 2026','All turnstiles offline.','','[]','[{"time":"16:48","msg":"Created — assigned to Shavine (night shift)"},{"time":"17:00","msg":"Escalated to Marvin Grant for on-site repair"}]','[]'],
        ['SR-1850','KFTL','Kingport','Server J1013DDV failed drive','marvin.grant@etechsystems.com','Server','Medium','Open','Shavine','Jun 8, 2026','Server J1013DDV has failed drive.','','[]','[{"time":"09:12","msg":"Created — assigned to Shavine (night shift)"}]','[]'],

        // ── KWL Security Service Requests (from June 25, 2026 document) ──
        ['SR-1851','KFTL','TLF','Cam 117 TLF Car Park PTZ — Pixelated Images','vincent@lascoja.com','Camera','High','Open','Unassigned','Dec 1, 2025','Camera needs to be physically checked. MANLIFT required.','','[]','[{"time":"07:00","msg":"Created from KWL Security Control Centre log"}]','[]'],
        ['SR-1852','KFTL','KWC','Cam 280 Stripping Ramp 1 — Shifted Camera','vincent@lascoja.com','Camera','High','Open','Unassigned','May 19, 2026','Camera previously adjusted. Movement is from fan above.','','[]','[{"time":"07:00","msg":"Created from KWL Security Control Centre log"}]','[]'],
        ['SR-1853','KFTL','TLF','Cam 068 TLF Warehouse Receival Bay 13 & 14 — Blurred Camera','vincent@lascoja.com','Camera','High','Resolved','Unassigned','Jun 25, 2026','Blurred — Resolved.','','[]','[{"time":"14:06","msg":"Created from KWL Security Control Centre log"},{"time":"14:06","msg":"Status → Resolved"}]','[]'],
        ['SR-1854','KFTL','TLF','Cam 027 TLF Warehouse Aisles 10 & 11 — Blurred Camera','vincent@lascoja.com','Camera','High','Resolved','Unassigned','Jun 24, 2026','Blurred — Resolved.','','[]','[{"time":"15:40","msg":"Created from KWL Security Control Centre log"},{"time":"15:40","msg":"Status → Resolved"}]','[]'],
        ['SR-1855','KFTL','KWC','Cam 248 KWC Stripping Ramp 5 — Out of Focus','vincent@lascoja.com','Camera','High','Open','Unassigned','Mar 17, 2026','Camera lens shows signs of being defective. Lens not responding to attempts to focus.','','[]','[{"time":"07:00","msg":"Created from KWL Security Control Centre log"}]','[]'],
        ['SR-1856','KWL','GALC','Cam 263 TP Pole 47 Cam 1 — Out of Focus','vincent@lascoja.com','Camera','High','Open','Unassigned','Sep 16, 2025','Camera covering is crystalized. Camera dome needs to be replaced.','','[]','[{"time":"07:00","msg":"Created from KWL Security Control Centre log"}]','[]'],
        ['SR-1857','KWL','GALC','Cam 235 TP Pole 42 Cam 2 — Out of Focus','vincent@lascoja.com','Camera','High','Open','Unassigned','Sep 16, 2025','Camera covering is crystalized. Camera dome needs to be replaced.','','[]','[{"time":"07:00","msg":"Created from KWL Security Control Centre log"}]','[]'],
        ['SR-1858','KFTL','PORT','Cam 361 KWL Port Berth 1 Corner — Navigational Difficulty','vincent@lascoja.com','Camera','High','Open','Unassigned','Apr 28, 2026','Camera rebooted & settings changed. Camera will not accept configuration changes after reboot.','','[]','[{"time":"07:00","msg":"Created from KWL Security Control Centre log"}]','[]'],
        ['SR-1859','KWL','GALC','Cam 246 TP Pole 11 PTZ — Intermittent Disconnections','vincent@lascoja.com','Camera','High','Open','Unassigned','Mar 14, 2026','Camera defective.','','[]','[{"time":"07:00","msg":"Created from KWL Security Control Centre log"}]','[]'],
        ['SR-1860','KFTL','Port','Cam 402 Port Berth 1 OP South — Disconnected','vincent@lascoja.com','Camera','High','Open','Unassigned','Mar 22, 2026','CAMERA DEFECTIVE.','','[]','[{"time":"07:00","msg":"Created from KWL Security Control Centre log"}]','[]'],
        ['SR-1861','KWL','GALC','Cam 282 TP Pole 21 Cam 1 — Disconnected','vincent@lascoja.com','Camera','High','Open','Unassigned','May 29, 2026','Camera defective needs to be replaced.','','[]','[{"time":"07:00","msg":"Created from KWL Security Control Centre log"}]','[]'],
        ['SR-1862','KWL','GALC','Cam 209 TP Pole 2 Cam 2 — Disconnected','vincent@lascoja.com','Camera','High','Open','Unassigned','May 28, 2026','Cable needs to be replaced.','','[]','[{"time":"07:00","msg":"Created from KWL Security Control Centre log"}]','[]'],
        ['SR-1863','KWL','GALC','Cam 215 TP Pole 37 Cam 2 — Disconnected','vincent@lascoja.com','Camera','High','Open','Unassigned','May 25, 2026','Cable needs to be replaced.','','[]','[{"time":"07:00","msg":"Created from KWL Security Control Centre log"}]','[]'],
        ['SR-1864','KWL','GALC','Cam 208 TP Pole 6 Cam 2 — Disconnected','vincent@lascoja.com','Camera','High','Open','Unassigned','Feb 23, 2026','Switch only has 1 working port which cam 1 is plugged into (Previously updated).','','[]','[{"time":"07:00","msg":"Created from KWL Security Control Centre log"}]','[]'],
        ['SR-1865','KFTL','Port','Cam 439 KWL Port Berth 4 Pylon East — Disconnected','vincent@lascoja.com','Camera','High','Open','Unassigned','Feb 3, 2026','Camera gets connection from Berth 5. Berth 5 is offline.','','[]','[{"time":"07:00","msg":"Created from KWL Security Control Centre log"}]','[]'],
        ['SR-1866','KWL','GALC','Cam 219 TP Pole 25 cam 1 — Disconnected','vincent@lascoja.com','Camera','High','Open','Unassigned','Feb 1, 2026','Fibre damaged. Fibre needs to be repaired.','','[]','[{"time":"07:00","msg":"Created from KWL Security Control Centre log"}]','[]'],
        ['SR-1867','KWL','GALC','Cam 310 TP Pole 25 cam 2 — Disconnected','vincent@lascoja.com','Camera','High','Open','Unassigned','Feb 1, 2026','Fibre damaged. Fibre needs to be repaired.','','[]','[{"time":"07:00","msg":"Created from KWL Security Control Centre log"}]','[]'],
        ['SR-1868','KFTL','Port','Cam 254 TP Pole 33 Cam 1 — Disconnected','vincent@lascoja.com','Camera','High','Open','Unassigned','Jan 12, 2026','Switch Enclosure damaged, needs to be replaced. Switch damaged needs to be replaced. Camera tested okay.','','[]','[{"time":"07:00","msg":"Created from KWL Security Control Centre log"}]','[]'],
        ['SR-1869','KFTL','KWC','Cam 279 KWC Stripping Ramp PTZ — Disconnected','vincent@lascoja.com','Camera','High','Open','Unassigned','Jan 6, 2025','Camera defective.','','[]','[{"time":"07:00","msg":"Created from KWL Security Control Centre log"}]','[]'],
        ['SR-1870','KFTL','KWC','Cam 303 KWC Vehicular Exit — Disconnected','vincent@lascoja.com','Camera','High','Open','Unassigned','Nov 18, 2025','CABLE NEEDS TO BE CHANGED.','','[]','[{"time":"07:00","msg":"Created from KWL Security Control Centre log"}]','[]'],
        ['SR-1871','KWL','GALC','Cam 237 TP Pole 8 Cam 1 — Disconnected','vincent@lascoja.com','Camera','High','Open','Unassigned','Oct 24, 2025','Water inside of camera.','','[]','[{"time":"07:00","msg":"Created from KWL Security Control Centre log"}]','[]'],
        ['SR-1872','KFTL','TLF','Cam 090 TLF Receival External Perimeter PTZ — Disconnected','vincent@lascoja.com','Camera','High','Open','Unassigned','Sep 15, 2025','CABLE NEEDS TO BE CHANGED.','','[]','[{"time":"07:00","msg":"Created from KWL Security Control Centre log"}]','[]'],
        ['SR-1873','KFTL','PORT','Cam 346 Port Exit Gate Lane 6 LPR — Colour Scale Issues','vincent@lascoja.com','Camera','High','Open','Unassigned','May 16, 2026','Camera defective.','','[]','[{"time":"07:00","msg":"Created from KWL Security Control Centre log"}]','[]'],
        ['SR-1874','KWL','GALC','Cam 308 TP Pole 34 PTZ — Colour Scale Issues','vincent@lascoja.com','Camera','High','Open','Unassigned','Feb 8, 2026','Camera defective, lens defective.','','[]','[{"time":"07:00","msg":"Created from KWL Security Control Centre log"}]','[]'],
        ['SR-1875','KWL','WH1','Cam 397 WH1 Receival Bay Door — Colour Scale Issues','vincent@lascoja.com','Camera','High','Open','Unassigned','Sep 30, 2025','IR lens defective.','','[]','[{"time":"07:00","msg":"Created from KWL Security Control Centre log"}]','[]']
      ];
      for (const ticket of tickets) {
        await pool.query(`INSERT INTO tickets (id, client, site, subject, from_email, category, priority, status, assigned, received, body, notes, hardware, history, attachments) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13::jsonb,$14::jsonb,$15::jsonb)`, ticket);
      }
      console.log('✅ Tickets seeded (' + tickets.length + ' tickets)');
    }

    // ── SEED AUDIT LOGS ──────────────────────────────────
    const auditCheck = await pool.query("SELECT COUNT(*) FROM audit_logs");
    if (parseInt(auditCheck.rows[0].count) === 0) {
      console.log('🌱 Seeding audit logs...');
      const auditEntries = [
        ['14:32','Shanice Vernon','updated','SR-1847 → In Progress'],
        ['13:50','Marvin Grant','updated','HM3 PTZ comment → "Defective"'],
        ['12:00','System','converted','David Chen → SR-1848'],
        ['11:30','System','sync','Camera_Maintenance_2025.csv ✅'],
        ['10:45','System','sync','Access_Control_Survey.csv ⚠️'],
        ['07:00','System','created','25 KWL Security Control Centre tickets imported']
      ];
      for (const entry of auditEntries) {
        await pool.query(`INSERT INTO audit_logs (time, username, action, target) VALUES ($1,$2,$3,$4)`, entry);
      }
      console.log('✅ Audit logs seeded');
    }

    // ── SEED EMAILS ──────────────────────────────────
    const emailsCheck = await pool.query("SELECT COUNT(*) FROM emails");
    if (parseInt(emailsCheck.rows[0].count) === 0) {
      console.log('🌱 Seeding emails...');
      const emails = [
        ['e1','David Chen','facilities@kftl.com','support@etechsystems.com','Replace defective cameras - NORTH zone','Hi team,\n\nWe did a walk-through of the NORTH zone yesterday and counted at least 8 cameras showing as defective on the wall display, including HM3, HM11, HM23, and N25. A few of these have been down for over a week now and we are getting questions from the warehouse supervisors about blind spots near the loading bays.\n\nCan someone confirm a timeline for replacement or repair? Happy to provide access to the affected areas whenever a technician is available.\n\nThanks,\nDavid','Jun 15, 2026 14:22','[]',true,'SR-1847',true,'KFTL'],
        ['e2','Andrea Williams','security@kwl.com','support@etechsystems.com','URGENT: 5 Cameras Offline - Tinson Pen','This is urgent — we have 5 cameras down simultaneously at Tinson Pen as of this morning, all on the same switch it looks like. Given the recent perimeter alarm activity in that area, we need eyes back up there as soon as possible.\n\nPlease advise on ETA and let me know if you need anyone on-site to assist.\n\nAndrea Williams\nSecurity Manager, KWL','Jun 15, 2026 11:05','[]',true,'SR-1848',true,'KWL'],
        ['e3','IT Department','it@kftl.com','support@etechsystems.com','ASAP: Access Doors - Second Entrance Offline','All four turnstiles at the Second Entrance (staff entry/exit 1 and 2) are showing offline on our side and staff are being let in manually by the guard on duty, which is not sustainable for a full shift.\n\nCan you escalate this for an on-site technician visit today? Let us know what time works.\n\nIT Department','Jun 14, 2026 16:48','[]',true,'SR-1849',true,'KFTL'],
        ['e4','Marvin Grant','marvin.grant@etechsystems.com','support@etechsystems.com','Server J1013DDV - drive failure follow-up','Following up on the failed drive alert for J1013DDV at Kingport. I swapped the bad drive on-site this morning and the array is rebuilding now — should be back to full redundancy within a few hours. Will update once it is confirmed healthy.\n\nNo action needed from support right now, just wanted it on record.\n\nMarvin','Jun 8, 2026 09:30','[]',true,'SR-1850',false,'KFTL'],
        ['e5','Patricia Lowe','plowe@kwl.com','support@etechsystems.com','Question about camera coverage report','Good afternoon,\n\nOur ops manager asked for a coverage summary of all cameras at the Tinson Pen and Warehouse 2 sites for an upcoming insurance review. Is this something your team can pull together, and if so what is the usual turnaround?\n\nNo rush on this one — end of month would be perfectly fine.\n\nBest,\nPatricia Lowe','Jun 12, 2026 10:15','[]',false,null,false,'KWL'],
        ['e6','Gate Pass Office','gatepass@kftl.com','support@etechsystems.com','Switch firmware update window - LPR Overview','We noticed the LPR Overview switch at Gate Pass Office is showing firmware 6.54.2739 still, while I believe a newer version was rolled out to most other switches last month. Is this one scheduled for update, or did it get missed?\n\nLet us know if there is anything needed from our side to schedule a maintenance window.','Jun 17, 2026 08:50','[]',false,null,false,'KFTL'],
        ['e7','Shanice Vernon','shanice.vernon@etechsystems.com','support@etechsystems.com','Heads up - recurring issue on HM3 PTZ','Just flagging that HM3 PTZ has now gone defective for the third time this quarter. Each time it has been a different symptom (no signal, then power, now showing defective again with no obvious cause). Might be worth a full unit swap instead of another spot repair next time someone is on-site.\n\nLogged as part of SR-1847 for now.','Jun 16, 2026 13:05','[]',false,null,false,'KFTL'],
        ['e8','Wharfage Office','wharfage@kftl.com','support@etechsystems.com','Cashier window cameras - picture quality','The cameras covering Cashier Windows 1-3 at the Wharfage Office have looked noticeably grainy/low quality on the live feed for the past few days, even though they are reporting Online. Could be a settings or firmware thing rather than a hardware fault. Can someone take a look when they get a chance? Not urgent.','Jun 19, 2026 15:40','[]',false,null,false,'KFTL']
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
    const { code, code_verifier } = req.body;
    if (!code) return res.status(400).json({ error: 'Authorization code required' });

    const clientId = process.env.MS_CLIENT_ID || 'e87a6592-aaa5-4a13-9c85-8dbc8e9cd7b2';
    const redirectUri = process.env.MS_REDIRECT_URI || 'https://e-tech-ccsm-production-19f0.up.railway.app';
    const tenantId = process.env.MS_TENANT_ID || '799ae988-9d3d-40d3-bf5c-93197f5d8d44';

    const params = new URLSearchParams({
      client_id: clientId,
      scope: 'https://graph.microsoft.com/Sites.Read.All Files.Read.All User.Read',
      code: code,
      redirect_uri: redirectUri,
      grant_type: 'authorization_code'
    });

    if (code_verifier) { params.append('code_verifier', code_verifier); }

    const tokenResponse = await fetch(
      `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/token`,
      { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: params.toString() }
    );

    const data = await tokenResponse.json();
    if (data.error) { console.error('Token exchange error:', data); return res.status(400).json({ error: data.error_description || data.error }); }
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
    const siteResponse = await fetch('https://graph.microsoft.com/v1.0/sites/etechsystemsltd.sharepoint.com:/sites/Share', { headers: { Authorization: 'Bearer ' + accessToken } });
    const siteData = await siteResponse.json();
    const driveResponse = await fetch('https://graph.microsoft.com/v1.0/sites/' + siteData.id + '/drives', { headers: { Authorization: 'Bearer ' + accessToken } });
    const drives = await driveResponse.json();
    const documentsDrive = drives.value.find(function(d) { return d.name === 'Documents'; });
    const childrenResponse = await fetch('https://graph.microsoft.com/v1.0/drives/' + documentsDrive.id + '/root:/E-Tech%20Maintenance:/children', { headers: { Authorization: 'Bearer ' + accessToken } });
    const folderData = await childrenResponse.json();
    const allFiles = [];
    for (let i = 0; i < folderData.value.length; i++) {
      const item = folderData.value[i];
      if (item.folder) {
        const subResponse = await fetch('https://graph.microsoft.com/v1.0/drives/' + documentsDrive.id + '/items/' + item.id + '/children', { headers: { Authorization: 'Bearer ' + accessToken } });
        const subData = await subResponse.json();
        for (let j = 0; j < subData.value.length; j++) {
          const file = subData.value[j];
          if (!file.folder) {
            allFiles.push({ name: file.name, type: getFileType(file.name), size: formatFileSize(file.size), modified: new Date(file.lastModifiedDateTime).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' }), downloadUrl: file['@microsoft.graph.downloadUrl'], client: item.name, status: 'synced' });
          }
        }
      } else {
        allFiles.push({ name: item.name, type: getFileType(item.name), size: formatFileSize(item.size), modified: new Date(item.lastModifiedDateTime).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' }), downloadUrl: item['@microsoft.graph.downloadUrl'], client: 'Root', status: 'synced' });
      }
    }
    return allFiles;
  } catch (error) { console.error('SharePoint fetch error:', error); return null; }
}

app.get('/api/sharepoint/sync', authenticate, async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    const graphToken = authHeader ? authHeader.split(' ')[1] : null;
    if (!graphToken) return res.status(401).json({ error: 'Microsoft Graph token required' });
    const files = await fetchSharePointFiles(graphToken);
    if (!files) return res.status(500).json({ error: 'Failed to fetch SharePoint files' });
    res.json({ data: files, count: files.length });
  } catch (error) { res.status(500).json({ error: error.message }); }
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
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// ── CAMERAS ─────────────────────────────────────────────
app.get('/api/cameras', authenticate, async (req, res) => {
  try { const result = await pool.query('SELECT * FROM cameras ORDER BY zone, name'); res.json({ data: result.rows }); }
  catch (error) { res.status(500).json({ error: error.message }); }
});
app.put('/api/cameras/:name', authenticate, async (req, res) => {
  try {
    const { name } = req.params; const { comments, status, model, resolution } = req.body;
    const fields = []; const values = []; let counter = 1;
    if (comments !== undefined) { fields.push('comments = $' + counter); values.push(comments); counter++; }
    if (status !== undefined) { fields.push('status = $' + counter); values.push(status); counter++; }
    if (model !== undefined) { fields.push('model = $' + counter); values.push(model); counter++; }
    if (resolution !== undefined) { fields.push('resolution = $' + counter); values.push(resolution); counter++; }
    fields.push('updated_at = CURRENT_TIMESTAMP'); values.push(name);
    await pool.query('UPDATE cameras SET ' + fields.join(', ') + ' WHERE name = $' + counter, values);
    res.json({ success: true });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// ── DOORS ─────────────────────────────────────────────────
app.get('/api/doors', authenticate, async (req, res) => {
  try { const result = await pool.query('SELECT *, lock_type AS lock, ip_address AS ip, last_service AS date FROM doors ORDER BY site, name'); res.json({ data: result.rows }); }
  catch (error) { res.status(500).json({ error: error.message }); }
});
app.put('/api/doors/:name', authenticate, async (req, res) => {
  try {
    const { name } = req.params; const { status, tech, comments } = req.body;
    if (status !== undefined) await pool.query('UPDATE doors SET status = $1, updated_at = CURRENT_TIMESTAMP WHERE name = $2', [status, name]);
    if (tech !== undefined) await pool.query('UPDATE doors SET tech = $1, updated_at = CURRENT_TIMESTAMP WHERE name = $2', [tech, name]);
    if (comments !== undefined) await pool.query('UPDATE doors SET comments = $1, updated_at = CURRENT_TIMESTAMP WHERE name = $2', [comments, name]);
    res.json({ success: true });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// ── SERVERS ──────────────────────────────────────────────
app.get('/api/servers', authenticate, async (req, res) => {
  try { const result = await pool.query('SELECT * FROM servers ORDER BY location, serial'); res.json({ data: result.rows }); }
  catch (error) { res.status(500).json({ error: error.message }); }
});
app.put('/api/servers/:serial', authenticate, async (req, res) => {
  try {
    const { serial } = req.params; const { comments } = req.body;
    if (comments !== undefined) await pool.query('UPDATE servers SET comments = $1, updated_at = CURRENT_TIMESTAMP WHERE serial = $2', [comments, serial]);
    res.json({ success: true });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// ── SWITCHES ─────────────────────────────────────────────
app.get('/api/switches', authenticate, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM switches ORDER BY location, name');
    const masked = result.rows.map(function(row) { return { ...row, password: row.password ? '••••••••' : null }; });
    res.json({ data: masked });
  } catch (error) { res.status(500).json({ error: error.message }); }
});
app.get('/api/switches/:id/reveal-password', authenticate, async (req, res) => {
  try {
    const { id } = req.params;
    const result = await pool.query('SELECT id, name, password FROM switches WHERE id = $1', [id]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'Switch not found' });
    const now = new Date(); const timeStr = now.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
    await pool.query('INSERT INTO audit_logs (time, username, action, target) VALUES ($1, $2, $3, $4)', [timeStr, req.user.username, 'revealed credential', 'Switch ' + result.rows[0].name + ' password']);
    res.json({ password: result.rows[0].password });
  } catch (error) { res.status(500).json({ error: error.message }); }
});
app.put('/api/switches/:name', authenticate, async (req, res) => {
  try {
    const { name } = req.params; const { comments } = req.body;
    if (comments !== undefined) await pool.query('UPDATE switches SET comments = $1, updated_at = CURRENT_TIMESTAMP WHERE name = $2', [comments, name]);
    res.json({ success: true });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// ── TICKETS ──────────────────────────────────────────────
app.get('/api/tickets', authenticate, async (req, res) => {
  try { const result = await pool.query('SELECT * FROM tickets ORDER BY created_at DESC'); res.json({ data: result.rows }); }
  catch (error) { res.status(500).json({ error: error.message }); }
});
app.post('/api/tickets', authenticate, async (req, res) => {
  try {
    const { id, client, site, subject, from_email, category, priority, status, assigned, received, body, notes, hardware, history, attachments } = req.body;
    await pool.query('INSERT INTO tickets (id, client, site, subject, from_email, category, priority, status, assigned, received, body, notes, hardware, history, attachments) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13::jsonb,$14::jsonb,$15::jsonb)', [id, client, site, subject, from_email, category, priority, status, assigned, received, body, notes, JSON.stringify(hardware || []), JSON.stringify(history || []), JSON.stringify(attachments || [])]);
    res.json({ success: true, id });
  } catch (error) { res.status(500).json({ error: error.message }); }
});
app.put('/api/tickets/:id', authenticate, async (req, res) => {
  try {
    const { id } = req.params; const { status, assigned, notes, priority, category } = req.body;
    const fields = []; const values = []; let counter = 1;
    if (status !== undefined) { fields.push('status = $' + counter); values.push(status); counter++; }
    if (assigned !== undefined) { fields.push('assigned = $' + counter); values.push(assigned); counter++; }
    if (notes !== undefined) { fields.push('notes = $' + counter); values.push(notes); counter++; }
    if (priority !== undefined) { fields.push('priority = $' + counter); values.push(priority); counter++; }
    if (category !== undefined) { fields.push('category = $' + counter); values.push(category); counter++; }
    fields.push('updated_at = CURRENT_TIMESTAMP'); values.push(id);
    await pool.query('UPDATE tickets SET ' + fields.join(', ') + ' WHERE id = $' + counter, values);
    res.json({ success: true });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// ── AUDIT LOG ────────────────────────────────────────────
app.get('/api/audit', authenticate, async (req, res) => {
  try { const limit = parseInt(req.query.limit) || 50; const result = await pool.query('SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT $1', [limit]); res.json({ data: result.rows }); }
  catch (error) { res.status(500).json({ error: error.message }); }
});
app.post('/api/audit', authenticate, async (req, res) => {
  try {
    const { user, action, target } = req.body; const now = new Date(); const timeStr = now.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
    await pool.query('INSERT INTO audit_logs (time, username, action, target) VALUES ($1, $2, $3, $4)', [timeStr, user || req.user.username, action, target]);
    res.json({ success: true });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// ── INBOX ────────────────────────────────────────────────
app.get('/api/inbox', authenticate, async (req, res) => {
  try { const result = await pool.query('SELECT * FROM emails ORDER BY created_at DESC'); res.json({ data: result.rows }); }
  catch (error) { res.status(500).json({ error: error.message }); }
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
    const camerasDefective = parseInt(camRes.rows[0].count); const doorsOffline = parseInt(doorRes.rows[0].count);
    const serversOnline = parseInt(srvRes.rows[0].online); const serversTotal = parseInt(srvRes.rows[0].total);
    const switchesTotal = parseInt(swRes.rows[0].total);

    await pool.query('INSERT INTO dashboard_snapshots (snapshot_date, cameras_defective, doors_offline, servers_online, servers_total, switches_total) VALUES (CURRENT_DATE, $1, $2, $3, $4, $5) ON CONFLICT (snapshot_date) DO UPDATE SET cameras_defective = $1, doors_offline = $2, servers_online = $3, servers_total = $4, switches_total = $5', [camerasDefective, doorsOffline, serversOnline, serversTotal, switchesTotal]);

    const baseline = await pool.query("SELECT * FROM dashboard_snapshots WHERE snapshot_date <= CURRENT_DATE - INTERVAL '7 days' ORDER BY snapshot_date DESC LIMIT 1");
    function pctChange(current, past) { if (past === null || past === undefined || past === 0) return null; return Math.round(((current - past) / past) * 100); }
    const base = baseline.rows[0] || null;
    res.json({ data: { camerasDefective: { value: camerasDefective, trendPct: base ? pctChange(camerasDefective, base.cameras_defective) : null }, doorsOffline: { value: doorsOffline, trendPct: base ? pctChange(doorsOffline, base.doors_offline) : null }, serversOnline: { value: serversOnline, total: serversTotal, trendPct: base ? pctChange(serversOnline, base.servers_online) : null }, switchesTotal: { value: switchesTotal, trendPct: base ? pctChange(switchesTotal, base.switches_total) : null }, comparisonAvailable: !!base, comparisonPeriodDays: 7 } });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// ── HEALTH CHECK ────────────────────────────────────────
app.get('/api/health', (req, res) => { res.json({ status: 'ok', timestamp: new Date().toISOString() }); });

// ── SERVE FRONTEND ───────────────────────────────────────
app.use(express.static(__dirname));
app.get('*', (req, res, next) => { if (req.path.startsWith('/api/')) return next(); res.sendFile(path.join(__dirname, 'index.html')); });

// ── ERROR HANDLER ──────────────────────────────────────
app.use((err, req, res, next) => { console.error('❌ Error:', err.stack); res.status(500).json({ error: err.message || 'Internal server error' }); });

// ── START SERVER ────────────────────────────────────────
async function startServer() {
  try {
    await initDatabase();
    await seedData();
    app.listen(PORT, () => { console.log('✅ CCSM Backend running on http://localhost:' + PORT); console.log('📡 API endpoint: http://localhost:' + PORT + '/api'); console.log('🔑 Default login: admin / admin123'); });
  } catch (error) { console.error('❌ Failed to start server:', error.message); process.exit(1); }
}
startServer();

process.on('SIGTERM', async () => { console.log('🛑 Shutting down...'); await pool.end(); process.exit(0); });
process.on('SIGINT', async () => { console.log('🛑 Shutting down...'); await pool.end(); process.exit(0); });
