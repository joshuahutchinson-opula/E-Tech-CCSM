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
  origin: true,
  credentials: true
}));

app.use(express.json({ limit: '10mb' }));

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  trustProxy: true,
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
        resolution VARCHAR(50),
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

    // Check if admin exists
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
  // ===== PELCO CAMERAS =====
  ['HM3 PTZ', 'NORTH', 'Defective', '172.17.102.218', 'admin', 'Pelco P2820-ESR', '1920x1080 (2MP)', 'Defective'],
  ['HM4 PTZ', 'NORTH', 'Online', '172.17.102.219', 'admin', 'Pelco P2820-ESR', '1920x1080 (2MP)', 'Pelco PTZ camera'],
  ['HM5 PTZ', 'NORTH', 'Online', '172.17.102.223', 'admin', 'Pelco P2820-ESR', '1920x1080 (2MP)', 'Pelco PTZ camera'],
  ['HM8 PTZ', 'NORTH', 'Online', '172.17.102.221', 'administrator', 'Pelco P2820-ESR', '1920x1080 (2MP)', 'Pelco PTZ camera'],
  ['HM10 PTZ', 'NORTH', 'Defective', '172.17.102.224', 'admin', 'Pelco P2820-ESR', '1920x1080 (2MP)', 'Keeps resetting'],
  ['HM11 PTZ', 'NORTH', 'Defective', '172.17.102.225', 'admin', 'Pelco P2820-ESR', '1920x1080 (2MP)', 'Keeps resetting'],
  ['HM23 PTZ', 'NORTH', 'Offline', '172.17.102.200', 'admin', 'Pelco P2820-ESR', '1920x1080 (2MP)', 'Offline'],
  ['HM28 PTZ', 'NORTH', 'Online', '172.17.102.202', 'admin', 'Pelco P2820-ESR', '1920x1080 (2MP)', 'Online'],
  ['N25 PTZ', 'NORTH', 'Defective', '172.17.102.216', 'administrator', 'Pelco P2820-ESR', '1920x1080 (2MP)', 'Defective'],
  ['N30 PTZ', 'NORTH', 'Online', '172.17.102.210', 'admin', 'Pelco P2820-ESR', '1920x1080 (2MP)', 'Online'],
  ['A1 PTZ', 'NORTH', 'Online', '172.17.103.30', 'admin', 'Pelco P2820-ESR', '1920x1080 (2MP)', 'Active PTZ camera'],
  ['A2 PTZ', 'NORTH', 'Online', '172.17.103.31', 'admin', 'Pelco P2820-ESR', '1920x1080 (2MP)', 'Active PTZ camera'],
  ['A4 PTZ', 'SOUTH', 'Online', '172.17.103.33', 'admin', 'Pelco P2820-ESR', '1920x1080 (2MP)', 'Active PTZ camera'],
  ['A5 PTZ', 'SOUTH', 'Online', '172.17.103.34', 'admin', 'Pelco P2820-ESR', '1920x1080 (2MP)', 'Active PTZ camera'],
  ['A6 PTZ', 'SOUTH', 'Offline', '172.17.103.35', 'administrator', 'Pelco P2820-ESR', '1920x1080 (2MP)', 'Offline'],
  ['A7 PTZ', 'SOUTH', 'Offline', '172.17.103.36', 'admin', 'Pelco P2820-ESR', '1920x1080 (2MP)', 'Offline'],
  ['A8 PTZ', 'SOUTH', 'Offline', '172.17.103.37', 'admin', 'Pelco P2820-ESR', '1920x1080 (2MP)', 'Offline'],
  ['A10 PTZ', 'SOUTH', 'Online', '172.17.103.39', 'admin', 'Pelco P2820-ESR', '1920x1080 (2MP)', 'Online'],
  ['A11 PTZ', 'SOUTH', 'Online', '172.17.103.40', 'admin', 'Pelco P2820-ESR', '1920x1080 (2MP)', 'Online'],
  ['A12 PTZ', 'SOUTH', 'Online', '172.17.103.41', 'admin', 'Pelco P2820-ESR', '1920x1080 (2MP)', 'Online'],
  ['B1 PTZ', 'WEST', 'Online', '172.17.103.60', 'admin', 'Pelco P2820-ESR', '1920x1080 (2MP)', 'PTZ camera'],
  ['B2 PTZ', 'WEST', 'Online', '172.17.103.61', 'admin', 'Pelco P2820-ESR', '1920x1080 (2MP)', 'PTZ camera'],
  ['B5 PTZ', 'WEST', 'Offline', '172.17.103.63', 'admin', 'Pelco P2820-ESR', '1920x1080 (2MP)', 'Offline'],
  ['B6 PTZ', 'WEST', 'Online', '172.17.103.64', 'admin', 'Pelco P2820-ESR', '1920x1080 (2MP)', 'PTZ camera'],
  ['B8 PTZ', 'WEST', 'Online', '172.17.103.66', 'administrator', 'Pelco P2820-ESR', '1920x1080 (2MP)', 'PTZ camera'],
  ['B9 PTZ', 'WEST', 'Online', '172.17.103.67', 'administrator', 'Pelco P2820-ESR', '1920x1080 (2MP)', 'PTZ camera'],
  ['B10 PTZ', 'WEST', 'Online', '172.17.103.68', 'admin', 'Pelco P2820-ESR', '1920x1080 (2MP)', 'PTZ camera'],
  ['B11 PTZ', 'WEST', 'Online', '172.17.103.69', 'administrator', 'Pelco P2820-ESR', '1920x1080 (2MP)', 'PTZ camera'],
  ['B12 PTZ', 'WEST', 'Online', '172.17.103.70', 'admin', 'Pelco P2820-ESR', '1920x1080 (2MP)', 'PTZ camera'],
  ['C1 PTZ', 'SOUTH', 'Offline', '172.17.103.81', 'admin', 'Pelco P2820-ESR', '1920x1080 (2MP)', 'Offline'],
  ['C2 PTZ', 'SOUTH', 'Online', '172.17.103.82', 'administrator', 'Pelco P2820-ESR', '1920x1080 (2MP)', 'PTZ camera'],
  ['C4 PTZ', 'SOUTH', 'Online', '172.17.103.83', 'administrator', 'Pelco P2820-ESR', '1920x1080 (2MP)', 'PTZ camera'],
  ['C9 PTZ', 'SOUTH', 'Online', '172.17.103.143', 'admin', 'Pelco P2820-ESR', '1920x1080 (2MP)', 'PTZ camera'],
  ['C11 PTZ', 'SOUTH', 'Offline', '172.17.103.85', 'administrator', 'Pelco P2820-ESR', '1920x1080 (2MP)', 'Offline'],
  ['D4 PTZ', 'EAST', 'Online', '172.17.103.99', 'admin', 'Pelco P2820-ESR', '1920x1080 (2MP)', 'PTZ camera'],
  ['D5 PTZ', 'EAST', 'Online', '172.17.103.100', 'administrator', 'Pelco P2820-ESR', '1920x1080 (2MP)', 'PTZ camera'],
  ['D10 PTZ', 'EAST', 'Online', '172.17.103.104', 'administrator', 'Pelco P2820-ESR', '1920x1080 (2MP)', 'PTZ camera'],
  ['D12 PTZ', 'EAST', 'Online', '172.17.103.105', 'admin', 'Pelco P2820-ESR', '1920x1080 (2MP)', 'PTZ camera'],
  ['Manager Car Park PTZ', 'NORTH', 'Defective', '172.17.102.186', 'administrator', 'Pelco P2820-ESR', '1920x1080 (2MP)', 'Defective'],
  ['Visitor Car Park Ptz 1', 'NORTH', 'Online', '172.17.102.184', 'administrator', 'Pelco P2820-ESR', '1920x1080 (2MP)', 'PTZ camera'],
  ['Visitor Car Park Ptz 2', 'NORTH', 'Online', '172.17.102.185', 'administrator', 'Pelco P2820-ESR', '1920x1080 (2MP)', 'PTZ camera'],
  ['SW Corner Perim PTZ', 'NORTH', 'Online', '172.17.102.155', 'admin', 'Pelco P2820-ESR', '1920x1080 (2MP)', 'To be replaced'],
  ['South Perim PTZ', 'SOUTH', 'Online', '172.17.103.86', 'admin', 'Pelco P2820-ESR', '1920x1080 (2MP)', 'PTZ camera'],
  ['Toll Gate Entry PTZ', 'NORTH', 'Online', '172.17.102.182', 'administrator', 'Pelco P2820-ESR', '1920x1080 (2MP)', 'PTZ camera'],
  ['Wharfage Perim N Exit Gate PTZ', 'NORTH', 'Online', '172.17.102.183', 'administrator', 'Pelco P2820-ESR', '1920x1080 (2MP)', 'PTZ camera'],
  ['PPE Store Perim PTZ', 'NORTH', 'Online', '172.17.102.203', 'admin', 'Pelco P2820-ESR', '1920x1080 (2MP)', 'PTZ camera'],
  ['W2 PTZ', 'WEST', 'Online', '172.17.102.244', 'administrator', 'Pelco P2820-ESR', '1920x1080 (2MP)', 'PTZ camera'],
  ['W6 PTZ', 'WEST', 'Online', '172.17.102.248', 'admin', 'Pelco P2820-ESR', '1920x1080 (2MP)', 'PTZ camera'],

  // ===== AVIGILON CAMERAS =====
  ['B1', 'WEST', 'Online', '172.17.103.43', 'administrator', 'Avigilon 5.0C-H5A-DP2', '2560x1920 (5MP)', 'Avigilon fixed camera'],
  ['B1', 'WEST', 'Online', '172.17.103.44', 'administrator', 'Avigilon 5.0C-H5A-DP2', '2560x1920 (5MP)', 'Avigilon fixed camera'],
  ['B2', 'WEST', 'Online', '172.17.103.45', 'administrator', 'Avigilon 5.0C-H5A-DP2', '2560x1920 (5MP)', 'Avigilon fixed camera'],
  ['B3', 'SOUTH', 'Online', '172.17.103.46', 'administrator', 'Avigilon 5.0C-H5A-DP2', '2560x1920 (5MP)', 'Avigilon fixed camera'],
  ['B5', 'SOUTH', 'Online', '172.17.103.47', 'administrator', 'Avigilon 5.0C-H5A-DP2', '2560x1920 (5MP)', 'Avigilon fixed camera'],
  ['B5', 'SOUTH', 'Online', '172.17.103.48', 'administrator', 'Avigilon 5.0C-H5A-DP2', '2560x1920 (5MP)', 'Avigilon fixed camera'],
  ['B5', 'SOUTH', 'Online', '172.17.103.49', 'administrator', 'Avigilon 5.0C-H5A-DP2', '2560x1920 (5MP)', 'Avigilon fixed camera'],
  ['B6', 'WEST', 'Online', '172.17.103.50', 'administrator', 'Avigilon 5.0C-H5A-DP2', '2560x1920 (5MP)', 'Avigilon fixed camera'],
  ['B6', 'WEST', 'Online', '172.17.103.51', 'administrator', 'Avigilon 5.0C-H5A-DP2', '2560x1920 (5MP)', 'Avigilon fixed camera'],
  ['B7', 'WEST', 'Online', '172.17.103.52', 'administrator', 'Avigilon 5.0C-H5A-DP2', '2560x1920 (5MP)', 'Avigilon fixed camera'],
  ['B7', 'WEST', 'Online', '172.17.103.53', 'administrator', 'Avigilon 5.0C-H5A-DP2', '2560x1920 (5MP)', 'Avigilon fixed camera'],
  ['B8', 'WEST', 'Online', '172.17.103.54', 'administrator', 'Avigilon 5.0C-H5A-DP2', '2560x1920 (5MP)', 'Avigilon fixed camera'],
  ['B9', 'WEST', 'Online', '172.17.103.55', 'administrator', 'Avigilon 5.0C-H5A-DP2', '2560x1920 (5MP)', 'Avigilon fixed camera'],
  ['B10', 'WEST', 'Online', '172.17.103.56', 'administrator', 'Avigilon 5.0C-H5A-DP2', '2560x1920 (5MP)', 'Avigilon fixed camera'],
  ['B11', 'WEST', 'Online', '172.17.103.57', 'administrator', 'Avigilon 5.0C-H5A-DP2', '2560x1920 (5MP)', 'Avigilon fixed camera'],
  ['B12', 'WEST', 'Online', '172.17.103.58', 'administrator', 'Avigilon 5.0C-H5A-DP2', '2560x1920 (5MP)', 'Avigilon fixed camera'],
  ['B13', 'WEST', 'Online', '172.17.103.59', 'administrator', 'Avigilon 5.0C-H5A-DP2', '2560x1920 (5MP)', 'Avigilon fixed camera'],
  ['B14', 'EAST', 'Online', '172.17.103.7', 'administrator', 'Avigilon 5.0C-H5A-DP2', '2560x1920 (5MP)', 'Avigilon fixed camera'],
  ['C1', 'SOUTH', 'Online', '172.17.103.71', 'administrator', 'Avigilon 5.0C-H5A-DP2', '2560x1920 (5MP)', 'Avigilon fixed camera'],
  ['C2', 'SOUTH', 'Online', '172.17.103.72', 'administrator', 'Avigilon 5.0C-H5A-DP2', '2560x1920 (5MP)', 'Avigilon fixed camera'],
  ['C4', 'SOUTH', 'Online', '172.17.103.73', 'administrator', 'Avigilon 5.0C-H5A-DP2', '2560x1920 (5MP)', 'Avigilon fixed camera'],
  ['C5', 'SOUTH', 'Online', '172.17.103.74', 'administrator', 'Avigilon 5.0C-H5A-DP2', '2560x1920 (5MP)', 'Avigilon fixed camera'],
  ['C5', 'SOUTH', 'Online', '172.17.103.75', 'administrator', 'Avigilon 5.0C-H5A-DP2', '2560x1920 (5MP)', 'Avigilon fixed camera'],
  ['C9', 'SOUTH', 'Online', '172.17.103.76', 'administrator', 'Avigilon 5.0C-H5A-DP2', '2560x1920 (5MP)', 'Avigilon fixed camera'],
  ['C9', 'SOUTH', 'Online', '172.17.103.77', 'administrator', 'Avigilon 5.0C-H5A-DP2', '2560x1920 (5MP)', 'Avigilon fixed camera'],
  ['C11', 'SOUTH', 'Online', '172.17.103.78', 'administrator', 'Avigilon 5.0C-H5A-DP2', '2560x1920 (5MP)', 'Avigilon fixed camera'],
  ['C12', 'SOUTH', 'Online', '172.17.103.79', 'administrator', 'Avigilon 5.0C-H5A-DP2', '2560x1920 (5MP)', 'Avigilon fixed camera'],
  ['C12', 'SOUTH', 'Online', '172.17.103.80', 'administrator', 'Avigilon 5.0C-H5A-DP2', '2560x1920 (5MP)', 'Avigilon fixed camera'],
  ['D1', 'EAST', 'Online', '172.17.103.87', 'administrator', 'Avigilon 5.0C-H5A-DP2', '2560x1920 (5MP)', 'Avigilon fixed camera'],
  ['D2', 'EAST', 'Online', '172.17.103.88', 'administrator', 'Avigilon 5.0C-H5A-DP2', '2560x1920 (5MP)', 'Avigilon fixed camera'],
  ['D4', 'EAST', 'Online', '172.17.103.89', 'administrator', 'Avigilon 5.0C-H5A-DP2', '2560x1920 (5MP)', 'Avigilon fixed camera'],
  ['D5', 'EAST', 'Online', '172.17.103.90', 'administrator', 'Avigilon 5.0C-H5A-DP2', '2560x1920 (5MP)', 'Avigilon fixed camera'],
  ['D6', 'EAST', 'Online', '172.17.103.106', 'administrator', 'Avigilon 5.0C-H5A-DP2', '2560x1920 (5MP)', 'Avigilon fixed camera'],
  ['D7', 'EAST', 'Online', '172.17.103.92', 'administrator', 'Avigilon 5.0C-H5A-DP2', '2560x1920 (5MP)', 'Avigilon fixed camera'],
  ['D8', 'EAST', 'Online', '172.17.103.93', 'administrator', 'Avigilon 5.0C-H5A-DP2', '2560x1920 (5MP)', 'Avigilon fixed camera'],
  ['E2', 'SOUTH', 'Online', '172.17.103.11', 'administrator', 'Avigilon 5.0C-H5A-DP2', '2560x1920 (5MP)', 'Avigilon fixed camera'],
  ['HM5', 'NORTH', 'Online', '172.17.102.222', 'administrator', 'Avigilon 5.0C-H5A-DP2', '2560x1920 (5MP)', 'Avigilon fixed camera'],
  ['HM8', 'NORTH', 'Online', '172.17.102.220', 'administrator', 'Avigilon 5.0C-H5A-DP2', '2560x1920 (5MP)', 'Avigilon fixed camera'],
  ['HM14', 'NORTH', 'Online', '172.17.102.212', 'administrator', 'Avigilon 5.0C-H5A-DP2', '2560x1920 (5MP)', 'Avigilon fixed camera'],
  ['A14', 'SOUTH', 'Online', '172.17.103.5', 'administrator', 'Avigilon 5.0C-H5A-DP2', '2560x1920 (5MP)', 'Avigilon fixed camera'],
  ['W1', 'WEST', 'Online', '172.17.103.155', 'admin', 'Avigilon 5.0C-H5A-DP2', '2560x1920 (5MP)', 'Avigilon fixed camera'],
  ['W3', 'WEST', 'Online', '172.17.102.230', 'administrator', 'Avigilon 5.0C-H5A-DP2', '2560x1920 (5MP)', 'Avigilon fixed camera'],
  ['W4', 'WEST', 'Online', '172.17.102.232', 'administrator', 'Avigilon 5.0C-H5A-DP2', '2560x1920 (5MP)', 'Avigilon fixed camera'],
  ['W5', 'WEST', 'Online', '172.17.102.228', 'administrator', 'Avigilon 5.0C-H5A-DP2', '2560x1920 (5MP)', 'Avigilon fixed camera'],
  ['W6', 'WEST', 'Online', '172.17.102.233', 'administrator', 'Avigilon 5.0C-H5A-DP2', '2560x1920 (5MP)', 'Avigilon fixed camera'],
  ['W7', 'WEST', 'Online', '172.17.102.234', 'administrator', 'Avigilon 5.0C-H5A-DP2', '2560x1920 (5MP)', 'Avigilon fixed camera'],
  ['W8', 'WEST', 'Online', '172.17.102.235', 'administrator', 'Avigilon 5.0C-H5A-DP2', '2560x1920 (5MP)', 'Avigilon fixed camera'],
  ['W9', 'WEST', 'Online', '172.17.102.236', 'administrator', 'Avigilon 5.0C-H5A-DP2', '2560x1920 (5MP)', 'Avigilon fixed camera'],
  ['W10', 'WEST', 'Online', '172.17.102.231', 'administrator', 'Avigilon 5.0C-H5A-DP2', '2560x1920 (5MP)', 'Avigilon fixed camera'],
  ['W11', 'WEST', 'Online', '172.17.102.239', 'administrator', 'Avigilon 5.0C-H5A-DP2', '2560x1920 (5MP)', 'Avigilon fixed camera'],
  ['W12', 'WEST', 'Online', '172.17.102.240', 'administrator', 'Avigilon 5.0C-H5A-DP2', '2560x1920 (5MP)', 'Avigilon fixed camera'],
  ['W13', 'WEST', 'Online', '172.17.102.241', 'administrator', 'Avigilon 5.0C-H5A-DP2', '2560x1920 (5MP)', 'Avigilon fixed camera'],
  ['W16', 'WEST', 'Online', '172.17.102.242', 'administrator', 'Avigilon 5.0C-H5A-DP2', '2560x1920 (5MP)', 'Avigilon fixed camera'],

  // ===== AXIS CAMERAS =====
  ['A3 PTZ', 'NORTH', 'Online', '172.17.103.32', 'root', 'Axis P5655-E', '1920x1080 (2MP)', 'Axis PTZ camera'],
  ['A13 PTZ', 'SOUTH', 'Offline', '172.17.103.42', 'admin', 'FLIR DX-612', '1920x1080 (2MP)', 'FLIR PTZ camera'],
  ['A9 PTZ', 'SOUTH', 'Offline', '172.17.103.38', 'admin', 'FLIR DX-612', '1920x1080 (2MP)', 'FLIR PTZ camera'],
  ['N31 PTZ', 'NORTH', 'Offline', '172.17.102.207', 'admin', 'FLIR DX-624', '1920x1080 (2MP)', 'FLIR PTZ camera'],
  ['N34 PTZ', 'NORTH', 'Offline', '172.17.102.204', 'admin', 'FLIR DX-624', '1920x1080 (2MP)', 'FLIR PTZ camera'],
  ['E2 PTZ', 'SOUTH', 'Offline', '172.17.103.10', 'root', 'Axis P5655-E', '1920x1080 (2MP)', 'Axis PTZ camera'],
  ['B3 PTZ', 'SOUTH', 'Online', '172.17.103.62', 'root', 'Axis P3267-LVE', '1920x1080 (2MP)', 'Axis PTZ camera'],
  ['B7 PTZ', 'WEST', 'Online', '172.17.103.63', 'root', 'Axis P3267-LVE', '1920x1080 (2MP)', 'Axis PTZ camera'],
  ['B14 PTZ', 'EAST', 'Online', '172.17.103.6', 'root', 'Axis P5655-E', '1920x1080 (2MP)', 'Axis PTZ camera'],
  ['Berth 9 PTZ', 'EAST', 'Online', '172.17.103.146', 'root', 'Axis P5655-E', '1920x1080 (2MP)', 'Axis PTZ camera'],
  ['C12 PTZ', 'SOUTH', 'Online', '172.17.103.117', 'root', 'Axis P3267-LVE', '1920x1080 (2MP)', 'Axis PTZ camera'],
  ['D1 PTZ', 'EAST', 'Online', '172.17.103.97', 'root', 'Axis P5655-E', '1920x1080 (2MP)', 'Axis PTZ camera'],
  ['D2 PTZ', 'EAST', 'Online', '172.17.103.98', 'root', 'Axis P5655-E', '1920x1080 (2MP)', 'Axis PTZ camera'],
  ['D6 PTZ', 'EAST', 'Online', '172.17.103.101', 'root', 'Axis P5655-E', '1920x1080 (2MP)', 'Axis PTZ camera'],
  ['D7 PTZ', 'EAST', 'Online', '172.17.103.102', 'root', 'Axis P5655-E', '1920x1080 (2MP)', 'Axis PTZ camera'],
  ['D8 PTZ', 'EAST', 'Offline', '172.17.103.103', 'root', 'Axis P5655-E', '1920x1080 (2MP)', 'Axis PTZ camera'],
  ['HM14 PTZ', 'NORTH', 'Online', '172.17.103.145', 'root', 'Axis P5655-E', '1920x1080 (2MP)', 'Axis PTZ camera'],
  ['HM24A PTZ', 'NORTH', 'Offline', '172.17.102.215', 'root', 'Axis P5655-E', '1920x1080 (2MP)', 'Axis PTZ camera'],
  ['HR Tower 1 PTZ', 'NORTH', 'Online', '172.17.102.195', 'root', 'Axis P5655-E', '1920x1080 (2MP)', 'Axis PTZ camera'],
  ['HR Tower 2 PTZ', 'NORTH', 'Online', '172.17.102.196', 'root', 'Axis P5655-E', '1920x1080 (2MP)', 'Axis PTZ camera'],
  ['MEZ SE corner PTZ', 'SOUTH', 'Online', '172.17.103.12', 'root', 'Axis P5655-E', '1920x1080 (2MP)', 'Axis PTZ camera'],
  ['N Terminal NW Corner PTZ', 'NORTH', 'Online', '172.17.102.226', 'root', 'Axis P5655-E', '1920x1080 (2MP)', 'Axis PTZ camera'],
  ['Toll Booth Exit PTZ', 'NORTH', 'Online', '172.17.102.176', 'root', 'Axis P5655-E', '1920x1080 (2MP)', 'Axis PTZ camera'],
  ['W Perim PTZ', 'WEST', 'Online', '172.17.103.157', 'root', 'Axis P5655-E', '1920x1080 (2MP)', 'Axis PTZ camera'],
  ['W1 PTZ', 'WEST', 'Offline', '172.17.102.243', 'root', 'Axis P5655-E', '1920x1080 (2MP)', 'Axis PTZ camera'],
  ['W3 PTZ', 'WEST', 'Online', '172.17.102.245', 'root', 'Axis P5655-E', '1920x1080 (2MP)', 'Axis PTZ camera'],
  ['W4 PTZ', 'WEST', 'Online', '172.17.102.246', 'root', 'Axis P5655-E', '1920x1080 (2MP)', 'Axis PTZ camera'],
  ['W5 PTZ', 'WEST', 'Online', '172.17.102.247', 'root', 'Axis P5655-E', '1920x1080 (2MP)', 'Axis PTZ camera'],
  ['W7 PTZ', 'WEST', 'Online', '172.17.102.249', 'root', 'Axis P5655-E', '1920x1080 (2MP)', 'Axis PTZ camera'],
  ['W8 PTZ', 'WEST', 'Online', '172.17.102.250', 'root', 'Axis P5655-E', '1920x1080 (2MP)', 'Axis PTZ camera'],
  ['W9 PTZ', 'WEST', 'Online', '172.17.102.251', 'root', 'Axis P5655-E', '1920x1080 (2MP)', 'Axis PTZ camera'],
  ['W11 PTZ', 'WEST', 'Online', '172.17.102.253', 'root', 'Axis P5655-E', '1920x1080 (2MP)', 'Axis PTZ camera'],
  ['W12 PTZ', 'WEST', 'Online', '172.17.102.254', 'root', 'Axis P5655-E', '1920x1080 (2MP)', 'Axis PTZ camera'],
  ['W13 PTZ', 'WEST', 'Online', '172.17.103.2', 'root', 'Axis P5655-E', '1920x1080 (2MP)', 'Axis PTZ camera'],
  ['W16 PTZ', 'WEST', 'Online', '172.17.103.3', 'root', 'Axis P5655-E', '1920x1080 (2MP)', 'Axis PTZ camera'],
  ['Warehouse Central PTZ', 'NORTH', 'Online', '172.17.102.96', 'root', 'Axis P5655-E', '1920x1080 (2MP)', 'Axis PTZ camera'],
  ['Warehouse Central PTZ 2', 'NORTH', 'Online', '172.17.102.175', 'root', 'Axis P5655-E', '1920x1080 (2MP)', 'Axis PTZ camera'],
  ['WB1 PTZ', 'WEST', 'Offline', '172.17.102.198', 'root', 'Axis P3267-LVE', '1920x1080 (2MP)', 'Axis PTZ camera'],
  ['WB11 Ptz', 'WEST', 'Online', '172.17.103.9', 'root', 'Axis P5655-E', '1920x1080 (2MP)', 'Axis PTZ camera'],
  ['A1', 'SOUTH', 'Online', '172.17.103.16', 'root', 'Axis P3227-LVE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['A2', 'SOUTH', 'Online', '172.17.103.17', 'root', 'Axis P3227-LVE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['A3', 'SOUTH', 'Online', '172.17.103.18', 'root', 'Axis P3227-LVE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['A4', 'SOUTH', 'Online', '172.17.103.19', 'root', 'Axis P3227-LVE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['A5', 'SOUTH', 'Online', '172.17.103.20', 'root', 'Axis P3227-LVE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['A6', 'SOUTH', 'Online', '172.17.103.21', 'root', 'Axis P3227-LVE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['A7', 'SOUTH', 'Online', '172.17.103.22', 'root', 'Axis P3227-LVE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['A8', 'SOUTH', 'Online', '172.17.103.23', 'root', 'Axis P3227-LVE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['A9', 'SOUTH', 'Online', '172.17.103.24', 'root', 'Axis P3227-LVE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['A10', 'SOUTH', 'Online', '172.17.103.25', 'root', 'Axis P3227-LVE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['A11', 'SOUTH', 'Online', '172.17.103.26', 'root', 'Axis P3227-LVE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['A12', 'SOUTH', 'Online', '172.17.103.27', 'root', 'Axis P3227-LVE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['A13', 'SOUTH', 'Online', '172.17.103.28', 'root', 'Axis P3227-LVE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['A13', 'SOUTH', 'Online', '172.17.103.29', 'root', 'Axis P3227-LVE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['A13 Strad Parking', 'SOUTH', 'Online', '172.17.103.231', 'root', 'Axis P1467-LE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['A14 PTZ', 'SOUTH', 'Online', '172.17.103.4', 'root', 'Axis P5655-E', '1920x1080 (2MP)', 'Axis PTZ camera'],
  ['ATM Walkway', 'NORTH', 'Online', '172.17.102.79', 'root', 'Axis P3227-LVE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['Bathroom Passage 1', 'NORTH', 'Online', '172.17.102.156', 'root', 'Axis P3227-LVE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['Bathroom Passage 2', 'NORTH', 'Online', '172.17.102.157', 'root', 'Axis P3227-LVE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['Battery Shop', 'NORTH', 'Online', '172.17.102.154', 'root', 'Axis P1447-LE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['Board N Ceo Secretary', 'NORTH', 'Online', '172.17.102.130', 'root', 'Axis P3245-LV', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['Broker Parking Area', 'NORTH', 'Online', '172.17.102.85', 'root', 'Axis P1447-LE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['Canteen East Entry', 'NORTH', 'Online', '172.17.102.53', 'root', 'Axis P3227-LVE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['Canteen West Entry', 'NORTH', 'Online', '172.17.102.54', 'root', 'Axis P3227-LVE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['Car Park 1', 'NORTH', 'Online', '172.17.102.164', 'root', 'Axis P1447-LE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['Car Park 2', 'NORTH', 'Online', '172.17.102.165', 'root', 'Axis P1447-LE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['Car Park 3', 'NORTH', 'Online', '172.17.102.166', 'root', 'Axis P1447-LE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['Car Park 4', 'NORTH', 'Online', '172.17.102.167', 'root', 'Axis P1447-LE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['Car Park 5', 'NORTH', 'Online', '172.17.102.168', 'root', 'Axis P1447-LE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['Car Park 6', 'NORTH', 'Online', '172.17.102.56', 'root', 'Axis P3227-LVE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['Cashier / Service Counter Canteen', 'NORTH', 'Online', '172.17.102.52', 'root', 'Axis P3227-LVE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['Cashier Window 1 Wharfage', 'NORTH', 'Online', '172.17.102.76', 'root', 'Axis P3227-LVE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['Cashier Window 2 Wharfage', 'NORTH', 'Online', '172.17.102.77', 'root', 'Axis P3227-LVE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['Cashier Window 3 Wharfage', 'NORTH', 'Online', '172.17.102.78', 'root', 'Axis P3227-LVE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['Crane K', 'SOUTH', 'Online', '172.17.103.171', 'root', 'Axis P3227-LVE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['Crane M', 'SOUTH', 'Online', '172.17.103.173', 'root', 'Axis P3227-LVE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['Crane S', 'SOUTH', 'Online', '172.17.103.182', 'root', 'Axis P3227-LVE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['Crane A', 'SOUTH', 'Online', '172.17.103.163', 'root', 'Axis P3227-LVE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['Crane B', 'SOUTH', 'Online', '172.17.103.164', 'root', 'Axis P3227-LVE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['Crane L', 'SOUTH', 'Online', '172.17.103.172', 'root', 'Axis P3227-LVE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['Crane N', 'SOUTH', 'Online', '172.17.103.166', 'root', 'Axis P3227-LVE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['Crane O', 'SOUTH', 'Online', '172.17.103.177', 'root', 'Axis P3227-LVE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['Crane P', 'SOUTH', 'Online', '172.17.103.178', 'root', 'Axis P3227-LVE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['Crane Q', 'SOUTH', 'Online', '172.17.103.175', 'root', 'Axis P3227-LVE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['Crane R', 'SOUTH', 'Online', '172.17.103.181', 'root', 'Axis P3227-LVE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['Crane T', 'SOUTH', 'Online', '172.17.103.168', 'root', 'Axis P3227-LVE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['Crane U', 'SOUTH', 'Online', '172.17.103.169', 'root', 'Axis P3227-LVE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['Crane V', 'SOUTH', 'Online', '172.17.103.162', 'root', 'Axis P3227-LVE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['Crane Y', 'SOUTH', 'Online', '172.17.103.174', 'root', 'Axis P3227-LVE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['Crane Z', 'SOUTH', 'Online', '172.17.103.170', 'root', 'Axis P3227-LVE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['Customer / Broker Lobby SE Corner', 'NORTH', 'Online', '172.17.102.74', 'root', 'Axis P3227-LVE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['Customer /Broker Entry', 'NORTH', 'Online', '172.17.102.72', 'root', 'Axis P1468-LE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['D12', 'EAST', 'Online', '172.17.103.96', 'root', 'Axis P3227-LVE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['Data Center A', 'NORTH', 'Online', '172.17.103.153', 'root', 'Axis P3227-LVE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['Data Center B Unit', 'NORTH', 'Online', '172.17.103.108', 'administrator', 'Avigilon 5.0C-H5A-DP2', '2560x1920 (5MP)', 'Avigilon fixed camera'],
  ['Dining Area 1 Canteen', 'NORTH', 'Online', '172.17.102.50', 'root', 'Axis P3227-LVE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['Dining Area 2 Canteen', 'NORTH', 'Online', '172.17.102.51', 'root', 'Axis P3227-LVE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['East West Corner Perimeter Rest Bay', 'NORTH', 'Online', '172.17.102.108', 'root', 'Axis P1447-LE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['Eng Workshop 3', 'NORTH', 'Online', '172.17.102.152', 'root', 'Axis P3245-LV', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['Engineering East Stair', 'NORTH', 'Online', '172.17.102.146', 'root', 'Axis P3245-LV', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['Engineering Entry', 'NORTH', 'Online', '172.17.102.151', 'root', 'Axis P3245-LV', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['Engineering Entry Passage', 'NORTH', 'Online', '172.17.102.95', 'root', 'Axis P3227-LVE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['Engineering GYM', 'NORTH', 'Online', '172.17.102.150', 'root', 'Axis P3245-LV', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['Engineering Lunch RM Kitchen', 'NORTH', 'Online', '172.17.103.193', 'root', 'Axis M3085-V', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['Engineering Lunch Room', 'NORTH', 'Online', '172.17.102.97', 'root', 'Axis P3227-LVE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['Engineering Rear Passage', 'NORTH', 'Online', '172.17.102.148', 'root', 'Axis P3227-LVE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['Engineering Stationary Passage', 'NORTH', 'Online', '172.17.102.163', 'root', 'Axis P3227-LVE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['Engineering West Stair', 'NORTH', 'Online', '172.17.102.147', 'root', 'Axis P3245-LV', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['Executive 2nd Fl Exit Stair Lower', 'NORTH', 'Online', '172.17.102.132', 'root', 'Axis P3245-LV', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['Executive 2nd Fl Exit Stair Top', 'NORTH', 'Online', '172.17.102.134', 'root', 'Axis P3245-LV', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['Executive Passage N Entry', 'NORTH', 'Online', '172.17.102.136', 'root', 'Axis P3245-LV', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['Exit Gate', 'NORTH', 'Online', '172.17.102.90', 'root', 'Axis P3227-LVE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['F Changing Room Exit Passage', 'NORTH', 'Online', '172.17.102.149', 'root', 'Axis P3245-LV', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['Gate Office E Side Outside', 'NORTH', 'Online', '172.17.102.62', 'root', 'Axis P3227-LVE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['Gate Office Easteern Side Inside', 'NORTH', 'Online', '172.17.102.60', 'root', 'Axis P3227-LVE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['HM5', 'NORTH', 'Online', '172.17.102.192', 'root', 'Axis P3227-LVE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['HM23', 'NORTH', 'Online', '172.17.102.201', 'root', 'Axis P3227-LVE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['HM24A', 'NORTH', 'Offline', '172.17.102.214', 'root', 'Axis P1447-LE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['HR Building Rear Walkway', 'NORTH', 'Online', '172.17.102.82', 'root', 'Axis P1447-LE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['HR Meeting Rm Passage 2', 'NORTH', 'Online', '172.17.102.131', 'root', 'Axis P3245-LV', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['HR Waiting Area', 'NORTH', 'Online', '172.17.102.133', 'root', 'Axis P3245-LV', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['IT Entry', 'NORTH', 'Online', '172.17.103.152', 'root', 'Axis P3227-LVE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['IT Exit', 'NORTH', 'Online', '172.17.103.151', 'root', 'Axis P3227-LVE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['IT Stairwell', 'NORTH', 'Online', '172.17.102.145', 'root', 'Axis P3245-LV', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['KFTL Port Main Entry Exit', 'NORTH', 'Online', '172.17.102.61', 'root', 'Axis P3227-LVE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['Lobby HR', 'NORTH', 'Online', '172.17.102.80', 'root', 'Axis P3227-LVE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['Main Entry/Exit Security Walkway', 'NORTH', 'Online', '172.17.102.98', 'root', 'Axis P1447-LE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['Main Entry/Exit Turn Style', 'NORTH', 'Offline', '172.17.102.99', 'root', 'Axis P1447-LE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['Manager Car Park Dome', 'NORTH', 'Online', '172.17.102.187', 'root', 'Axis P3227-LVE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['Meeting RM Passage', 'NORTH', 'Online', '172.17.102.128', 'root', 'Axis P3245-LV', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['MEZ SW Corner', 'SOUTH', 'Online', '172.17.103.14', 'root', 'Axis P3227-LVE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['Monitoring Room 1', 'SOUTH', 'Online', '172.17.103.180', 'root', 'Axis P3227-LVE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['Monitoring Room 2', 'SOUTH', 'Online', '172.17.103.179', 'root', 'Axis P3227-LVE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['N Bay 2', 'NORTH', 'Online', '172.17.102.111', 'root', 'Axis P1447-LE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['N Bay 5', 'NORTH', 'Online', '172.17.102.114', 'root', 'Axis P1447-LE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['N Bay 7', 'NORTH', 'Online', '172.17.102.116', 'root', 'Axis P1447-LE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['N Bay 8', 'NORTH', 'Online', '172.17.102.117', 'root', 'Axis P1447-LE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['N Bay 9', 'NORTH', 'Online', '172.17.102.113', 'root', 'Axis P1447-LE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['N Bay 10', 'NORTH', 'Online', '172.17.102.115', 'root', 'Axis P1447-LE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['N Bay 11', 'NORTH', 'Online', '172.17.102.110', 'root', 'Axis P1447-LE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['N Bay 12', 'NORTH', 'Online', '172.17.102.112', 'root', 'Axis P1447-LE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['N Fence', 'NORTH', 'Online', '172.17.103.109', 'root', 'Axis P3227-LVE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['N Fence 1 (W) Thermal', 'NORTH', 'Online', '172.17.102.193', 'root', 'Axis Q1941-E', '3840x2160 (4K)', 'Axis thermal camera'],
  ['N Fence 2 (E) Thermal', 'NORTH', 'Online', '172.17.102.169', 'root', 'Axis Q1942-E', '3840x2160 (4K)', 'Axis thermal camera'],
  ['N Fence 3 (W) Thermal', 'NORTH', 'Online', '172.17.102.181', 'root', 'Axis Q1941-E', '3840x2160 (4K)', 'Axis thermal camera'],
  ['N Fence Stripping Warehouse Thermal', 'NORTH', 'Online', '172.17.102.170', 'root', 'Axis Q1942-E', '3840x2160 (4K)', 'Axis thermal camera'],
  ['N Platform 1 Stripping', 'NORTH', 'Online', '172.17.102.102', 'root', 'Axis P1447-LE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['N Platform 2 Stripping', 'NORTH', 'Online', '172.17.102.103', 'root', 'Axis P1447-LE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['N Terminal NW Corner', 'NORTH', 'Online', '172.17.102.227', 'root', 'Axis P1447-LE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['N30', 'NORTH', 'Offline', '172.17.102.209', 'root', 'Axis P3227-LVE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['N30 Thermal', 'NORTH', 'Offline', '172.17.102.178', 'root', 'Axis Q1941-E', '3840x2160 (4K)', 'Axis thermal camera'],
  ['N31', 'NORTH', 'Online', '172.17.102.208', 'root', 'Axis P3227-LVE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['N33', 'NORTH', 'Online', '172.17.102.206', 'root', 'Axis P3227-LVE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['N34', 'NORTH', 'Online', '172.17.102.205', 'root', 'Axis P3227-LVE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['NE Corner Stripping', 'NORTH', 'Online', '172.17.102.140', 'root', 'Axis P1447-LE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['North South Corner Rest Bay', 'NORTH', 'Online', '172.17.102.107', 'root', 'Axis P1447-LE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['NW Corner Stripping', 'NORTH', 'Online', '172.17.102.139', 'root', 'Axis P1447-LE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['Payroll Walkway', 'NORTH', 'Online', '172.17.102.93', 'root', 'Axis P3227-LVE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['Planning Main Entry', 'NORTH', 'Online', '172.17.102.129', 'root', 'Axis P3245-LV', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['PPE N Stationary Entry / Exit Gate', 'NORTH', 'Online', '172.17.102.160', 'root', 'Axis P1447-LE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['PPE Perim N Thermal', 'NORTH', 'Online', '172.17.102.173', 'root', 'Axis Q1941-E', '3840x2160 (4K)', 'Axis thermal camera'],
  ['PPE Perim S Thermal', 'NORTH', 'Online', '172.17.102.171', 'root', 'Axis Q1942-E', '3840x2160 (4K)', 'Axis thermal camera'],
  ['PPE Store Entrance', 'NORTH', 'Online', '172.17.102.91', 'root', 'Axis P3227-LVE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['PPE Store Invetory', 'NORTH', 'Online', '172.17.103.142', 'root', 'Axis P1447-LE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['PPE Store Perim N', 'NORTH', 'Online', '172.17.102.162', 'root', 'Axis P1447-LE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['PPE Store Perim S', 'NORTH', 'Online', '172.17.102.159', 'root', 'Axis P1447-LE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['Procurement Passage', 'NORTH', 'Online', '172.17.102.92', 'root', 'Axis P3227-LVE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['Production Turn Style', 'NORTH', 'Online', '172.17.102.83', 'root', 'Axis P1447-LE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['Radio Room', 'NORTH', 'Online', '172.17.102.87', 'root', 'Axis P3227-LVE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['Reay Entry / Exit', 'NORTH', 'Online', '172.17.102.143', 'root', 'Axis P1447-LE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['Recreation Area Rest Bay', 'NORTH', 'Online', '172.17.102.109', 'root', 'Axis P3267-LVE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['Registry Entry Passage', 'NORTH', 'Offline', '172.17.102.94', 'root', 'Axis P3227-LVE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['Registry Office Passage Rear', 'NORTH', 'Online', '172.17.102.89', 'root', 'Axis P3227-LVE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['Registry Passage to Warehouse', 'NORTH', 'Online', '172.17.102.144', 'root', 'Axis P3245-LV', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['Rest Bay Turn Style', 'NORTH', 'Online', '172.17.102.81', 'root', 'Axis P1447-LE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['S Bay AB', 'SOUTH', 'Online', '172.17.102.118', 'root', 'Axis P1447-LE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['S Bay CD', 'SOUTH', 'Online', '172.17.102.119', 'root', 'Axis P1447-LE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['S Bay EF', 'SOUTH', 'Online', '172.17.102.120', 'root', 'Axis P1447-LE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['S Bay G', 'SOUTH', 'Online', '172.17.102.121', 'root', 'Axis P1447-LE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['S Bay HI', 'SOUTH', 'Online', '172.17.102.122', 'root', 'Axis P1447-LE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['S Bay J', 'SOUTH', 'Online', '172.17.102.123', 'root', 'Axis P1447-LE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['S Bay KL', 'SOUTH', 'Online', '172.17.102.124', 'root', 'Axis P1447-LE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['S Bay M', 'SOUTH', 'Online', '172.17.102.125', 'root', 'Axis P1447-LE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['S Bay NO', 'SOUTH', 'Online', '172.17.102.126', 'root', 'Axis P1447-LE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['S Bay PQ', 'SOUTH', 'Online', '172.17.102.127', 'root', 'Axis P1447-LE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['S Bay RS', 'SOUTH', 'Online', '172.17.102.137', 'root', 'Axis P1447-LE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['S Bay T', 'SOUTH', 'Online', '172.17.102.138', 'root', 'Axis P1447-LE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['S Bay U', 'SOUTH', 'Online', '172.17.102.106', 'root', 'Axis P1447-LE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['S Perim Berth 9 Area Thermal', 'SOUTH', 'Online', '172.17.102.190', 'root', 'Axis Q1942-E', '3840x2160 (4K)', 'Axis thermal camera'],
  ['Scanning Area 1', 'SOUTH', 'Online', '172.17.103.226', 'root', 'Axis M4216-V', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['Scanning Area 2', 'SOUTH', 'Online', '172.17.103.227', 'root', 'Axis M4216-V', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['SE Corner Stripping', 'NORTH', 'Online', '172.17.102.142', 'root', 'Axis P1447-LE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['SE corner Thermal', 'SOUTH', 'Online', '172.17.103.13', 'root', 'Axis Q1942-E', '3840x2160 (4K)', 'Axis thermal camera'],
  ['SE Tower PTZ', 'SOUTH', 'Online', '172.17.103.165', 'admin', 'Opgal OP94-1200-0000', '1920x1080 (2MP)', 'Opgal PTZ camera'],
  ['Security Dept West side 1', 'NORTH', 'Online', '172.17.102.63', 'root', 'Axis P3227-LVE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['Security Dept West side 2', 'NORTH', 'Online', '172.17.102.64', 'root', 'Axis P3227-LVE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['Security Station N Pedestrian Gate', 'NORTH', 'Online', '172.17.102.58', 'root', 'Axis P3227-LVE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['South East Tower Thermal', 'SOUTH', 'Online', '172.17.103.110', 'root', 'Axis Q1942-E', '3840x2160 (4K)', 'Axis thermal camera'],
  ['South Perim 2 Thermal', 'SOUTH', 'Online', '172.17.103.116', 'root', 'Axis Q1941-E', '3840x2160 (4K)', 'Axis thermal camera'],
  ['South Perim Thermal', 'SOUTH', 'Online', '172.17.103.115', 'root', 'Axis Q1941-E', '3840x2160 (4K)', 'Axis thermal camera'],
  ['Store Entrance', 'NORTH', 'Online', '172.17.102.86', 'root', 'Axis P3227-LVE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['Store Rear Entry N Passage', 'NORTH', 'Online', '172.17.102.158', 'root', 'Axis P3227-LVE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['Store Warehouse', 'NORTH', 'Online', '172.17.102.88', 'root', 'Axis P3227-LVE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['Store Warehouse 3', 'NORTH', 'Online', '172.17.102.161', 'root', 'Axis P1447-LE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['SW Corner Perimer 1 Stripping', 'NORTH', 'Online', '172.17.102.104', 'root', 'Axis P1447-LE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['SW Corner Perimer 2 Stripping', 'NORTH', 'Online', '172.17.102.105', 'root', 'Axis P1447-LE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['SW Corner Stripping', 'NORTH', 'Online', '172.17.102.141', 'root', 'Axis P1447-LE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['Refuelling N KWC Perim Thermal', 'NORTH', 'Online', '172.17.102.177', 'root', 'Axis Q1941-E', '3840x2160 (4K)', 'Axis thermal camera'],
  ['Toll Gate Entry', 'NORTH', 'Online', '172.17.102.172', 'root', 'Axis P1447-LE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['Toll Gate Exit', 'NORTH', 'Online', '172.17.102.174', 'root', 'Axis P1447-LE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['Tollgate Entry LPR', 'NORTH', 'Online', '172.17.102.188', 'admin', 'AutoVu SharpOS', '1920x1080 (2MP)', 'LPR camera'],
  ['Tollgate Exit LPR', 'NORTH', 'Online', '172.17.102.189', 'admin', 'AutoVu SharpOS', '1920x1080 (2MP)', 'LPR camera'],
  ['Training Room East', 'NORTH', 'Online', '172.17.102.84', 'root', 'Axis P3227-LVE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['Training Room West', 'NORTH', 'Online', '172.17.102.75', 'root', 'Axis P3227-LVE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['Truck Entry 1', 'NORTH', 'Online', '172.17.103.150', 'root', 'Axis P3227-LVE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['Truck Entry 1 LPR', 'NORTH', 'Online', '172.17.103.186', 'admin', 'AutoVu SharpOS', '1920x1080 (2MP)', 'LPR camera'],
  ['Truck Entry 2', 'NORTH', 'Online', '172.17.103.149', 'root', 'Axis P3227-LVE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['Truck Entry 2 LPR', 'NORTH', 'Online', '172.17.103.167', 'admin', 'AutoVu SharpOS', '1920x1080 (2MP)', 'LPR camera'],
  ['Truck entry LPR 3', 'NORTH', 'Online', '172.17.103.190', 'admin', 'Genetec SharpV (Gen 3)', '1920x1080 (2MP)', 'LPR camera'],
  ['Truck entry LPR 4', 'NORTH', 'Online', '172.17.103.191', 'admin', 'Genetec SharpV (Gen 3)', '1920x1080 (2MP)', 'LPR camera'],
  ['Truck Exit', 'NORTH', 'Online', '172.17.103.148', 'root', 'Axis P3227-LVE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['Truck Exit LPR', 'NORTH', 'Online', '172.17.102.194', 'admin', 'AutoVu SharpOS', '1920x1080 (2MP)', 'LPR camera'],
  ['Truck Guard House Exit', 'NORTH', 'Online', '172.17.102.179', 'root', 'Axis P3227-LVE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['Tyre Shop', 'NORTH', 'Online', '172.17.102.153', 'root', 'Axis P1447-LE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['Vet office 1', 'SOUTH', 'Online', '172.17.103.228', 'root', 'Axis P3267-LV', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['Vet office 2 Window', 'SOUTH', 'Online', '172.17.103.229', 'root', 'Axis P3267-LVE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['Vet Office entry Walkway', 'NORTH', 'Online', '172.17.102.73', 'root', 'Axis P3227-LVE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['Vet Waiting Area', 'SOUTH', 'Online', '172.17.103.230', 'root', 'Axis P3267-LV', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['W Perim Berth 9 Area Thermal', 'WEST', 'Online', '172.17.102.191', 'root', 'Axis Q1941-E', '3840x2160 (4K)', 'Axis thermal camera'],
  ['W Perim 1 Thermal Adjacent to W4', 'WEST', 'Offline', '172.17.102.197', 'root', 'Axis Q1942-E', '3840x2160 (4K)', 'Axis thermal camera'],
  ['W Perim 2 Thermal Adjacent to W7', 'WEST', 'Online', '172.17.102.199', 'root', 'Axis Q1942-E', '3840x2160 (4K)', 'Axis thermal camera'],
  ['W Perim 3 Thermal Adjacent to W7', 'WEST', 'Online', '172.17.103.158', 'root', 'Axis Q1942-E', '3840x2160 (4K)', 'Axis thermal camera'],
  ['W Perim 4 Thermal Adjacent to W9', 'WEST', 'Offline', '172.17.103.159', 'root', 'Axis Q1942-E', '3840x2160 (4K)', 'Axis thermal camera'],
  ['W Perim 5 Thermal Adjacent to W4', 'WEST', 'Offline', '172.17.103.160', 'root', 'Axis Q1942-E', '3840x2160 (4K)', 'Axis thermal camera'],
  ['W Perim 6 Adjacent W9', 'WEST', 'Offline', '172.17.103.147', 'root', 'Axis P1447-LE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['W2', 'WEST', 'Offline', '172.17.102.237', 'root', 'Axis P3227-LVE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['Welfare Passage', 'NORTH', 'Online', '172.17.102.55', 'root', 'Axis P3227-LVE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['Wharfage Office Cashier 1', 'NORTH', 'Online', '172.17.102.68', 'root', 'Axis P3227-LVE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['Wharfage Office Cashier 2', 'NORTH', 'Online', '172.17.102.69', 'root', 'Axis P3227-LVE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['Wharfage Office Cashier 3', 'NORTH', 'Online', '172.17.102.70', 'root', 'Axis P3227-LVE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['Wharfage Office Cashier Emergency Door', 'NORTH', 'Online', '172.17.102.71', 'root', 'Axis P3227-LVE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['Wharfage Office NW Corner', 'NORTH', 'Online', '172.17.102.66', 'root', 'Axis P3227-LVE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['Wharfage Office Storage Area/Safe', 'NORTH', 'Online', '172.17.102.67', 'root', 'Axis P3227-LVE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['Wharfage Perim', 'NORTH', 'Offline', '172.17.102.180', 'root', 'Axis P1447-LE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['Wharfage Staff Entrance Office', 'NORTH', 'Online', '172.17.102.65', 'root', 'Axis P3227-LVE', '1920x1080 (2MP)', 'Axis fixed camera'],
  ['172.17.103.195 - Unit', 'SOUTH', 'Online', '172.17.103.195', 'root', 'Axis P1467-LE', '1920x1080 (2MP)', 'Axis fixed camera'],
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
    const { comments, status, model, resolution } = req.body;

    const fields = [];
    const values = [];
    let counter = 1;

    if (comments !== undefined) { fields.push(`comments = $${counter}`); values.push(comments); counter++; }
    if (status !== undefined) { fields.push(`status = $${counter}`); values.push(status); counter++; }
    if (model !== undefined) { fields.push(`model = $${counter}`); values.push(model); counter++; }
    if (resolution !== undefined) { fields.push(`resolution = $${counter}`); values.push(resolution); counter++; }
    
    fields.push(`updated_at = CURRENT_TIMESTAMP`);
    values.push(name);

    if (fields.length > 0) {
      await pool.query(
        `UPDATE cameras SET ${fields.join(', ')} WHERE name = $${counter}`,
        values
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
// Serve static files from the current directory
app.use(express.static(__dirname));

// For any non-API route, serve the frontend
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
