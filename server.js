const express = require('express');
const path = require('path');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');

const app = express();
const PORT = process.env.PORT || 3000;
const SALT_ROUNDS = 10;

app.use(express.json({ limit: '50mb' }));
// All API routes registered before static middleware

let pool = null;
let dbReady = false;
let dbError = null;

const DB_URL = process.env.DATABASE_PUBLIC_URL || process.env.DATABASE_URL;
if (DB_URL) {
  pool = new Pool({ connectionString: DB_URL, ssl: { rejectUnauthorized: false } });
}

async function initDB() {
  if (!pool) { dbError = 'No DATABASE_URL set'; console.log('No DATABASE_URL — running without cloud DB'); return; }
  try {
    console.log('Connecting to DB...');
    await pool.query('SELECT 1');
    console.log('DB connection OK, creating tables...');
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        username VARCHAR(100) PRIMARY KEY,
        password VARCHAR(200) NOT NULL,
        role VARCHAR(20) NOT NULL DEFAULT 'user'
      );
      CREATE TABLE IF NOT EXISTS app_config (
        key VARCHAR(100) PRIMARY KEY,
        value JSONB NOT NULL,
        updated_at TIMESTAMP DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS sessions (
        id BIGINT PRIMARY KEY,
        label VARCHAR(200),
        month_cfg JSONB,
        scan_data JSONB,
        employees JSONB,
        employee_count INT DEFAULT 0,
        saved_at VARCHAR(100),
        created_at TIMESTAMP DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS active_work (
        username VARCHAR(100) PRIMARY KEY,
        scan_data JSONB,
        month_cfg JSONB,
        updated_at TIMESTAMP DEFAULT NOW()
      );
    `);
    // Seed default admin if no users exist
    const { rows } = await pool.query('SELECT COUNT(*) FROM users');
    if (parseInt(rows[0].count) === 0) {
      const hash = await bcrypt.hash('admin123', SALT_ROUNDS);
      await pool.query('INSERT INTO users (username, password, role) VALUES ($1, $2, $3)', ['admin', hash, 'admin']);
      console.log('Default admin created (admin / admin123)');
    }
    dbReady = true;
    console.log('PostgreSQL ready');
  } catch (e) {
    dbError = e.message;
    console.error('DB init error:', e.message);
  }
}

const requireDB = (req, res, next) => {
  if (!dbReady) return res.status(503).json({ error: 'Database not available' });
  next();
};

// ─── HEALTH ────────────────────────────────────────────────────────────────────
app.get('/api/health', (req, res) => {
  res.json({ dbReady, dbError, hasUrl: !!DB_URL });
});

// ─── AUTH ──────────────────────────────────────────────────────────────────────
app.post('/api/auth/login', requireDB, async (req, res) => {
  try {
    const { username, password } = req.body;
    const { rows } = await pool.query('SELECT username, role, password FROM users WHERE username=$1', [username?.trim()]);
    if (!rows.length) return res.status(401).json({ error: 'ຊື່ຜູ້ໃຊ້ ຫຼື ລະຫັດຜ່ານບໍ່ຖືກຕ້ອງ' });
    const user = rows[0];
    let valid = false;
    if (user.password.startsWith('$2b$') || user.password.startsWith('$2a$')) {
      valid = await bcrypt.compare(password, user.password);
    } else {
      // Plain text legacy — compare then migrate to hash
      valid = user.password === password;
      if (valid) {
        const hash = await bcrypt.hash(password, SALT_ROUNDS);
        await pool.query('UPDATE users SET password=$1 WHERE username=$2', [hash, user.username]);
        console.log(`Migrated ${user.username} password to bcrypt`);
      }
    }
    if (!valid) return res.status(401).json({ error: 'ຊື່ຜູ້ໃຊ້ ຫຼື ລະຫັດຜ່ານບໍ່ຖືກຕ້ອງ' });
    res.json({ username: user.username, role: user.role });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ─── USERS ─────────────────────────────────────────────────────────────────────
app.get('/api/users', requireDB, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT username, role FROM users ORDER BY role DESC, username');
    res.json(rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/users', requireDB, async (req, res) => {
  try {
    const { username, password, role } = req.body;
    const hash = await bcrypt.hash(password?.trim(), SALT_ROUNDS);
    await pool.query('INSERT INTO users (username, password, role) VALUES ($1, $2, $3)', [username?.trim(), hash, role || 'user']);
    res.json({ ok: true });
  } catch (e) {
    if (e.code === '23505') return res.status(400).json({ error: 'ຊື່ຜູ້ໃຊ້ນີ້ມີຢູ່ແລ້ວ' });
    res.status(500).json({ error: e.message });
  }
});

app.delete('/api/users/:username', requireDB, async (req, res) => {
  try {
    await pool.query('DELETE FROM users WHERE username=$1', [req.params.username]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/users/:username/password', requireDB, async (req, res) => {
  try {
    const hash = await bcrypt.hash(req.body.password?.trim(), SALT_ROUNDS);
    await pool.query('UPDATE users SET password=$1 WHERE username=$2', [hash, req.params.username]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ─── CONFIG (employees, monthCfg) ──────────────────────────────────────────────
app.get('/api/config/:key', requireDB, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT value FROM app_config WHERE key=$1', [req.params.key]);
    res.json(rows.length ? rows[0].value : null);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/config/:key', requireDB, async (req, res) => {
  try {
    await pool.query(
      `INSERT INTO app_config (key, value, updated_at) VALUES ($1, $2::jsonb, NOW())
       ON CONFLICT (key) DO UPDATE SET value=$2::jsonb, updated_at=NOW()`,
      [req.params.key, JSON.stringify(req.body.value)]
    );
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ─── ACTIVE WORK (current CSV session per user) ────────────────────────────────
app.get('/api/active-work', requireDB, async (req, res) => {
  try {
    const username = req.query.u;
    if (!username) return res.status(400).json({ error: 'Missing username' });
    const { rows } = await pool.query('SELECT scan_data, month_cfg FROM active_work WHERE username=$1', [username]);
    res.json(rows.length ? { scanData: rows[0].scan_data, monthCfg: rows[0].month_cfg } : null);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/active-work', requireDB, async (req, res) => {
  try {
    const { username, scanData, monthCfg } = req.body;
    if (!username) return res.status(400).json({ error: 'Missing username' });
    await pool.query(
      `INSERT INTO active_work (username, scan_data, month_cfg, updated_at) VALUES ($1, $2::jsonb, $3::jsonb, NOW())
       ON CONFLICT (username) DO UPDATE SET scan_data=$2::jsonb, month_cfg=$3::jsonb, updated_at=NOW()`,
      [username, JSON.stringify(scanData), JSON.stringify(monthCfg)]
    );
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/active-work', requireDB, async (req, res) => {
  try {
    const username = req.body.username || req.query.u;
    if (!username) return res.status(400).json({ error: 'Missing username' });
    await pool.query('DELETE FROM active_work WHERE username=$1', [username]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ─── SESSIONS ──────────────────────────────────────────────────────────────────
app.get('/api/sessions', requireDB, async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT id, label, month_cfg, scan_data, employees, employee_count, saved_at FROM sessions ORDER BY created_at DESC'
    );
    res.json(rows.map(r => ({
      id: r.id, label: r.label,
      monthCfg: r.month_cfg, scanData: r.scan_data, employees: r.employees,
      employeeCount: r.employee_count, savedAt: r.saved_at,
    })));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/sessions', requireDB, async (req, res) => {
  try {
    const { id, label, monthCfg, scanData, employees, employeeCount, savedAt } = req.body;
    await pool.query(
      `INSERT INTO sessions (id, label, month_cfg, scan_data, employees, employee_count, saved_at)
       VALUES ($1, $2, $3::jsonb, $4::jsonb, $5::jsonb, $6, $7)
       ON CONFLICT (id) DO UPDATE SET label=$2, month_cfg=$3::jsonb, scan_data=$4::jsonb, employees=$5::jsonb, employee_count=$6, saved_at=$7`,
      [id, label, JSON.stringify(monthCfg), JSON.stringify(scanData), JSON.stringify(employees), employeeCount, savedAt]
    );
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/sessions/:id', requireDB, async (req, res) => {
  try {
    await pool.query('DELETE FROM sessions WHERE id=$1', [req.params.id]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Static files AFTER all API routes
app.use(express.static(__dirname));
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'sengchanh-salary-calculator.html'));
});

initDB().then(() => {
  app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
});
