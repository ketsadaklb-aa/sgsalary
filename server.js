const express = require('express');
const path = require('path');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json({ limit: '50mb' }));
app.use(express.static(__dirname));

let pool = null;
let dbReady = false;
let dbError = null;

if (process.env.DATABASE_URL) {
  pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false },
  });
}

async function initDB() {
  if (!pool) {
    dbError = 'No DATABASE_URL set';
    console.log('No DATABASE_URL — running without cloud DB');
    return;
  }
  try {
    console.log('Connecting to DB...');
    await pool.query('SELECT 1'); // test connection
    console.log('DB connection OK, creating tables...');
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        username VARCHAR(100) PRIMARY KEY,
        password VARCHAR(100) NOT NULL,
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
    `);
    const { rows } = await pool.query('SELECT COUNT(*) FROM users');
    if (parseInt(rows[0].count) === 0) {
      await pool.query(
        'INSERT INTO users (username, password, role) VALUES ($1, $2, $3)',
        ['admin', 'admin123', 'admin']
      );
      console.log('Default admin user created (admin / admin123)');
    }
    dbReady = true;
    console.log('PostgreSQL ready');
  } catch (e) {
    dbError = e.message;
    console.error('DB init error:', e.message);
  }
}

app.get('/api/health', (req, res) => {
  res.json({ dbReady, dbError, hasUrl: !!process.env.DATABASE_URL });
});

const requireDB = (req, res, next) => {
  if (!dbReady) return res.status(503).json({ error: 'Database not available' });
  next();
};

// ─── AUTH ──────────────────────────────────────────────────────────────────────
app.post('/api/auth/login', requireDB, async (req, res) => {
  try {
    const { username, password } = req.body;
    const { rows } = await pool.query(
      'SELECT username, role FROM users WHERE username=$1 AND password=$2',
      [username?.trim(), password]
    );
    if (!rows.length) return res.status(401).json({ error: 'ຊື່ຜູ້ໃຊ້ ຫຼື ລະຫັດຜ່ານບໍ່ຖືກຕ້ອງ' });
    res.json(rows[0]);
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
    await pool.query(
      'INSERT INTO users (username, password, role) VALUES ($1, $2, $3)',
      [username?.trim(), password?.trim(), role || 'user']
    );
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
    await pool.query('UPDATE users SET password=$1 WHERE username=$2', [req.body.password?.trim(), req.params.username]);
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

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'sengchanh-salary-calculator.html'));
});

initDB().then(() => {
  app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
});
