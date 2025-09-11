// src/server.js
require('dotenv').config();
const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const multer = require('multer');
const cors = require('cors');
const { v4: uuidv4 } = require('uuid');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');

const app = express();

// --------- CONFIG ---------
const PORT = process.env.PORT || 3000;
const NODE_ENV = process.env.NODE_ENV || 'development';
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret';
const SESSION_SECRET = process.env.SESSION_SECRET || 'dev_session_secret';
const UPLOAD_PATH = process.env.UPLOAD_PATH || './uploads';
const BCRYPT_ROUNDS = parseInt(process.env.BCRYPT_ROUNDS || '12', 10);

// ensure upload dir exists
const uploadsDir = path.resolve(UPLOAD_PATH);
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

// --------- MIDDLEWARE ---------
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

const allowedOrigins = [
  'http://localhost:3000',
  'http://127.0.0.1:3000'
];
if (process.env.FRONTEND_URL) allowedOrigins.push(process.env.FRONTEND_URL);

app.use(cors({
  origin: allowedOrigins,
  credentials: true
}));

// --------- DATABASE SETUP (Postgres in PROD) ---------
const DATABASE_URL = process.env.DATABASE_URL || '';
let isPostgres = false;
let pool = null;
let dbRun, dbGet, dbAll;

// Convert ? placeholders to $1, $2 for Postgres
function convertPlaceholders(query, params = []) {
  if (!isPostgres) return { text: query, values: params };
  let idx = 0;
  const text = query.replace(/\?/g, () => {
    idx++;
    return `$${idx}`;
  });
  return { text, values: params };
}

const connStr = process.env.DATABASE_PUBLIC_URL || process.env.DATABASE_URL || '';


if (connStr && connStr.startsWith('postgresql://')) {
  isPostgres = true;
  const { Pool } = require('pg');
  pool = new Pool({
    connectionString: connStr,
    ssl: sslOption
  });

  pool.connect()
  .then(client => {
    client.release();
    console.log('✅ Postgres connection established (using connectionString from env).');
  })
  .catch(err => {
    console.error('❌ Postgres connection test failed:', err);
    // Exit so Railway shows a failing deployment and you can see the error in logs
    process.exit(1);
  });

 pool.connect()
    .then(client => {
      client.release();
      console.log('✅ Postgres connection established (using connectionString from env).');
    })
    .catch(err => {
      console.error('❌ Postgres connection test failed:', err.message || err);
    });

  dbRun = async (query, params = []) => {
    const { text, values } = convertPlaceholders(query, params);
    const client = await pool.connect();
    try {
      return await client.query(text, values);
    } finally {
      client.release();
    }
  };

  dbGet = async (query, params = []) => {
    const { text, values } = convertPlaceholders(query, params);
    const client = await pool.connect();
    try {
      const result = await client.query(text, values);
      return result.rows[0];
    } finally {
      client.release();
    }
  };

  dbAll = async (query, params = []) => {
    const { text, values } = convertPlaceholders(query, params);
    const client = await pool.connect();
    try {
      const result = await client.query(text, values);
      return result.rows;
    } finally {
      client.release();
    }
  };
} else {
  // fallback to sqlite for local/dev only
  const Database = require('sqlite3').Database;
  const dbPath = './cloudbackup.db';
  const db = new Database(dbPath);

  dbRun = (query, params = []) => new Promise((resolve, reject) => {
    db.run(query, params, function(err) {
      if (err) reject(err);
      else resolve({ changes: this.changes, lastID: this.lastID });
    });
  });

  dbGet = (query, params = []) => new Promise((resolve, reject) => {
    db.get(query, params, (err, row) => {
      if (err) reject(err);
      else resolve(row);
    });
  });

  dbAll = (query, params = []) => new Promise((resolve, reject) => {
    db.all(query, params, (err, rows) => {
      if (err) reject(err);
      else resolve(rows);
    });
  });
}

// --------- Use a persistent session store in production (Postgres) ---------
if (isPostgres) {
  const PgSession = require('connect-pg-simple')(session);
  app.use(session({
    store: new PgSession({
      pool: pool,                // uses same pg pool
      tableName: 'session'       // optional; default 'session'
    }),
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: NODE_ENV === 'production',
      httpOnly: true,
      sameSite: NODE_ENV === 'production' ? 'none' : 'lax'
    }
  }));
} else {
  // memory store for local dev (not for prod)
  app.use(session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false }
  }));
}

// --------- MULTER ---------
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadsDir),
  filename: (req, file, cb) => cb(null, `${uuidv4()}_${file.originalname}`)
});
const upload = multer({ storage });

// --------- AUTH HELPERS ---------
function generateToken(user) {
  return jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: process.env.JWT_EXPIRES_IN || '7d' });
}

function authMiddleware(req, res, next) {
  const header = req.headers['authorization'];
  if (!header) return res.status(401).json({ error: 'Missing token' });
  const token = header.split(' ')[1];
  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = decoded;
    next();
  });
}

// --------- AUTO MIGRATIONS (CREATE TABLES IF MISSING) ---------
async function initDatabase() {
  try {
    if (isPostgres) {
      // Run Postgres-compatible CREATE TABLE IF NOT EXISTS statements
      await dbRun(`
        CREATE TABLE IF NOT EXISTS users (
          id VARCHAR(36) PRIMARY KEY,
          email VARCHAR(255) UNIQUE NOT NULL,
          password_hash TEXT NOT NULL,
          first_name VARCHAR(100),
          last_name VARCHAR(100),
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
      `);

      await dbRun(`
        CREATE TABLE IF NOT EXISTS user_sessions (
          id VARCHAR(36) PRIMARY KEY,
          user_id VARCHAR(36) REFERENCES users(id) ON DELETE CASCADE,
          device_id VARCHAR(100),
          device_name VARCHAR(100),
          device_type VARCHAR(20),
          access_token_hash TEXT,
          refresh_token_hash TEXT,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          expires_at TIMESTAMP
        );
      `);

      await dbRun(`
        CREATE TABLE IF NOT EXISTS files (
          id VARCHAR(36) PRIMARY KEY,
          user_id VARCHAR(36) REFERENCES users(id) ON DELETE CASCADE,
          filename VARCHAR(255) NOT NULL,
          original_name VARCHAR(255),
          file_path TEXT NOT NULL,
          file_size BIGINT,
          mime_type VARCHAR(100),
          uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
      `);

      // session table used by connect-pg-simple (if not exists)
      await dbRun(`
        CREATE TABLE IF NOT EXISTS session (
          sid varchar NOT NULL COLLATE "default",
          sess json NOT NULL,
          expire timestamp(6) NOT NULL
        )
        WITH (OIDS=FALSE);
      `).catch(()=>{/* ignore if pg driver uses its own creation */});
    } else {
      // SQLite schema
      await dbRun(`
        CREATE TABLE IF NOT EXISTS users (
          id TEXT PRIMARY KEY,
          email TEXT UNIQUE NOT NULL,
          password_hash TEXT NOT NULL,
          first_name TEXT,
          last_name TEXT,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
      `);

      await dbRun(`
        CREATE TABLE IF NOT EXISTS user_sessions (
          id TEXT PRIMARY KEY,
          user_id TEXT,
          device_id TEXT,
          device_name TEXT,
          device_type TEXT,
          access_token_hash TEXT,
          refresh_token_hash TEXT,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          expires_at DATETIME,
          FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );
      `);

      await dbRun(`
        CREATE TABLE IF NOT EXISTS files (
          id TEXT PRIMARY KEY,
          user_id TEXT,
          filename TEXT NOT NULL,
          original_name TEXT,
          file_path TEXT NOT NULL,
          file_size INTEGER,
          mime_type TEXT,
          uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );
      `);
    }

    console.log('✅ Database initialized successfully');
  } catch (err) {
    console.error('❌ Database initialization error:', err);
    throw err;
  }
}

// --------- ROUTES (uses password_hash now) ---------

// register
app.post('/api/register', async (req, res) => {
  try {
    const { email, password, firstName = '', lastName = '' } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Missing email or password' });

    const hash = await bcrypt.hash(password, BCRYPT_ROUNDS);
    const id = uuidv4();

    await dbRun(
      `INSERT INTO users (id, email, password_hash, first_name, last_name) VALUES (?, ?, ?, ?, ?)`,
      [id, email, hash, firstName, lastName]
    );

    res.json({ success: true, id });
  } catch (err) {
    console.error('Register error', err);
    res.status(500).json({ error: 'Registration failed' });
  }
});

// login
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Missing email or password' });

    const user = await dbGet('SELECT * FROM users WHERE email = ?', [email]);
    if (!user) return res.status(400).json({ error: 'Invalid credentials' });

    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) return res.status(400).json({ error: 'Invalid credentials' });

    const token = generateToken(user);
    res.json({ token });
  } catch (err) {
    console.error('Login error', err);
    res.status(500).json({ error: 'Login failed' });
  }
});

// rest of routes (upload/list/download) unchanged but they rely on dbRun/dbGet/dbAll
app.post('/api/upload', authMiddleware, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
    const { originalname, filename, mimetype, size, path: filePath } = req.file;
    const fileId = uuidv4();

    await dbRun(
      `INSERT INTO files (id, user_id, filename, original_name, file_path, file_size, mime_type)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [fileId, req.user.id, filename, originalname, filePath, size, mimetype]
    );

    res.json({ success: true, fileId });
  } catch (err) {
    console.error('Upload error', err);
    res.status(500).json({ error: 'Upload failed' });
  }
});

app.get('/api/files', authMiddleware, async (req, res) => {
  try {
    const files = await dbAll('SELECT * FROM files WHERE user_id = ?', [req.user.id]);
    res.json({ files });
  } catch (err) {
    console.error('List files error', err);
    res.status(500).json({ error: 'Could not list files' });
  }
});

app.get('/api/files/:id/download', authMiddleware, async (req, res) => {
  try {
    const fileId = req.params.id;
    const fileRow = await dbGet('SELECT * FROM files WHERE id = ?', [fileId]);
    if (!fileRow) return res.status(404).json({ error: 'File not found' });
    if (fileRow.user_id !== req.user.id) return res.status(403).json({ error: 'Access denied' });

    const absPath = path.resolve(fileRow.file_path);
    if (!absPath.startsWith(uploadsDir)) {
      return res.status(400).json({ error: 'Invalid file path' });
    }
    if (!fs.existsSync(absPath)) return res.status(404).json({ error: 'File not found on disk' });

    res.setHeader('Content-Type', fileRow.mime_type || 'application/octet-stream');
    res.setHeader('Content-Disposition', `attachment; filename="${fileRow.original_name || fileRow.filename}"`);
    fs.createReadStream(absPath).pipe(res);
  } catch (err) {
    console.error('Download error', err);
    res.status(500).json({ error: 'Download failed' });
  }
});

// --------- START ---------
(async function start() {
  try {
    await initDatabase();
    app.listen(PORT, () => {
      console.log(`🚀 Server running on port ${PORT} in ${NODE_ENV} mode`);
    });
  } catch (err) {
    console.error('❌ Failed to start server:', err);
    process.exit(1);
  }
})();
