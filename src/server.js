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

// allow frontend origins
const allowedOrigins = [
  'http://localhost:3000',
  'http://127.0.0.1:3000'
];
if (process.env.FRONTEND_URL) allowedOrigins.push(process.env.FRONTEND_URL);

app.use(cors({
  origin: allowedOrigins,
  credentials: true
}));

app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: NODE_ENV === 'production',
    httpOnly: true,
    sameSite: NODE_ENV === 'production' ? 'none' : 'lax'
  }
}));

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

// --------- DATABASE SETUP ---------
const DATABASE_URL = process.env.DATABASE_URL;
let isPostgres = false;
let pool = null;
let dbRun, dbGet, dbAll, db;

function convertPlaceholders(query, params = []) {
  if (!isPostgres) return { text: query, values: params };
  let idx = 0;
  const text = query.replace(/\?/g, () => {
    idx++;
    return `$${idx}`;
  });
  return { text, values: params };
}

if (DATABASE_URL && DATABASE_URL.startsWith('postgresql://')) {
  isPostgres = true;
  const { Pool } = require('pg');
  pool = new Pool({
    connectionString: DATABASE_URL,
    ssl: NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
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
  const Database = require('sqlite3').Database;
  const dbPath = './cloudbackup.db';
  db = new Database(dbPath);

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

// --------- MULTER ---------
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadsDir),
  filename: (req, file, cb) => cb(null, `${uuidv4()}_${file.originalname}`)
});
const upload = multer({ storage });

// --------- ROUTES ---------

// register
app.post('/api/register', async (req, res) => {
  try {
    const { email, password } = req.body;
    const hash = await bcrypt.hash(password, BCRYPT_ROUNDS);
    const id = uuidv4();
    await dbRun('INSERT INTO users (id, email, password) VALUES (?, ?, ?)', [id, email, hash]);
    res.json({ success: true });
  } catch (err) {
    console.error('Register error', err);
    res.status(500).json({ error: 'Registration failed' });
  }
});

// login
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await dbGet('SELECT * FROM users WHERE email = ?', [email]);
    if (!user) return res.status(400).json({ error: 'Invalid credentials' });
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ error: 'Invalid credentials' });
    const token = generateToken(user);
    res.json({ token });
  } catch (err) {
    console.error('Login error', err);
    res.status(500).json({ error: 'Login failed' });
  }
});

// upload file
app.post('/api/upload', authMiddleware, upload.single('file'), async (req, res) => {
  try {
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

// list files
app.get('/api/files', authMiddleware, async (req, res) => {
  try {
    const files = await dbAll('SELECT * FROM files WHERE user_id = ?', [req.user.id]);
    res.json({ files });
  } catch (err) {
    console.error('List files error', err);
    res.status(500).json({ error: 'Could not list files' });
  }
});

// download file
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
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT} in ${NODE_ENV} mode`);
});
