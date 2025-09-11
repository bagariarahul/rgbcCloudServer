// =============================================================================
// 📦 IMPORTS & INITIAL SETUP
// =============================================================================
require('dotenv').config();

const express = require('express');
const cors = require('cors');
const morgan = require('morgan');
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const Joi = require('joi');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const session = require('express-session');
const pgSession = require('connect-pg-simple')(session);

// =============================================================================
// 📝 LOGGER SETUP
// =============================================================================
// A simple logger for consistent, timestamped output.
const logger = {
    log: (level, message, meta) => {
        const timestamp = new Date().toISOString();
        const logObject = { timestamp, level, message, ...meta };
        console.log(JSON.stringify(logObject));
    },
    info: (message, meta) => logger.log('INFO', message, meta),
    warn: (message, meta) => logger.log('WARN', message, meta),
    error: (message, meta) => logger.log('ERROR', message, meta),
    debug: (message, meta) => {
        if (process.env.NODE_ENV !== 'production') {
            logger.log('DEBUG', message, meta);
        }
    },
};

logger.info('Starting server process...');

// =============================================================================
// ⚙️ CONFIGURATION
// =============================================================================
const PORT = process.env.PORT || 3000;
const NODE_ENV = process.env.NODE_ENV || 'development';
const DATABASE_URL = process.env.DATABASE_URL;
const SESSION_SECRET = process.env.SESSION_SECRET || 'dev-session-secret';
const JWT_SECRET = process.env.JWT_SECRET || 'dev-jwt-secret';
const UPLOADS_DIR = process.env.UPLOAD_PATH || './uploads';
const BCRYPT_ROUNDS = parseInt(process.env.BCRYPT_ROUNDS, 10) || 12;

// =============================================================================
// 🗄️ DATABASE SETUP & CONNECTION
// =============================================================================
let pool;
let dbRun, dbGet, dbAll, closeDatabaseConnection;

if (DATABASE_URL && DATABASE_URL.startsWith('postgresql://')) {
    logger.info('Using PostgreSQL database');
    const { Pool } = require('pg');
    
    // Create a new pool with SSL required for production environments like Railway
    pool = new Pool({
        connectionString: DATABASE_URL,
        ssl: {
            rejectUnauthorized: false
        }
    });

    pool.on('connect', () => {
        logger.info('Database pool connected.');
    });

    pool.on('error', (err) => {
        logger.error('Unexpected error on idle client', { error: err.message });
        process.exit(-1);
    });

    // Function to convert SQLite's '?' placeholders to PostgreSQL's '$1', '$2', etc.
    const convertPlaceholders = (query) => {
        let i = 0;
        return query.replace(/\?/g, () => `$${++i}`);
    };

    dbRun = async (query, params = []) => {
        const client = await pool.connect();
        try {
            logger.debug('Executing DB run query', { query, params });
            const result = await client.query(convertPlaceholders(query), params);
            return result;
        } finally {
            client.release();
        }
    };

    dbGet = async (query, params = []) => {
        const client = await pool.connect();
        try {
            logger.debug('Executing DB get query', { query, params });
            const result = await client.query(convertPlaceholders(query), params);
            return result.rows[0];
        } finally {
            client.release();
        }
    };

    dbAll = async (query, params = []) => {
        const client = await pool.connect();
        try {
            logger.debug('Executing DB all query', { query, params });
            const result = await client.query(convertPlaceholders(query), params);
            return result.rows;
        } finally {
            client.release();
        }
    };

    closeDatabaseConnection = async () => {
        logger.info('Closing database pool...');
        await pool.end();
    };

} else {
    logger.info('Using SQLite database (development)');
    const Database = require('sqlite3').Database;
    const db = new Database('./cloudbackup.db');
    
    dbRun = (query, params = []) => new Promise((resolve, reject) => {
        db.run(query, params, function (err) {
            if (err) reject(err); else resolve({ changes: this.changes, lastID: this.lastID });
        });
    });
    dbGet = (query, params = []) => new Promise((resolve, reject) => {
        db.get(query, params, (err, row) => { if (err) reject(err); else resolve(row); });
    });
    dbAll = (query, params = []) => new Promise((resolve, reject) => {
        db.all(query, params, (err, rows) => { if (err) reject(err); else resolve(rows); });
    });
    closeDatabaseConnection = () => new Promise((resolve) => {
        logger.info('Closing SQLite database connection...');
        db.close(resolve);
    });
}

const initDatabase = async () => {
    try {
        const userTable = `
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                first_name TEXT,
                last_name TEXT,
                created_at ${NODE_ENV === 'production' ? 'TIMESTAMP' : 'DATETIME'} DEFAULT CURRENT_TIMESTAMP
            );
        `;
        await dbRun(userTable);

        const filesTable = `
            CREATE TABLE IF NOT EXISTS files (
                id TEXT PRIMARY KEY,
                user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
                filename TEXT NOT NULL,
                original_name TEXT NOT NULL,
                file_path TEXT NOT NULL,
                file_size BIGINT NOT NULL,
                mime_type TEXT,
                uploaded_at ${NODE_ENV === 'production' ? 'TIMESTAMP' : 'DATETIME'} DEFAULT CURRENT_TIMESTAMP
            );
        `;
        await dbRun(filesTable);
        
        logger.info('✅ Database schema initialized successfully');
    } catch (error) {
        logger.error('❌ Database initialization failed', { error: error.message, stack: error.stack });
        throw error; // Propagate error to stop the server from starting
    }
};


// =============================================================================
// 🚀 EXPRESS APP & MIDDLEWARE SETUP
// =============================================================================
const app = express();

app.use(helmet());
app.use(compression());
app.use(cors({
    origin: ['http://localhost:3000', 'http://127.0.0.1:3000', process.env.FRONTEND_URL].filter(Boolean),
    credentials: true
}));
app.use(morgan('combined', { stream: { write: message => logger.info(message.trim(), { type: 'access_log' }) } }));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

app.use(rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 1000,
    message: { success: false, error: 'Too many requests, please try again later.' }
}));


// =============================================================================
// 🔐 SESSION & PASSPORT (AUTH) SETUP
// =============================================================================
// Use PostgreSQL for session storage in production, otherwise default to memory store for dev
const sessionStore = (NODE_ENV === 'production' && pool)
    ? new pgSession({ pool, tableName: 'user_sessions' }) // 'user_sessions' table will be created automatically
    : new session.MemoryStore();

if(NODE_ENV === 'production' && pool) {
    logger.info('Using pgSession for persistent session storage.');
} else {
    logger.warn('Using MemoryStore for sessions. Not suitable for production!');
}

app.use(session({
    store: sessionStore,
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: NODE_ENV === 'production',
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000 // 24 hours
    }
}));

app.use(passport.initialize());
app.use(passport.session());

// Google OAuth Strategy
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: process.env.GOOGLE_CALLBACK_URL
}, async (accessToken, refreshToken, profile, done) => {
    try {
        const email = profile.emails?.[0]?.value;
        if (!email) {
            logger.error('Google OAuth failed: No email provided.', { profileId: profile.id });
            return done(new Error('No email found in Google profile.'), null);
        }

        let user = await dbGet('SELECT * FROM users WHERE email = ?', [email]);
        if (!user) {
            logger.info('New user via Google OAuth. Creating account...', { email });
            const userId = uuidv4();
            await dbRun(
                'INSERT INTO users (id, email, password_hash, first_name, last_name) VALUES (?, ?, ?, ?, ?)',
                [userId, email, 'google_oauth', profile.name?.givenName || 'Google', profile.name?.familyName || 'User']
            );
            user = await dbGet('SELECT * FROM users WHERE id = ?', [userId]);
        } else {
            logger.info('Existing user logged in via Google OAuth.', { email });
        }
        return done(null, user);
    } catch (error) {
        logger.error('Error during Google OAuth strategy execution.', { error: error.message });
        return done(error, null);
    }
}));

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
    try {
        const user = await dbGet('SELECT * FROM users WHERE id = ?', [id]);
        done(null, user);
    } catch (error) {
        done(error, null);
    }
});


// =============================================================================
// 📁 FILE UPLOAD (MULTER) SETUP
// =============================================================================
if (!fs.existsSync(UPLOADS_DIR)) {
    logger.info(`Uploads directory not found. Creating at: ${UPLOADS_DIR}`);
    fs.mkdirSync(UPLOADS_DIR, { recursive: true });
}

const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, UPLOADS_DIR),
    filename: (req, file, cb) => cb(null, `${uuidv4()}-${file.originalname}`)
});
const upload = multer({ storage });


// =============================================================================
// 🛡️ CUSTOM AUTHENTICATION MIDDLEWARE
// =============================================================================
const authMiddleware = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ success: false, error: 'Unauthorized: No token provided' });
    }

    const token = authHeader.split(' ')[1];
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = { id: decoded.userId }; // Attach user ID to the request
        next();
    } catch (error) {
        return res.status(401).json({ success: false, error: 'Unauthorized: Invalid token' });
    }
};

// Async error handling wrapper for routes
const asyncHandler = fn => (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch(next);
};

// =============================================================================
// ↔️ API ROUTES
// =============================================================================

// --- Health Check ---
app.get('/health', (req, res) => {
    res.status(200).json({ status: 'healthy', timestamp: new Date().toISOString() });
});

// --- Google OAuth Routes ---
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get('/auth/google/callback',
    passport.authenticate('google', { failureRedirect: '/auth/google/error' }),
    asyncHandler(async (req, res) => {
        logger.info('Google OAuth callback successful', { email: req.user.email });
        // Redirect to frontend with token, or send token directly.
        // This example sends the token directly.
        const token = jwt.sign({ userId: req.user.id }, JWT_SECRET, { expiresIn: '7d' });
        res.status(200).json({ success: true, token, user: req.user });
    })
);

app.get('/auth/google/error', (req, res) => {
    res.status(401).json({ success: false, error: 'Google OAuth authentication failed.' });
});

// --- User & Auth Routes ---
app.post('/api/register', asyncHandler(async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).json({ success: false, error: 'Email and password are required.' });
    }
    
    const existingUser = await dbGet('SELECT id FROM users WHERE email = ?', [email]);
    if (existingUser) {
        return res.status(409).json({ success: false, error: 'User with this email already exists.' });
    }

    const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);
    const userId = uuidv4();
    await dbRun('INSERT INTO users (id, email, password_hash) VALUES (?, ?, ?)', [userId, email, passwordHash]);
    
    logger.info('User registered successfully', { userId, email });
    res.status(201).json({ success: true, message: 'User created.' });
}));

app.post('/api/login', asyncHandler(async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).json({ success: false, error: 'Email and password are required.' });
    }
    
    const user = await dbGet('SELECT * FROM users WHERE email = ?', [email]);
    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
        return res.status(401).json({ success: false, error: 'Invalid credentials.' });
    }

    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '7d' });
    logger.info('User logged in successfully', { userId: user.id, email });
    res.status(200).json({ success: true, token, user: { id: user.id, email: user.email }});
}));


// --- File Management Routes ---
app.post('/api/upload', authMiddleware, upload.single('file'), asyncHandler(async (req, res) => {
    if (!req.file) {
        return res.status(400).json({ success: false, error: 'No file was uploaded.' });
    }
    
    const { filename, originalname, path: filePath, size, mimetype } = req.file;
    const fileId = uuidv4();
    await dbRun(
        'INSERT INTO files (id, user_id, filename, original_name, file_path, file_size, mime_type) VALUES (?, ?, ?, ?, ?, ?, ?)',
        [fileId, req.user.id, filename, originalname, filePath, size, mimetype]
    );

    logger.info('File uploaded successfully', { userId: req.user.id, fileId, originalname, size });
    res.status(201).json({ success: true, fileId, message: 'File uploaded.' });
}));

app.get('/api/files', authMiddleware, asyncHandler(async (req, res) => {
    const files = await dbAll('SELECT id, original_name, file_size, mime_type, uploaded_at FROM files WHERE user_id = ?', [req.user.id]);
    res.status(200).json({ success: true, files });
}));

app.get('/api/files/:id/download', authMiddleware, asyncHandler(async (req, res) => {
    const { id } = req.params;
    const file = await dbGet('SELECT * FROM files WHERE id = ? AND user_id = ?', [id, req.user.id]);
    
    if (!file) {
        return res.status(404).json({ success: false, error: 'File not found or access denied.' });
    }

    const absolutePath = path.resolve(file.file_path);
    if (!fs.existsSync(absolutePath)) {
        logger.error('File missing from disk but present in DB', { fileId: id, path: absolutePath });
        return res.status(404).json({ success: false, error: 'File not found on server.' });
    }

    logger.info('User downloading file', { userId: req.user.id, fileId: id });
    res.download(absolutePath, file.original_name);
}));


// =============================================================================
// 💣 ERROR HANDLING
// =============================================================================

// Handle 404 Not Found
app.use((req, res, next) => {
    res.status(404).json({ success: false, error: 'Not Found' });
});

// Centralized Error Handler
app.use((err, req, res, next) => {
    logger.error('An unhandled error occurred', {
        error: err.message,
        stack: err.stack,
        url: req.originalUrl,
        method: req.method
    });
    res.status(500).json({ success: false, error: 'Internal Server Error' });
});


// =============================================================================
// 🚀 SERVER START & GRACEFUL SHUTDOWN
// =============================================================================
let server;

const startServer = async () => {
    try {
        await initDatabase();
        server = app.listen(PORT, () => {
            logger.info(`✅ Server is live and running on port ${PORT} in ${NODE_ENV} mode.`);
        });
    } catch (error) {
        logger.error('❌ Failed to start server after setup', { error: error.message });
        process.exit(1);
    }
};

const gracefulShutdown = async (signal) => {
    logger.warn(`Received ${signal}. Starting graceful shutdown...`);
    
    if (server) {
        server.close(async () => {
            logger.info('HTTP server closed.');
            await closeDatabaseConnection();
            logger.info('All connections closed. Exiting.');
            process.exit(0);
        });
    } else {
        await closeDatabaseConnection();
        logger.info('Server was not running. Exiting.');
        process.exit(0);
    }
    
    // Force shutdown after a timeout
    setTimeout(() => {
        logger.error('Could not close connections in time, forcing shutdown.');
        process.exit(1);
    }, 10000); // 10 seconds
};

// Listen for termination signals
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// Catch unhandled exceptions and rejections
process.on('unhandledRejection', (reason, promise) => {
    logger.error('Unhandled Rejection at:', { promise, reason: reason.stack || reason });
    gracefulShutdown('unhandledRejection');
});

process.on('uncaughtException', (err) => {
    logger.error('Uncaught Exception thrown', { error: err.stack });
    gracefulShutdown('uncaughtException');
});

// Start the application
startServer();