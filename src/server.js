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

// =============================================================================
// 📝 LOGGER SETUP
// =============================================================================
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

logger.info('🚀 Starting Cloud Backup Server...');

// =============================================================================
// ⚙️ CONFIGURATION
// =============================================================================
const PORT = process.env.PORT || 3000;
const NODE_ENV = process.env.NODE_ENV || 'development';
const DATABASE_URL = process.env.DATABASE_PUBLIC_URL || process.env.DATABASE_URL; // Use PUBLIC_URL for Railway
const SESSION_SECRET = process.env.SESSION_SECRET || 'dev-session-secret-change-in-production';
const JWT_SECRET = process.env.JWT_SECRET || 'dev-jwt-secret-change-in-production';
const UPLOADS_DIR = process.env.UPLOAD_PATH || './uploads';
const BCRYPT_ROUNDS = parseInt(process.env.BCRYPT_ROUNDS, 10) || 12;

logger.info('📋 Configuration loaded', {
    port: PORT,
    environment: NODE_ENV,
    hasDatabase: !!DATABASE_URL,
    hasGoogleOAuth: !!(process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET)
});

// =============================================================================
// 🗄️ DATABASE SETUP & CONNECTION - RAILWAY OPTIMIZED
// =============================================================================
let pool;
let dbRun, dbGet, dbAll, closeDatabaseConnection;

if (DATABASE_URL && DATABASE_URL.startsWith('postgresql://')) {
    logger.info('🐘 Initializing PostgreSQL connection for Railway...');
    const { Pool } = require('pg');
    
    // Railway-specific SSL configuration
    const isRailway = DATABASE_URL.includes('railway.app') || DATABASE_URL.includes('rlwy.net');
    
    let poolConfig = {
        connectionString: DATABASE_URL,
        max: 10, // Reduced for Railway limits
        idleTimeoutMillis: 20000,
        connectionTimeoutMillis: 15000,
        acquireTimeoutMillis: 15000,
        allowExitOnIdle: true
    };

    // SSL configuration for Railway
    if (isRailway || NODE_ENV === 'production') {
        poolConfig.ssl = {
            rejectUnauthorized: false
        };
    }
    
    pool = new Pool(poolConfig);

    pool.on('connect', (client) => {
        logger.info('✅ Database pool connected successfully');
    });

    pool.on('error', (err, client) => {
        logger.error('❌ Database pool error', { 
            error: err.message, 
            code: err.code
        });
    });

    // Convert SQLite placeholders to PostgreSQL format
    const convertPlaceholders = (query) => {
        let i = 0;
        return query.replace(/\?/g, () => `$${++i}`);
    };

    // Enhanced database functions with retry logic
    dbRun = async (query, params = [], retries = 3) => {
        for (let attempt = 1; attempt <= retries; attempt++) {
            let client;
            try {
                client = await pool.connect();
                const result = await client.query(convertPlaceholders(query), params);
                return result;
            } catch (error) {
                logger.error(`❌ Database run query failed (attempt ${attempt}/${retries})`, { 
                    error: error.message, 
                    code: error.code,
                    query: query.substring(0, 50) + '...'
                });
                
                if (attempt === retries) throw error;
                await new Promise(resolve => setTimeout(resolve, 1000 * attempt));
            } finally {
                if (client) client.release();
            }
        }
    };

    dbGet = async (query, params = [], retries = 3) => {
        for (let attempt = 1; attempt <= retries; attempt++) {
            let client;
            try {
                client = await pool.connect();
                const result = await client.query(convertPlaceholders(query), params);
                return result.rows[0];
            } catch (error) {
                logger.error(`❌ Database get query failed (attempt ${attempt}/${retries})`, { 
                    error: error.message, 
                    code: error.code,
                    query: query.substring(0, 50) + '...'
                });
                
                if (attempt === retries) throw error;
                await new Promise(resolve => setTimeout(resolve, 1000 * attempt));
            } finally {
                if (client) client.release();
            }
        }
    };

    dbAll = async (query, params = [], retries = 3) => {
        for (let attempt = 1; attempt <= retries; attempt++) {
            let client;
            try {
                client = await pool.connect();
                const result = await client.query(convertPlaceholders(query), params);
                return result.rows;
            } catch (error) {
                logger.error(`❌ Database all query failed (attempt ${attempt}/${retries})`, { 
                    error: error.message, 
                    code: error.code,
                    query: query.substring(0, 50) + '...'
                });
                
                if (attempt === retries) throw error;
                await new Promise(resolve => setTimeout(resolve, 1000 * attempt));
            } finally {
                if (client) client.release();
            }
        }
    };

    closeDatabaseConnection = async () => {
        logger.info('🔒 Closing database pool...');
        try {
            await pool.end();
            logger.info('✅ Database pool closed successfully');
        } catch (error) {
            logger.error('❌ Error closing database pool', { error: error.message });
        }
    };

} else {
    logger.info('📁 Using SQLite database (development mode)');
    const Database = require('sqlite3').Database;
    const db = new Database('./cloudbackup.db');
    
    dbRun = (query, params = []) => new Promise((resolve, reject) => {
        db.run(query, params, function (err) {
            if (err) {
                logger.error('❌ SQLite run query failed', { error: err.message });
                reject(err);
            } else {
                resolve({ changes: this.changes, lastID: this.lastID });
            }
        });
    });
    
    dbGet = (query, params = []) => new Promise((resolve, reject) => {
        db.get(query, params, (err, row) => {
            if (err) {
                logger.error('❌ SQLite get query failed', { error: err.message });
                reject(err);
            } else {
                resolve(row);
            }
        });
    });
    
    dbAll = (query, params = []) => new Promise((resolve, reject) => {
        db.all(query, params, (err, rows) => {
            if (err) {
                logger.error('❌ SQLite all query failed', { error: err.message });
                reject(err);
            } else {
                resolve(rows);
            }
        });
    });
    
    closeDatabaseConnection = () => new Promise((resolve) => {
        logger.info('🔒 Closing SQLite database connection...');
        db.close((err) => {
            if (err) {
                logger.error('❌ Error closing SQLite database', { error: err.message });
            } else {
                logger.info('✅ SQLite database closed successfully');
            }
            resolve();
        });
    });
}

// =============================================================================
// 🗄️ DATABASE INITIALIZATION - SIMPLIFIED FOR RAILWAY
// =============================================================================
const initDatabase = async () => {
    try {
        logger.info('🔧 Testing database connection...');
        
        // Simple connection test without complex queries
        await dbGet('SELECT 1 as test');
        logger.info('✅ Database connection test successful');

        logger.info('🔧 Creating database tables...');

        // Create users table
        const usersTable = `
            CREATE TABLE IF NOT EXISTS users (
                id VARCHAR(36) PRIMARY KEY,
                email VARCHAR(255) UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                first_name VARCHAR(100),
                last_name VARCHAR(100),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `;
        
        await dbRun(usersTable);
        logger.info('✅ Users table ready');

        // Create files table
        const filesTable = `
            CREATE TABLE IF NOT EXISTS files (
                id VARCHAR(36) PRIMARY KEY,
                user_id VARCHAR(36),
                filename VARCHAR(255) NOT NULL,
                original_name VARCHAR(255) NOT NULL,
                file_path TEXT NOT NULL,
                file_size BIGINT NOT NULL,
                mime_type VARCHAR(100),
                uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `;
        
        await dbRun(filesTable);
        logger.info('✅ Files table ready');

        logger.info('🎉 Database initialization completed successfully');
    } catch (error) {
        logger.error('💥 Database initialization failed', { 
            error: error.message, 
            code: error.code,
            stack: error.stack
        });
        throw error;
    }
};

// =============================================================================
// 🚀 EXPRESS APP & MIDDLEWARE SETUP
// =============================================================================
const app = express();

// Security middleware
app.use(helmet({
    contentSecurityPolicy: false, // Disable for development
    crossOriginEmbedderPolicy: false
}));
app.use(compression());

// CORS configuration - Allow all origins for now
app.use(cors({
    origin: true, // Allow all origins
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
}));

// Logging middleware
app.use(morgan('combined', { 
    stream: { 
        write: message => logger.info(message.trim(), { type: 'access_log' }) 
    },
    skip: (req, res) => req.path === '/health'
}));

// Body parsing middleware
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: NODE_ENV === 'production' ? 200 : 1000,
    message: { success: false, error: 'Too many requests, please try again later.' },
    standardHeaders: true,
    legacyHeaders: false,
});
app.use('/api', limiter); // Only apply to API routes

// =============================================================================
// 🔐 SESSION & PASSPORT SETUP
// =============================================================================
// Use memory store for now to avoid session table issues
const sessionStore = new session.MemoryStore();
logger.info('⚠️ Using memory session store');

app.use(session({
    store: sessionStore,
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    name: 'cloudbackup.sid',
    cookie: {
        secure: false, // Allow HTTP for now
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000, // 24 hours
        sameSite: 'lax'
    }
}));

app.use(passport.initialize());
app.use(passport.session());

// Google OAuth Strategy
if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET) {
    passport.use(new GoogleStrategy({
        clientID: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackURL: process.env.GOOGLE_CALLBACK_URL || '/auth/google/callback'
    }, async (accessToken, refreshToken, profile, done) => {
        try {
            const email = profile.emails?.[0]?.value;
            if (!email) {
                logger.error('❌ Google OAuth: No email provided', { profileId: profile.id });
                return done(new Error('No email found in Google profile'), null);
            }

            let user = await dbGet('SELECT * FROM users WHERE email = ?', [email]);
            if (!user) {
                logger.info('👤 Creating new user from Google OAuth', { email });
                const userId = uuidv4();
                await dbRun(
                    'INSERT INTO users (id, email, password_hash, first_name, last_name) VALUES (?, ?, ?, ?, ?)',
                    [
                        userId, 
                        email, 
                        'google_oauth', 
                        profile.name?.givenName || 'Google', 
                        profile.name?.familyName || 'User'
                    ]
                );
                user = await dbGet('SELECT * FROM users WHERE id = ?', [userId]);
                logger.info('✅ New user created successfully', { userId, email });
            } else {
                logger.info('👋 Existing user logged in via Google OAuth', { userId: user.id, email });
            }
            
            return done(null, user);
        } catch (error) {
            logger.error('❌ Google OAuth strategy error', { 
                error: error.message
            });
            return done(error, null);
        }
    }));

    passport.serializeUser((user, done) => done(null, user.id));
    passport.deserializeUser(async (id, done) => {
        try {
            const user = await dbGet('SELECT * FROM users WHERE id = ?', [id]);
            done(null, user);
        } catch (error) {
            logger.error('❌ Error deserializing user', { error: error.message, userId: id });
            done(error, null);
        }
    });
    
    logger.info('🔐 Google OAuth configured successfully');
} else {
    logger.warn('⚠️ Google OAuth not configured (missing CLIENT_ID or CLIENT_SECRET)');
}

// =============================================================================
// 📁 FILE UPLOAD SETUP
// =============================================================================
if (!fs.existsSync(UPLOADS_DIR)) {
    logger.info(`📁 Creating uploads directory: ${UPLOADS_DIR}`);
    fs.mkdirSync(UPLOADS_DIR, { recursive: true });
}

const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, UPLOADS_DIR),
    filename: (req, file, cb) => {
        const uniqueFilename = `${uuidv4()}-${file.originalname}`;
        cb(null, uniqueFilename);
    }
});

const upload = multer({ 
    storage,
    limits: {
        fileSize: 100 * 1024 * 1024, // 100MB limit
        files: 1
    }
});

// =============================================================================
// 🛡️ AUTHENTICATION MIDDLEWARE
// =============================================================================
const authMiddleware = async (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({ success: false, error: 'Unauthorized: No token provided' });
        }

        const token = authHeader.split(' ')[1];
        const decoded = jwt.verify(token, JWT_SECRET);
        
        const user = await dbGet('SELECT * FROM users WHERE id = ?', [decoded.userId]);
        if (!user) {
            return res.status(401).json({ success: false, error: 'Unauthorized: User not found' });
        }
        
        req.user = { id: decoded.userId, email: user.email };
        next();
    } catch (error) {
        logger.error('❌ Auth middleware error', { error: error.message });
        return res.status(401).json({ success: false, error: 'Unauthorized: Invalid token' });
    }
};

const asyncHandler = (fn) => (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch(next);
};

// =============================================================================
// 🌐 API ROUTES
// =============================================================================

// Health check
app.get('/health', (req, res) => {
    res.status(200).json({ 
        status: 'healthy', 
        timestamp: new Date().toISOString(),
        environment: NODE_ENV,
        uptime: Math.floor(process.uptime())
    });
});

// Root endpoint
app.get('/', (req, res) => {
    res.json({
        message: 'Cloud Backup Server is running!',
        version: '1.0.0',
        endpoints: {
            health: '/health',
            auth: {
                register: 'POST /api/register',
                login: 'POST /api/login',
                googleOAuth: '/auth/google'
            },
            files: {
                upload: 'POST /api/upload',
                list: 'GET /api/files',
                download: 'GET /api/files/:id/download'
            }
        }
    });
});

// Google OAuth routes
if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET) {
    app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

    app.get('/auth/google/callback',
        passport.authenticate('google', { failureRedirect: '/auth/google/error' }),
        asyncHandler(async (req, res) => {
            logger.info('🎉 Google OAuth callback successful', { 
                userId: req.user.id, 
                email: req.user.email 
            });
            
            const token = jwt.sign({ userId: req.user.id }, JWT_SECRET, { expiresIn: '7d' });
            
            res.status(200).json({ 
                success: true, 
                token, 
                user: {
                    id: req.user.id,
                    email: req.user.email,
                    firstName: req.user.first_name,
                    lastName: req.user.last_name
                },
                message: 'Google OAuth login successful'
            });
        })
    );

    app.get('/auth/google/error', (req, res) => {
        logger.warn('⚠️ Google OAuth authentication failed');
        res.status(401).json({ success: false, error: 'Google OAuth authentication failed' });
    });
}

// User registration
app.post('/api/register', asyncHandler(async (req, res) => {
    const schema = Joi.object({
        email: Joi.string().email().required(),
        password: Joi.string().min(6).required(),
        firstName: Joi.string().min(1).max(100).optional(),
        lastName: Joi.string().min(1).max(100).optional()
    });

    const { error, value } = schema.validate(req.body);
    if (error) {
        return res.status(400).json({ success: false, error: error.details[0].message });
    }

    const { email, password, firstName, lastName } = value;
    
    const existingUser = await dbGet('SELECT id FROM users WHERE email = ?', [email]);
    if (existingUser) {
        return res.status(409).json({ success: false, error: 'User with this email already exists' });
    }

    const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);
    const userId = uuidv4();
    
    await dbRun(
        'INSERT INTO users (id, email, password_hash, first_name, last_name) VALUES (?, ?, ?, ?, ?)',
        [userId, email, passwordHash, firstName || null, lastName || null]
    );
    
    logger.info('👤 User registered successfully', { userId, email });
    
    res.status(201).json({ 
        success: true, 
        message: 'User registered successfully',
        user: { id: userId, email }
    });
}));

// User login
app.post('/api/login', asyncHandler(async (req, res) => {
    const schema = Joi.object({
        email: Joi.string().email().required(),
        password: Joi.string().required()
    });

    const { error, value } = schema.validate(req.body);
    if (error) {
        return res.status(400).json({ success: false, error: error.details[0].message });
    }

    const { email, password } = value;
    
    const user = await dbGet('SELECT * FROM users WHERE email = ?', [email]);
    if (!user) {
        return res.status(401).json({ success: false, error: 'Invalid email or password' });
    }

    if (user.password_hash === 'google_oauth') {
        return res.status(401).json({ success: false, error: 'Please use Google OAuth to login' });
    }

    const isValidPassword = await bcrypt.compare(password, user.password_hash);
    if (!isValidPassword) {
        return res.status(401).json({ success: false, error: 'Invalid email or password' });
    }

    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '7d' });
    
    logger.info('🔐 User logged in successfully', { userId: user.id, email });
    
    res.status(200).json({ 
        success: true, 
        token, 
        user: { 
            id: user.id, 
            email: user.email,
            firstName: user.first_name,
            lastName: user.last_name
        },
        message: 'Login successful'
    });
}));

// File upload
app.post('/api/upload', authMiddleware, upload.single('file'), asyncHandler(async (req, res) => {
    if (!req.file) {
        return res.status(400).json({ success: false, error: 'No file was uploaded' });
    }
    
    const { filename, originalname, path: filePath, size, mimetype } = req.file;
    const fileId = uuidv4();
    
    await dbRun(
        'INSERT INTO files (id, user_id, filename, original_name, file_path, file_size, mime_type) VALUES (?, ?, ?, ?, ?, ?, ?)',
        [fileId, req.user.id, filename, originalname, filePath, size, mimetype]
    );

    logger.info('📁 File uploaded successfully', { 
        userId: req.user.id, 
        fileId, 
        originalname, 
        size: `${Math.round(size / 1024)}KB` 
    });
    
    res.status(201).json({ 
        success: true, 
        fileId, 
        filename: originalname,
        size,
        message: 'File uploaded successfully' 
    });
}));

// Get user files
app.get('/api/files', authMiddleware, asyncHandler(async (req, res) => {
    const files = await dbAll(
        'SELECT id, original_name, file_size, mime_type, uploaded_at FROM files WHERE user_id = ? ORDER BY uploaded_at DESC', 
        [req.user.id]
    );
    
    res.status(200).json({ 
        success: true, 
        files: files.map(file => ({
            id: file.id,
            name: file.original_name,
            size: file.file_size,
            type: file.mime_type,
            uploadedAt: file.uploaded_at
        })),
        count: files.length
    });
}));

// Download file
app.get('/api/files/:id/download', authMiddleware, asyncHandler(async (req, res) => {
    const { id } = req.params;
    
    const file = await dbGet('SELECT * FROM files WHERE id = ? AND user_id = ?', [id, req.user.id]);
    if (!file) {
        return res.status(404).json({ success: false, error: 'File not found or access denied' });
    }

    const absolutePath = path.resolve(file.file_path);
    if (!fs.existsSync(absolutePath)) {
        logger.error('❌ File missing from disk', { fileId: id, path: absolutePath });
        return res.status(404).json({ success: false, error: 'File not found on server' });
    }

    logger.info('⬇️ File download requested', { userId: req.user.id, fileId: id });
    
    res.download(absolutePath, file.original_name, (err) => {
        if (err) {
            logger.error('❌ File download error', { error: err.message, fileId: id });
        }
    });
}));

// =============================================================================
// 💣 ERROR HANDLING
// =============================================================================

// 404 handler
app.use((req, res, next) => {
    res.status(404).json({ success: false, error: 'Endpoint not found' });
});

// Global error handler
app.use((err, req, res, next) => {
    logger.error('💥 Unhandled error occurred', {
        error: err.message,
        stack: err.stack,
        url: req.originalUrl,
        method: req.method
    });
    
    res.status(500).json({ 
        success: false, 
        error: NODE_ENV === 'production' ? 'Internal server error' : err.message 
    });
});

// =============================================================================
// 🚀 SERVER STARTUP & GRACEFUL SHUTDOWN
// =============================================================================
let server;

const startServer = async () => {
    try {
        await initDatabase();
        
        server = app.listen(PORT, '0.0.0.0', () => {
            logger.info(`🎉 Cloud Backup Server is running!`, {
                port: PORT,
                environment: NODE_ENV,
                urls: {
                    health: `http://localhost:${PORT}/health`,
                    root: `http://localhost:${PORT}/`,
                    oauth: process.env.GOOGLE_CLIENT_ID ? `http://localhost:${PORT}/auth/google` : 'Not configured'
                }
            });
        });

        server.on('error', (err) => {
            logger.error('❌ Server error', { error: err.message, code: err.code });
            process.exit(1);
        });

    } catch (error) {
        logger.error('💥 Failed to start server', { 
            error: error.message, 
            stack: error.stack 
        });
        process.exit(1);
    }
};

const gracefulShutdown = async (signal) => {
    logger.warn(`🛑 Received ${signal}. Starting graceful shutdown...`);
    
    if (server) {
        server.close(async (err) => {
            if (err) {
                logger.error('❌ Error closing HTTP server', { error: err.message });
            } else {
                logger.info('✅ HTTP server closed');
            }
            
            await closeDatabaseConnection();
            logger.info('👋 Graceful shutdown completed');
            process.exit(0);
        });
    } else {
        await closeDatabaseConnection();
        process.exit(0);
    }
    
    setTimeout(() => {
        logger.error('⏰ Forced shutdown due to timeout');
        process.exit(1);
    }, 30000);
};

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

process.on('unhandledRejection', (reason, promise) => {
    logger.error('💥 Unhandled Promise Rejection', { 
        reason: reason?.stack || reason
    });
    gracefulShutdown('unhandledRejection');
});

process.on('uncaughtException', (err) => {
    logger.error('💥 Uncaught Exception', { 
        error: err.message, 
        stack: err.stack 
    });
    gracefulShutdown('uncaughtException');
});

// Start the application
startServer();
