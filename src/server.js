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
require('dotenv').config();

// Database setup (PostgreSQL or SQLite)
let db, dbRun, dbGet, dbAll;
const DATABASE_URL = process.env.DATABASE_URL;

if (DATABASE_URL && DATABASE_URL.startsWith('postgresql://')) {
    // PostgreSQL setup
    const { Pool } = require('pg');
    const pool = new Pool({ connectionString: DATABASE_URL });
    
    dbRun = async (query, params = []) => {
        const client = await pool.connect();
        try {
            const result = await client.query(query, params);
            return result;
        } finally {
            client.release();
        }
    };
    
    dbGet = async (query, params = []) => {
        const client = await pool.connect();
        try {
            const result = await client.query(query, params);
            return result.rows[0];
        } finally {
            client.release();
        }
    };
    
    dbAll = async (query, params = []) => {
        const client = await pool.connect();
        try {
            const result = await client.query(query, params);
            return result.rows;
        } finally {
            client.release();
        }
    };
} else {
    // SQLite setup
    const Database = require('sqlite3').Database;
    const dbPath = './cloudbackup.db';
    db = new Database(dbPath);
    
    dbRun = (query, params = []) => {
        return new Promise((resolve, reject) => {
            db.run(query, params, function(err) {
                if (err) reject(err);
                else resolve({ changes: this.changes, lastID: this.lastID });
            });
        });
    };
    
    dbGet = (query, params = []) => {
        return new Promise((resolve, reject) => {
            db.get(query, params, (err, row) => {
                if (err) reject(err);
                else resolve(row);
            });
        });
    };
    
    dbAll = (query, params = []) => {
        return new Promise((resolve, reject) => {
            db.all(query, params, (err, rows) => {
                if (err) reject(err);
                else resolve(rows);
            });
        });
    };
}

// Initialize Express app
const app = express();

// =============================================================================
// 🛡️ SECURITY & MIDDLEWARE
// =============================================================================

app.use(helmet());
app.use(compression());
app.use(cors({
    origin: ['http://localhost:3000', 'http://127.0.0.1:3000'],
    credentials: true
}));
app.use(morgan('combined'));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 1000,
    message: { error: 'Too many requests from this IP, please try again later.' }
});
app.use(limiter);

// =============================================================================
// 🔐 SESSION & PASSPORT CONFIGURATION
// =============================================================================

// Session configuration
app.use(session({
    secret: process.env.SESSION_SECRET || 'your-session-secret-change-this',
    resave: false,
    saveUninitialized: false,
    cookie: { 
        secure: process.env.NODE_ENV === 'production',
        maxAge: 24 * 60 * 60 * 1000 // 24 hours
    }
}));

app.use(passport.initialize());
app.use(passport.session());

// Google OAuth Strategy
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: process.env.GOOGLE_CALLBACK_URL || "http://localhost:3000/auth/google/callback"
}, async (accessToken, refreshToken, profile, done) => {
    try {
        console.log('🔑 Google OAuth profile received:', {
            id: profile.id,
            email: profile.emails?.[0]?.value,
            name: profile.displayName
        });
        
        if (!profile.emails || profile.emails.length === 0) {
            return done(new Error('No email provided by Google'), null);
        }
        
        const email = profile.emails[0].value;
        
        // Check if user exists
        let user = await dbGet('SELECT * FROM users WHERE email = ?', [email]);
        
        if (!user) {
            // Create new user from Google profile
            const userId = uuidv4();
            await dbRun(`
                INSERT INTO users (id, email, password_hash, first_name, last_name)
                VALUES (?, ?, ?, ?, ?)
            `, [
                userId, 
                email,
                'google_oauth', // Special marker for OAuth users
                profile.name?.givenName || 'Google',
                profile.name?.familyName || 'User'
            ]);
            
            user = await dbGet('SELECT * FROM users WHERE id = ?', [userId]);
            console.log('✅ Created new user from Google OAuth:', email);
        } else {
            console.log('✅ Existing user logged in via Google OAuth:', email);
        }
        
        return done(null, user);
    } catch (error) {
        console.error('❌ Google OAuth error:', error);
        return done(error, null);
    }
}));

// Serialize user for session
passport.serializeUser((user, done) => {
    done(null, user.id);
});

// Deserialize user from session
passport.deserializeUser(async (id, done) => {
    try {
        const user = await dbGet('SELECT * FROM users WHERE id = ?', [id]);
        done(null, user);
    } catch (error) {
        done(error, null);
    }
});

// =============================================================================
// 📁 FILE UPLOAD CONFIGURATION
// =============================================================================

const uploadsDir = process.env.UPLOAD_PATH || './uploads';
if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir, { recursive: true });
}

const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, uploadsDir),
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
    }
});

const upload = multer({
    storage,
    limits: { 
        fileSize: parseInt(process.env.MAX_FILE_SIZE?.replace('MB', '')) * 1024 * 1024 || 100 * 1024 * 1024 
    },
    fileFilter: (req, file, cb) => {
        cb(null, true);
    }
});

// =============================================================================
// 🔐 AUTHENTICATION MIDDLEWARE
// =============================================================================

const authMiddleware = async (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({ success: false, error: 'No token provided' });
        }

        const token = authHeader.substring(7);
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'fallback_secret');
        
        const user = await dbGet('SELECT * FROM users WHERE id = ?', [decoded.userId]);
        if (!user) {
            return res.status(401).json({ success: false, error: 'User not found' });
        }

        req.user = { ...user, sessionId: decoded.sessionId };
        next();
    } catch (error) {
        console.error('Auth middleware error:', error);
        res.status(401).json({ success: false, error: 'Invalid token' });
    }
};

// =============================================================================
// 🗄️ DATABASE INITIALIZATION
// =============================================================================

const initDatabase = async () => {
    try {
        if (DATABASE_URL && DATABASE_URL.startsWith('postgresql://')) {
            // PostgreSQL schema
            await dbRun(`
                CREATE TABLE IF NOT EXISTS users (
                    id VARCHAR(36) PRIMARY KEY,
                    email VARCHAR(255) UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    first_name VARCHAR(100),
                    last_name VARCHAR(100),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
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
                )
            `);
            
            await dbRun(`
                CREATE TABLE IF NOT EXISTS files (
                    id VARCHAR(36) PRIMARY KEY,
                    user_id VARCHAR(36) REFERENCES users(id) ON DELETE CASCADE,
                    filename VARCHAR(255) NOT NULL,
                    original_name VARCHAR(255) NOT NULL,
                    file_path TEXT NOT NULL,
                    file_size BIGINT NOT NULL,
                    mime_type VARCHAR(100),
                    uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            `);
        } else {
            // SQLite schema
            await dbRun(`
                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    first_name TEXT,
                    last_name TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
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
                )
            `);
            
            await dbRun(`
                CREATE TABLE IF NOT EXISTS files (
                    id TEXT PRIMARY KEY,
                    user_id TEXT,
                    filename TEXT NOT NULL,
                    original_name TEXT NOT NULL,
                    file_path TEXT NOT NULL,
                    file_size INTEGER NOT NULL,
                    mime_type TEXT,
                    uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
                )
            `);
        }
        
        console.log('✅ Database initialized successfully');
    } catch (error) {
        console.error('❌ Database initialization error:', error);
        throw error;
    }
};

// =============================================================================
// 🔑 GOOGLE OAUTH ENDPOINTS
// =============================================================================

// Start Google OAuth flow
app.get('/auth/google',
    passport.authenticate('google', { scope: ['profile', 'email'] })
);

// Google OAuth callback
app.get('/auth/google/callback',
    passport.authenticate('google', { failureRedirect: '/auth/google/error' }),
    async (req, res) => {
        try {
            console.log('🎉 Google OAuth callback successful for:', req.user.email);
            
            // Create JWT tokens for API compatibility
            const sessionId = uuidv4();
            const tokenPayload = { 
                userId: req.user.id, 
                sessionId, 
                email: req.user.email 
            };
            
            const accessToken = jwt.sign(tokenPayload, process.env.JWT_SECRET || 'fallback_secret', {
                expiresIn: '7d'
            });
            
            const refreshToken = jwt.sign(
                { ...tokenPayload, type: 'refresh' }, 
                process.env.JWT_SECRET || 'fallback_secret', 
                { expiresIn: '30d' }
            );
            
            const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();
            
            // Store session in database
            await dbRun(`
                INSERT INTO user_sessions (id, user_id, device_id, device_name, device_type,
                                         access_token_hash, refresh_token_hash, expires_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            `, [
                sessionId, req.user.id, 'oauth_web', 'Google OAuth Web', 'WEB',
                await bcrypt.hash(accessToken, 5), 
                await bcrypt.hash(refreshToken, 5), 
                expiresAt
            ]);
            
            // Return tokens as JSON (you can modify this to redirect to your frontend)
            res.json({
                success: true,
                message: 'Google OAuth login successful',
                user: {
                    id: req.user.id,
                    email: req.user.email,
                    firstName: req.user.first_name,
                    lastName: req.user.last_name
                },
                tokens: {
                    accessToken,
                    refreshToken,
                    expiresIn: '7d'
                },
                sessionId
            });
            
        } catch (error) {
            console.error('OAuth callback error:', error);
            res.status(500).json({ 
                success: false,
                error: 'OAuth login failed',
                message: error.message 
            });
        }
    }
);

// OAuth error handler
app.get('/auth/google/error', (req, res) => {
    res.status(400).json({
        success: false,
        error: 'Google OAuth failed',
        message: 'Authentication with Google was unsuccessful'
    });
});

// Check OAuth status
app.get('/auth/status', authMiddleware, (req, res) => {
    res.json({
        authenticated: true,
        method: 'jwt',
        user: {
            id: req.user.id,
            email: req.user.email,
            firstName: req.user.first_name,
            lastName: req.user.last_name
        }
    });
});

// Logout endpoint
app.post('/auth/logout', authMiddleware, async (req, res) => {
    try {
        // Remove session from database
        await dbRun('DELETE FROM user_sessions WHERE id = ?', [req.user.sessionId]);
        
        // Logout from passport session
        req.logout((err) => {
            if (err) {
                console.error('Logout error:', err);
            }
        });
        
        res.json({
            success: true,
            message: 'Logged out successfully'
        });
    } catch (error) {
        console.error('Logout error:', error);
        res.status(500).json({
            success: false,
            error: 'Logout failed'
        });
    }
});

// =============================================================================
// 🔐 AUTHENTICATION ENDPOINTS (Regular email/password)
// =============================================================================

// Registration
app.post('/api/auth/register', async (req, res) => {
    try {
        const schema = Joi.object({
            email: Joi.string().email().required(),
            password: Joi.string().min(6).required(),
            firstName: Joi.string().min(1).required(),
            lastName: Joi.string().min(1).required(),
            deviceId: Joi.string().required(),
            deviceName: Joi.string().required(),
            deviceType: Joi.string().valid('MOBILE', 'WEB', 'DESKTOP').required()
        });
        
        const { error, value } = schema.validate(req.body);
        if (error) {
            return res.status(400).json({ success: false, error: error.details[0].message });
        }
        
        const { email, password, firstName, lastName, deviceId, deviceName, deviceType } = value;
        
        // Check if user already exists
        const existingUser = await dbGet('SELECT id FROM users WHERE email = ?', [email]);
        if (existingUser) {
            return res.status(409).json({ success: false, error: 'User already exists with this email' });
        }
        
        // Hash password
        const saltRounds = parseInt(process.env.BCRYPT_ROUNDS) || 12;
        const passwordHash = await bcrypt.hash(password, saltRounds);
        
        // Create user
        const userId = uuidv4();
        await dbRun(
            'INSERT INTO users (id, email, password_hash, first_name, last_name) VALUES (?, ?, ?, ?, ?)',
            [userId, email, passwordHash, firstName, lastName]
        );
        
        // Generate tokens
        const sessionId = uuidv4();
        const tokenPayload = { userId, sessionId, email };
        const accessToken = jwt.sign(tokenPayload, process.env.JWT_SECRET || 'fallback_secret', {
            expiresIn: process.env.JWT_EXPIRES_IN || '7d'
        });
        const refreshToken = jwt.sign(
            { ...tokenPayload, type: 'refresh' },
            process.env.JWT_SECRET || 'fallback_secret',
            { expiresIn: '30d' }
        );
        
        // Store session
        const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();
        await dbRun(
            `INSERT INTO user_sessions (id, user_id, device_id, device_name, device_type, 
             access_token_hash, refresh_token_hash, expires_at) 
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
            [sessionId, userId, deviceId, deviceName, deviceType,
             await bcrypt.hash(accessToken, 5), await bcrypt.hash(refreshToken, 5), expiresAt]
        );
        
        res.status(201).json({
            success: true,
            message: 'User registered successfully',
            user: { id: userId, email, firstName, lastName },
            tokens: { accessToken, refreshToken, expiresIn: '7d' },
            sessionId
        });
        
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ success: false, error: 'Registration failed' });
    }
});

// Login
app.post('/api/auth/login', async (req, res) => {
    try {
        const schema = Joi.object({
            email: Joi.string().email().required(),
            password: Joi.string().required(),
            deviceId: Joi.string().required(),
            deviceName: Joi.string().required(),
            deviceType: Joi.string().valid('MOBILE', 'WEB', 'DESKTOP').required()
        });
        
        const { error, value } = schema.validate(req.body);
        if (error) {
            return res.status(400).json({ success: false, error: error.details[0].message });
        }
        
        const { email, password, deviceId, deviceName, deviceType } = value;
        
        // Find user
        const user = await dbGet('SELECT * FROM users WHERE email = ?', [email]);
        if (!user) {
            return res.status(401).json({ success: false, error: 'Invalid email or password' });
        }
        
        // Verify password (skip for OAuth users)
        if (user.password_hash !== 'google_oauth') {
            const isValid = await bcrypt.compare(password, user.password_hash);
            if (!isValid) {
                return res.status(401).json({ success: false, error: 'Invalid email or password' });
            }
        } else {
            return res.status(401).json({ success: false, error: 'Please use Google OAuth to login' });
        }
        
        // Generate tokens
        const sessionId = uuidv4();
        const tokenPayload = { userId: user.id, sessionId, email };
        const accessToken = jwt.sign(tokenPayload, process.env.JWT_SECRET || 'fallback_secret', {
            expiresIn: process.env.JWT_EXPIRES_IN || '7d'
        });
        const refreshToken = jwt.sign(
            { ...tokenPayload, type: 'refresh' },
            process.env.JWT_SECRET || 'fallback_secret',
            { expiresIn: '30d' }
        );
        
        // Store session
        const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();
        await dbRun(
            `INSERT INTO user_sessions (id, user_id, device_id, device_name, device_type, 
             access_token_hash, refresh_token_hash, expires_at) 
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
            [sessionId, user.id, deviceId, deviceName, deviceType,
             await bcrypt.hash(accessToken, 5), await bcrypt.hash(refreshToken, 5), expiresAt]
        );
        
        res.json({
            success: true,
            message: 'Login successful',
            user: {
                id: user.id,
                email: user.email,
                firstName: user.first_name,
                lastName: user.last_name
            },
            tokens: { accessToken, refreshToken, expiresIn: '7d' },
            sessionId
        });
        
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ success: false, error: 'Login failed' });
    }
});

// =============================================================================
// 📁 FILE UPLOAD ENDPOINTS
// =============================================================================

app.post('/api/upload', authMiddleware, upload.single('file'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ success: false, error: 'No file uploaded' });
        }
        
        const fileId = uuidv4();
        const { filename, originalname, path: filePath, size, mimetype } = req.file;
        
        await dbRun(
            `INSERT INTO files (id, user_id, filename, original_name, file_path, file_size, mime_type) 
             VALUES (?, ?, ?, ?, ?, ?, ?)`,
            [fileId, req.user.id, filename, originalname, filePath, size, mimetype]
        );
        
        res.json({
            success: true,
            message: 'File uploaded successfully',
            file: {
                id: fileId,
                filename,
                originalName: originalname,
                size,
                mimeType: mimetype,
                uploadedAt: new Date().toISOString()
            }
        });
        
    } catch (error) {
        console.error('Upload error:', error);
        res.status(500).json({ success: false, error: 'Upload failed' });
    }
});

// Get user files
app.get('/api/files', authMiddleware, async (req, res) => {
    try {
        const files = await dbAll('SELECT * FROM files WHERE user_id = ? ORDER BY uploaded_at DESC', [req.user.id]);
        
        res.json({
            success: true,
            files: files.map(file => ({
                id: file.id,
                filename: file.filename,
                originalName: file.original_name,
                size: file.file_size,
                mimeType: file.mime_type,
                uploadedAt: file.uploaded_at
            }))
        });
        
    } catch (error) {
        console.error('Get files error:', error);
        res.status(500).json({ success: false, error: 'Failed to fetch files' });
    }
});

// =============================================================================
// 🏥 HEALTH CHECK
// =============================================================================

app.get('/health', (req, res) => {
    res.json({
        status: 'healthy',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        environment: process.env.NODE_ENV || 'development'
    });
});

// =============================================================================
// 🚀 START SERVER
// =============================================================================

const PORT = process.env.PORT || 3000;

const startServer = async () => {
    try {
        await initDatabase();
        
        app.listen(PORT, () => {
            console.log(`🚀 Cloud Backup Server running on port ${PORT}`);
            console.log(`🔗 Health check: http://localhost:${PORT}/health`);
            console.log(`🔐 Google OAuth: http://localhost:${PORT}/auth/google`);
            console.log(`📋 Environment: ${process.env.NODE_ENV || 'development'}`);
        });
    } catch (error) {
        console.error('❌ Failed to start server:', error);
        process.exit(1);
    }
};

startServer();
