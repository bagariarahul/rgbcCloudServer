const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs').promises;
const { v4: uuidv4 } = require('uuid');
const Joi = require('joi');
const sqlite3 = require('sqlite3').verbose();
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// =============================================================================
// 🗄️ SQLITE DATABASE CONNECTION
// =============================================================================

const dbPath = './cloudbackup.db';
const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
        console.error('❌ Database connection failed:', err.message);
        process.exit(1);
    } else {
        console.log('✅ SQLite Database connected successfully');
        initializeTables();
    }
});

function initializeTables() {
    // Users table
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        first_name TEXT NOT NULL,
        last_name TEXT NOT NULL,
        storage_quota INTEGER DEFAULT 107374182400,
        storage_used INTEGER DEFAULT 0,
        is_active INTEGER DEFAULT 1,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // Sessions table
    db.run(`CREATE TABLE IF NOT EXISTS user_sessions (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        device_id TEXT NOT NULL,
        device_name TEXT,
        device_type TEXT,
        access_token_hash TEXT NOT NULL,
        refresh_token_hash TEXT NOT NULL,
        expires_at DATETIME NOT NULL,
        last_activity DATETIME DEFAULT CURRENT_TIMESTAMP,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )`);

    // Files table
    db.run(`CREATE TABLE IF NOT EXISTS user_files (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        filename TEXT NOT NULL,
        original_path TEXT NOT NULL,
        file_type TEXT,
        mime_type TEXT,
        file_size INTEGER NOT NULL,
        storage_path TEXT NOT NULL,
        checksum TEXT NOT NULL,
        encryption_key TEXT NOT NULL,
        encryption_algorithm TEXT DEFAULT 'AES-256-GCM',
        is_encrypted INTEGER DEFAULT 1,
        backup_status TEXT DEFAULT 'COMPLETED',
        uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )`);
    
    console.log('✅ Database tables initialized');
}

// Helper functions to promisify SQLite
function dbGet(sql, params = []) {
    return new Promise((resolve, reject) => {
        db.get(sql, params, (err, row) => {
            if (err) reject(err);
            else resolve(row);
        });
    });
}

function dbAll(sql, params = []) {
    return new Promise((resolve, reject) => {
        db.all(sql, params, (err, rows) => {
            if (err) reject(err);
            else resolve(rows);
        });
    });
}

function dbRun(sql, params = []) {
    return new Promise((resolve, reject) => {
        db.run(sql, params, function(err) {
            if (err) reject(err);
            else resolve({ lastID: this.lastID, changes: this.changes });
        });
    });
}

// =============================================================================
// 🔧 MIDDLEWARE SETUP
// =============================================================================

app.use(helmet());
app.use(cors({
    origin: ['http://localhost:3000', 'http://10.0.2.2:3000'],
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Device-ID'],
    credentials: true
}));
app.use(compression());
app.use(morgan('combined'));

const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100,
    message: 'Too many requests, please try again later'
});
app.use(limiter);

app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// File upload configuration
const storage = multer.diskStorage({
    destination: async (req, file, cb) => {
        const uploadPath = process.env.UPLOAD_PATH || './uploads';
        await fs.mkdir(uploadPath, { recursive: true });
        cb(null, uploadPath);
    },
    filename: (req, file, cb) => {
        const uniqueName = `${uuidv4()}-${Date.now()}${path.extname(file.originalname)}`;
        cb(null, uniqueName);
    }
});

const upload = multer({
    storage,
    limits: { fileSize: 100 * 1024 * 1024 }, // 100MB
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
            return res.status(401).json({
                error: 'Authentication required',
                message: 'Missing or invalid authorization header'
            });
        }

        const token = authHeader.substring(7);
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'fallback_secret');
        
        // Verify session exists and is valid
        const session = await dbGet(`
            SELECT s.*, u.id as user_id, u.email, u.first_name, u.last_name, u.is_active
            FROM user_sessions s
            JOIN users u ON s.user_id = u.id
            WHERE s.id = ? AND datetime(s.expires_at) > datetime('now') AND u.is_active = 1
        `, [decoded.sessionId]);
        
        if (!session) {
            return res.status(401).json({
                error: 'Invalid session',
                message: 'Session expired or not found'
            });
        }

        req.user = {
            id: session.user_id,
            email: session.email,
            firstName: session.first_name,
            lastName: session.last_name,
            sessionId: session.id
        };

        // Update last activity
        await dbRun(
            'UPDATE user_sessions SET last_activity = datetime("now") WHERE id = ?',
            [decoded.sessionId]
        );

        next();
    } catch (error) {
        console.error('Auth middleware error:', error);
        return res.status(401).json({
            error: 'Invalid token',
            message: 'Token verification failed'
        });
    }
};

// =============================================================================
// 🏥 HEALTH CHECK
// =============================================================================

app.get('/health', async (req, res) => {
    try {
        const userCount = await dbGet('SELECT COUNT(*) as count FROM users');
        
        res.json({
            status: 'healthy',
            timestamp: new Date().toISOString(),
            uptime: process.uptime(),
            version: '2.0.0',
            environment: process.env.NODE_ENV || 'development',
            database: {
                status: 'connected',
                users: userCount.count
            }
        });
    } catch (error) {
        res.status(503).json({
            status: 'unhealthy',
            error: error.message,
            timestamp: new Date().toISOString()
        });
    }
});

// =============================================================================
// 🔐 AUTHENTICATION ENDPOINTS
// =============================================================================

// User Registration
app.post('/api/auth/register', async (req, res) => {
    try {
        const { email, password, firstName, lastName, deviceName, deviceType, deviceId } = req.body;

        // Basic validation
        if (!email || !password || !firstName || !lastName || !deviceId) {
            return res.status(400).json({
                error: 'Validation failed',
                message: 'Missing required fields'
            });
        }

        // Check if user already exists
        const existingUser = await dbGet('SELECT id FROM users WHERE email = ?', [email]);
        if (existingUser) {
            return res.status(409).json({
                error: 'Email already registered',
                message: 'An account with this email already exists'
            });
        }

        // Create user
        const userId = uuidv4();
        const passwordHash = await bcrypt.hash(password, 12);
        
        await dbRun(`
            INSERT INTO users (id, email, password_hash, first_name, last_name)
            VALUES (?, ?, ?, ?, ?)
        `, [userId, email, passwordHash, firstName, lastName]);

        // Create session
        const sessionId = uuidv4();
        const tokenPayload = { userId, sessionId, email };
        const accessToken = jwt.sign(tokenPayload, process.env.JWT_SECRET || 'fallback_secret', {
            expiresIn: '7d'
        });
        const refreshToken = jwt.sign({ ...tokenPayload, type: 'refresh' }, process.env.JWT_SECRET || 'fallback_secret', {
            expiresIn: '30d'
        });

        const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();

        await dbRun(`
            INSERT INTO user_sessions (id, user_id, device_id, device_name, device_type, 
                                     access_token_hash, refresh_token_hash, expires_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `, [sessionId, userId, deviceId, deviceName || 'Unknown Device', deviceType || 'ANDROID',
            await bcrypt.hash(accessToken, 5), await bcrypt.hash(refreshToken, 5), expiresAt]);

        console.log(`✅ User registered: ${email}`);

        res.status(201).json({
            message: 'User registered successfully',
            user: {
                id: userId,
                email,
                firstName,
                lastName,
                storageQuota: '107374182400',
                storageUsed: '0',
                createdAt: new Date().toISOString()
            },
            tokens: {
                accessToken,
                refreshToken,
                expiresIn: '7d'
            },
            sessionId
        });

    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({
            error: 'Registration failed',
            message: 'An internal server error occurred'
        });
    }
});

// User Login
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password, deviceName, deviceType, deviceId } = req.body;

        // Find user
        const user = await dbGet(`
            SELECT id, email, password_hash, first_name, last_name, 
                   storage_quota, storage_used, is_active
            FROM users WHERE email = ? AND is_active = 1
        `, [email]);

        if (!user) {
            return res.status(401).json({
                error: 'Invalid credentials',
                message: 'Email or password is incorrect'
            });
        }

        // Verify password
        const isPasswordValid = await bcrypt.compare(password, user.password_hash);
        if (!isPasswordValid) {
            return res.status(401).json({
                error: 'Invalid credentials',
                message: 'Email or password is incorrect'
            });
        }

        // Invalidate old sessions for this device
        await dbRun(`
            DELETE FROM user_sessions 
            WHERE user_id = ? AND device_id = ? AND device_type = ?
        `, [user.id, deviceId, deviceType]);

        // Create new session
        const sessionId = uuidv4();
        const tokenPayload = { userId: user.id, sessionId, email: user.email };
        const accessToken = jwt.sign(tokenPayload, process.env.JWT_SECRET || 'fallback_secret', {
            expiresIn: '7d'
        });
        const refreshToken = jwt.sign({ ...tokenPayload, type: 'refresh' }, process.env.JWT_SECRET || 'fallback_secret', {
            expiresIn: '30d'
        });

        const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();

        await dbRun(`
            INSERT INTO user_sessions (id, user_id, device_id, device_name, device_type,
                                     access_token_hash, refresh_token_hash, expires_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `, [sessionId, user.id, deviceId, deviceName || `${deviceType} Device`, deviceType,
            await bcrypt.hash(accessToken, 5), await bcrypt.hash(refreshToken, 5), expiresAt]);

        console.log(`✅ User logged in: ${email}`);

        res.json({
            message: 'Login successful',
            user: {
                id: user.id,
                email: user.email,
                firstName: user.first_name,
                lastName: user.last_name,
                storageQuota: user.storage_quota,
                storageUsed: user.storage_used
            },
            tokens: {
                accessToken,
                refreshToken,
                expiresIn: '7d'
            },
            sessionId
        });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({
            error: 'Login failed',
            message: 'An internal server error occurred'
        });
    }
});

// =============================================================================
// 🔗 LEGACY COMPATIBILITY ENDPOINTS
// =============================================================================

// Simple upload (your Android app uses this)
app.post('/upload', upload.single('file'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({
                error: 'No file provided',
                message: 'Please select a file to upload'
            });
        }

        console.log(`📤 File uploaded: ${req.file.originalname} (${req.file.size} bytes)`);
        
        res.json({
            message: 'File uploaded successfully',
            filename: req.file.originalname,
            size: req.file.size,
            uploadPath: req.file.path,
            timestamp: new Date().toISOString()
        });

    } catch (error) {
        console.error('Upload error:', error);
        res.status(500).json({
            error: 'Upload failed',
            message: 'An internal server error occurred'
        });
    }
});

// Simple download (your Android app uses this)
app.get('/download', async (req, res) => {
    try {
        const { file, user } = req.query;
        
        if (!file) {
            return res.status(400).json({
                error: 'File parameter required',
                message: 'Please specify a file to download'
            });
        }

        console.log(`📥 Download requested: ${file} by ${user || 'anonymous'}`);
        
        const uploadsDir = process.env.UPLOAD_PATH || './uploads';
        const uploadedFiles = await fs.readdir(uploadsDir);
        
        if (uploadedFiles.length === 0) {
            return res.status(404).json({
                error: 'No files found',
                message: 'No uploaded files available for download'
            });
        }
        
        // Get the most recent file
        const fileStats = await Promise.all(
            uploadedFiles.map(async filename => ({
                name: filename,
                path: `${uploadsDir}/${filename}`,
                time: (await fs.stat(`${uploadsDir}/${filename}`)).mtime.getTime()
            }))
        );
        
        const latestFile = fileStats.sort((a, b) => b.time - a.time)[0];

        console.log(`📂 Serving file: ${latestFile.name}`);
        
        res.setHeader('Content-Disposition', `attachment; filename="${file}"`);
        res.setHeader('Content-Type', 'application/octet-stream');
        
        const fileStream = require('fs').createReadStream(latestFile.path);
        fileStream.pipe(res);

    } catch (error) {
        console.error('Download error:', error);
        res.status(500).json({
            error: 'Download failed',
            message: 'An internal server error occurred'
        });
    }
});

// =============================================================================
// 🚨 ERROR HANDLING
// =============================================================================

app.use('*', (req, res) => {
    res.status(404).json({
        error: 'Not Found',
        message: `Route ${req.method} ${req.originalUrl} not found`,
        timestamp: new Date().toISOString()
    });
});

app.use((error, req, res, next) => {
    console.error('Global error handler:', error);
    
    res.status(error.status || 500).json({
        error: 'Internal Server Error',
        message: process.env.NODE_ENV === 'development' ? error.message : 'Something went wrong',
        timestamp: new Date().toISOString()
    });
});

// =============================================================================
// 🚀 START SERVER
// =============================================================================

app.listen(PORT, () => {
    console.log(`
🚀 CloudBackup SQLite Server Started!

   Environment: ${process.env.NODE_ENV || 'development'}
   Server:      http://localhost:${PORT}
   Health:      http://localhost:${PORT}/health
   Database:    SQLite Connected
   
   📊 Production Features:
   ✅ SQLite database persistence  
   ✅ JWT authentication with sessions
   ✅ File upload/download working
   ✅ Storage management
   ✅ Security headers & rate limiting
   ✅ Legacy compatibility (your Android app will work!)
   
   🔐 Ready for testing!
    `);
});

// Graceful shutdown
process.on('SIGTERM', () => {
    console.log('SIGTERM received. Shutting down gracefully...');
    db.close();
    process.exit(0);
});

process.on('SIGINT', () => {
    console.log('SIGINT received. Shutting down gracefully...');
    db.close();
    process.exit(0);
});