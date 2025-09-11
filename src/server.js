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
const PGStore = require('connect-pg-simple')(session);

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
  }
};

logger.info('🚀 Starting Cloud Backup Server...');

// =============================================================================
// ⚙️ CONFIGURATION
// =============================================================================

const PORT = process.env.PORT || 3000;
const NODE_ENV = process.env.NODE_ENV || 'development';
const DATABASE_URL = process.env.DATABASE_URL; // Railway automatically provides this
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
// 🚀 EXPRESS APP & MIDDLEWARE SETUP
// =============================================================================

const app = express();

// CRITICAL: Trust proxy for Railway deployment
// Railway uses proxies, so we need to trust the X-Forwarded-For header
app.set('trust proxy', true);

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

// Rate limiting - UPDATED for Railway proxy
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: NODE_ENV === 'production' ? 200 : 1000,
  message: { success: false, error: 'Too many requests, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
  trustProxy: true, // Trust Railway's proxy
});

app.use('/api', limiter); // Only apply to API routes

// =============================================================================
// 🔐 SESSION & PASSPORT SETUP - UPDATED FOR PRODUCTION
// =============================================================================

let sessionStore;

if (DATABASE_URL && DATABASE_URL.startsWith('postgresql://')) {
  sessionStore = new PGStore({
    conString: DATABASE_URL,
    createTableIfMissing: true
  });
  logger.info('✅ Using PostgreSQL session store');
} else {
  sessionStore = new session.MemoryStore();
  logger.info('⚠️ Using memory session store (development only)');
}

app.use(session({
  store: sessionStore,
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  name: 'cloudbackup.sid',
  cookie: {
    secure: NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000,
    sameSite: 'lax'
  }
}));

app.use(passport.initialize());
app.use(passport.session());

// =============================================================================
// 🗄️ DATABASE SETUP & CONNECTION - RAILWAY OPTIMIZED
// =============================================================================

let pool;
let dbRun, dbGet, dbAll, closeDatabaseConnection;

if (DATABASE_URL && DATABASE_URL.startsWith('postgresql://')) {
  logger.info('🐘 Initializing PostgreSQL connection for Railway...');
  
  const { Pool } = require('pg');
  
  // Railway-specific configuration
  const isRailway = DATABASE_URL.includes('railway.app') || 
                   DATABASE_URL.includes('rlwy.net') || 
                   DATABASE_URL.includes('postgres.railway.app');
  
  let poolConfig = {
    connectionString: DATABASE_URL,
    // Reduced connection limits for Railway free tier
    max: 3,  // Maximum 3 connections
    min: 0,  // No minimum connections
    idleTimeoutMillis: 10000,  // 10 seconds
    connectionTimeoutMillis: 10000,  // 10 seconds timeout
    allowExitOnIdle: true
  };

  // CRITICAL: SSL configuration for Railway
  if (isRailway) {
    poolConfig.ssl = {
      rejectUnauthorized: false,
      sslmode: 'require'
    };
  }

  pool = new Pool(poolConfig);

  // Enhanced error handling
  pool.on('connect', (client) => {
    logger.info('✅ Database client connected successfully');
  });

  pool.on('error', (err, client) => {
    logger.error('❌ Database pool error', {
      error: err.message,
      code: err.code,
      errno: err.errno
    });
    // Don't exit immediately on connection errors
    // Railway databases can have temporary connection issues
  });

  // Convert SQLite placeholders to PostgreSQL format
  const convertPlaceholders = (query) => {
    let i = 0;
    return query.replace(/\?/g, () => `$${++i}`);
  };

  // FIXED: Robust database functions with better retry logic
  dbRun = async (query, params = [], retries = 2) => {  // Reduced retries
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
        
        if (attempt === retries) {
          // On final failure, check if it's a connection issue
          if (error.code === 'ECONNRESET' || error.message.includes('terminated unexpectedly')) {
            logger.warn('🔄 Database connection lost, this may be temporary on Railway');
          }
          throw error;
        }
        
        // Wait before retry (exponential backoff)
        await new Promise(resolve => setTimeout(resolve, 2000 * attempt));
      } finally {
        if (client) {
          try {
            client.release();
          } catch (releaseError) {
            logger.warn('Warning: Failed to release client', { error: releaseError.message });
          }
        }
      }
    }
  };

  dbGet = async (query, params = [], retries = 2) => {
    for (let attempt = 1; attempt <= retries; attempt++) {
      let client;
      try {
        client = await pool.connect();
        const result = await client.query(convertPlaceholders(query), params);
        return result.rows[0];
      } catch (error) {
        logger.error(`❌ Database get query failed (attempt ${attempt}/${retries})`, {
          error: error.message,
          code: error.code
        });
        
        if (attempt === retries) throw error;
        await new Promise(resolve => setTimeout(resolve, 2000 * attempt));
      } finally {
        if (client) {
          try {
            client.release();
          } catch (releaseError) {
            logger.warn('Warning: Failed to release client', { error: releaseError.message });
          }
        }
      }
    }
  };

  dbAll = async (query, params = [], retries = 2) => {
    for (let attempt = 1; attempt <= retries; attempt++) {
      let client;
      try {
        client = await pool.connect();
        const result = await client.query(convertPlaceholders(query), params);
        return result.rows;
      } catch (error) {
        logger.error(`❌ Database all query failed (attempt ${attempt}/${retries})`, {
          error: error.message,
          code: error.code
        });
        
        if (attempt === retries) throw error;
        await new Promise(resolve => setTimeout(resolve, 2000 * attempt));
      } finally {
        if (client) {
          try {
            client.release();
          } catch (releaseError) {
            logger.warn('Warning: Failed to release client', { error: releaseError.message });
          }
        }
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
// 🗄️ DATABASE INITIALIZATION - ENHANCED FOR RAILWAY
// =============================================================================

const initDatabase = async () => {
  try {
    logger.info('🔧 Starting database initialization...');
    
    // Test connection first with simpler query
    logger.info('🔧 Testing database connection...');
    
    try {
      const testResult = await dbGet('SELECT 1 as test');
      logger.info('✅ Database connection test successful', { result: testResult });
    } catch (testError) {
      logger.error('❌ Database connection test failed', {
        error: testError.message,
        code: testError.code
      });
      
      // For Railway, sometimes the first connection fails
      // Wait a bit and try once more
      logger.info('🔄 Retrying database connection in 3 seconds...');
      await new Promise(resolve => setTimeout(resolve, 3000));
      
      const retryResult = await dbGet('SELECT 1 as test');
      logger.info('✅ Database connection retry successful', { result: retryResult });
    }

    logger.info('🔧 Creating database tables...');

    // Create users table with Railway-compatible syntax
    const usersTable = `
      CREATE TABLE IF NOT EXISTS users (
        id VARCHAR(36) PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        first_name VARCHAR(100),
        last_name VARCHAR(100),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `;

    await dbRun(usersTable);
    logger.info('✅ Users table created/verified');

    // Create files table with Railway-compatible syntax
    const filesTable = `
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
    `;

    await dbRun(filesTable);
    logger.info('✅ Files table created/verified');

    // Add indexes for better performance
    try {
      await dbRun('CREATE INDEX IF NOT EXISTS idx_files_user_id ON files(user_id)');
      await dbRun('CREATE INDEX IF NOT EXISTS idx_files_uploaded_at ON files(uploaded_at)');
      logger.info('✅ Database indexes created/verified');
    } catch (indexError) {
      logger.warn('⚠️ Some indexes may already exist', { error: indexError.message });
    }

    // Verify tables exist with a simple count
    try {
      const userCount = await dbGet('SELECT COUNT(*) as count FROM users');
      const fileCount = await dbGet('SELECT COUNT(*) as count FROM files');
      
      logger.info('🎉 Database initialization completed successfully', {
        usersTable: `${userCount?.count || 0} users`,
        filesTable: `${fileCount?.count || 0} files`
      });
    } catch (countError) {
      logger.warn('⚠️ Could not verify table counts, but tables should exist', {
        error: countError.message
      });
    }

  } catch (error) {
    logger.error('💥 Database initialization failed', {
      error: error.message,
      code: error.code,
      stack: NODE_ENV === 'development' ? error.stack : undefined
    });
    
    // For Railway, don't immediately exit - the database might be starting up
    if (error.message.includes('terminated unexpectedly') || 
        error.message.includes('ECONNRESET')) {
      logger.warn('🔄 Database connection issue detected - Railway database may be starting up');
      logger.warn('🔄 App will continue to start, health check will verify database later');
      
      // Don't throw error, let the app start and health check will catch issues
      return;
    }
    
    throw error;
  }
};

// =============================================================================
// 🔐 PASSPORT SETUP
// =============================================================================

// Google OAuth Strategy
if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET) {
  passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: process.env.GOOGLE_CALLBACK_URL || (NODE_ENV === 'production' ?
      `${process.env.RAILWAY_PUBLIC_DOMAIN || process.env.BASE_URL}/auth/google/callback` :
      '/auth/google/callback')
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

// ENHANCED Health check for Railway
app.get('/health', asyncHandler(async (req, res) => {
  try {
    // Set a reasonable timeout for the database query
    const dbQuery = dbGet('SELECT 1 as test');
    const timeout = new Promise((resolve, reject) => {
      setTimeout(() => reject(new Error('Database timeout')), 3000); // Reduced to 3 seconds
    });

    const dbResult = await Promise.race([dbQuery, timeout]);
    
    // Additional health metrics
    const uptime = Math.floor(process.uptime());
    const memory = process.memoryUsage();
    const memoryUsageMB = Math.round(memory.heapUsed / 1024 / 1024);
    
    res.status(200).json({
      status: 'healthy',
      timestamp: new Date().toISOString(),
      environment: NODE_ENV,
      uptime: uptime,
      uptimeFormatted: `${Math.floor(uptime / 60)}m ${uptime % 60}s`,
      database: 'connected',
      memory: {
        used: `${memoryUsageMB}MB`,
        total: `${Math.round(memory.heapTotal / 1024 / 1024)}MB`
      },
      version: '1.0.0'
    });
  } catch (error) {
    logger.error('❌ Health check failed', { 
      error: error.message,
      code: error.code 
    });
    
    // Still return 200 if it's just a database timeout on Railway
    // This prevents Railway from constantly restarting the service
    const isDbTimeout = error.message.includes('timeout') || 
                       error.message.includes('terminated unexpectedly');
    
    if (isDbTimeout) {
      res.status(200).json({
        status: 'degraded',
        error: 'Database temporarily unavailable',
        timestamp: new Date().toISOString(),
        database: 'disconnected',
        uptime: Math.floor(process.uptime()),
        note: 'Service is running, database connection will be retried'
      });
    } else {
      res.status(500).json({
        status: 'unhealthy',
        error: 'Health check failed: ' + error.message,
        timestamp: new Date().toISOString(),
        database: 'error'
      });
    }
  }
}));

// Root endpoint
app.get('/', (req, res) => {
  res.json({
    message: 'Cloud Backup Server is running!',
    version: '1.0.0',
    environment: NODE_ENV,
    endpoints: {
      health: '/health',
      auth: {
        register: 'POST /api/register',
        login: 'POST /api/login',
        authRegister: 'POST /api/auth/register',
        authLogin: 'POST /api/auth/login',
        googleOAuth: process.env.GOOGLE_CLIENT_ID ? '/auth/google' : 'Not configured'
      },
      files: {
        upload: 'POST /api/upload',
        list: 'GET /api/files',
        download: 'GET /api/files/:id/download'
      }
    }
  });
});

// =============================================================================
// 🔗 AUTHENTICATION ROUTES (Both /api and /api/auth for compatibility)
// =============================================================================

// Original routes
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

// Android app compatibility routes (/api/auth/*)
app.post('/api/auth/register', asyncHandler(async (req, res) => {
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

  logger.info('👤 User registered successfully via /auth/register', { userId, email });

  res.status(201).json({
    success: true,
    message: 'User registered successfully',
    user: { id: userId, email }
  });
}));

app.post('/api/auth/login', asyncHandler(async (req, res) => {
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

  logger.info('🔐 User logged in successfully via /auth/login', { userId: user.id, email });

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

// Additional auth endpoints for compatibility
app.post('/api/auth/logout', asyncHandler(async (req, res) => {
  // For JWT tokens, logout is typically handled client-side
  // But we can provide this endpoint for compatibility
  res.status(200).json({
    success: true,
    message: 'Logout successful'
  });
}));

app.get('/api/auth/me', authMiddleware, asyncHandler(async (req, res) => {
  const user = await dbGet('SELECT id, email, first_name, last_name FROM users WHERE id = ?', [req.user.id]);
  
  if (!user) {
    return res.status(404).json({ success: false, error: 'User not found' });
  }

  res.status(200).json({
    success: true,
    user: {
      id: user.id,
      email: user.email,
      firstName: user.first_name,
      lastName: user.last_name
    }
  });
}));

// =============================================================================
// 📁 FILE ROUTES
// =============================================================================

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
// 🔍 ADDITIONAL ENDPOINTS
// =============================================================================

// Metrics endpoint for monitoring
app.get('/metrics', asyncHandler(async (req, res) => {
  try {
    const dbStatus = await dbGet('SELECT 1 as status');
    const fileCount = await dbGet('SELECT COUNT(*) as count FROM files');
    const userCount = await dbGet('SELECT COUNT(*) as count FROM users');

    res.status(200).json({
      status: 'ok',
      metrics: {
        database: dbStatus ? 'connected' : 'disconnected',
        files: fileCount?.count || 0,
        users: userCount?.count || 0,
        uptime: process.uptime(),
        memory: process.memoryUsage()
      }
    });
  } catch (error) {
    res.status(500).json({
      status: 'error',
      error: 'Metrics unavailable',
      timestamp: new Date().toISOString()
    });
  }
}));

// Status endpoint
app.get('/status', asyncHandler(async (req, res) => {
  try {
    const dbStatus = await dbGet('SELECT 1 as status');
    res.status(200).json({
      status: 'ok',
      services: {
        database: dbStatus ? 'connected' : 'disconnected',
        storage: fs.existsSync(UPLOADS_DIR) ? 'available' : 'unavailable'
      },
      timestamp: new Date().toISOString(),
      uptime: process.uptime()
    });
  } catch (error) {
    res.status(500).json({
      status: 'error',
      error: 'Service unavailable',
      timestamp: new Date().toISOString()
    });
  }
}));

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

      // Redirect to frontend with token
      if (process.env.FRONTEND_URL) {
        res.redirect(`${process.env.FRONTEND_URL}/auth/success?token=${token}`);
      } else {
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
      }
    })
  );

  app.get('/auth/google/error', (req, res) => {
    logger.warn('⚠️ Google OAuth authentication failed');
    if (process.env.FRONTEND_URL) {
      res.redirect(`${process.env.FRONTEND_URL}/auth/error`);
    } else {
      res.status(401).json({ success: false, error: 'Google OAuth authentication failed' });
    }
  });
}

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
          health: `/health`,
          root: `/`
        }
      });
    });

    // Add keep-alive handling for Railway
    server.keepAliveTimeout = 65000;
    server.headersTimeout = 66000;

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

  // Close HTTP server first
  if (server) {
    server.close(async (err) => {
      if (err) {
        logger.error('❌ Error closing HTTP server', { error: err.message });
      }

      // Close database connection
      await closeDatabaseConnection();
      logger.info('👋 Graceful shutdown completed');
      process.exit(0);
    });

    // Force close after 30 seconds
    setTimeout(() => {
      logger.error('⏰ Forced shutdown due to timeout');
      process.exit(1);
    }, 30000);
  } else {
    await closeDatabaseConnection();
    process.exit(0);
  }
};

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

process.on('unhandledRejection', (reason, promise) => {
  logger.error('💥 Unhandled Promise Rejection', {
    reason: reason?.stack || reason
  });
  // Don't call gracefulShutdown here as it might cause infinite loops
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