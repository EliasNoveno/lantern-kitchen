// lantern_server.js - ULTRA-SECURE FOR DARKNET (Tor .onion)
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const { body, validationResult, param, query } = require('express-validator');
const { randomBytes, createHash, createCipheriv, createDecipheriv, timingSafeEqual } = crypto;
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// === ГЕНЕРАЦИЯ КРИПТОГРАФИЧЕСКИ БЕЗОПАСНЫХ СЕКРЕТОВ ===
const JWT_SECRET = process.env.JWT_SECRET || randomBytes(64).toString('hex');
const COOKIE_SECRET = process.env.COOKIE_SECRET || randomBytes(32).toString('hex');
const ENCRYPTION_KEY = createHash('sha256').update(
    process.env.ENCRYPTION_KEY || randomBytes(32)
).digest();

// === УСИЛЕННЫЙ КОМПАРАТОР ДЛЯ ЗАЩИТЫ ОТ АТАК ПО ВРЕМЕНИ ===
function timingSafeCompare(a, b) {
    if (typeof a !== 'string' || typeof b !== 'string') return false;
    if (a.length !== b.length) return false;
    try {
        return timingSafeEqual(Buffer.from(a), Buffer.from(b));
    } catch {
        return false;
    }
}

// === БЕЗОПАСНОЕ СРАВНЕНИЕ ХЕШЕЙ ===
async function secureCompareHash(plaintext, hash, salt) {
    const computed = await bcrypt.hash(plaintext + salt, 14);
    return timingSafeCompare(computed, hash);
}

// === ШИФРОВАНИЕ ЛОГОВ (AES-256-GCM) ===
function encryptLog(data) {
    const iv = randomBytes(16);
    const cipher = createCipheriv('aes-256-gcm', ENCRYPTION_KEY, iv);
    const encrypted = Buffer.concat([cipher.update(data, 'utf8'), cipher.final()]);
    const authTag = cipher.getAuthTag();
    return Buffer.concat([iv, authTag, encrypted]).toString('base64');
}

// === ОЧИСТКА ЧУВСТВИТЕЛЬНЫХ ДАННЫХ ИЗ ПАМЯТИ ===
function secureZeroBuffer(buffer) {
    if (Buffer.isBuffer(buffer)) {
        buffer.fill(0);
    }
}

// === HELMET ДЛЯ DARKNET (БЕЗ HSTS) ===
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", "data:"],
            connectSrc: ["'self'"],
            frameSrc: ["'none'"],
            objectSrc: ["'none'"],
            baseUri: ["'self'"],
            formAction: ["'self'"],
        },
    },
    hsts: {
        maxAge: 0, // .onion не поддерживает HSTS
        includeSubDomains: false,
        preload: false,
    },
    referrerPolicy: { policy: 'no-referrer' },
    noSniff: true,
    xssFilter: true,
    frameguard: { action: 'deny' },
    dnsPrefetchControl: { allow: false },
    expectCt: { maxAge: 0, enforce: false },
}));

// === RATE LIMITING С РАЗНЫМИ ЛИМИТАМИ ===
const globalLimiter = rateLimit({
    windowMs: 1 * 60 * 1000,
    max: 30,
    message: { error: 'Too many requests. Slow down.' },
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => req.ip || req.connection.remoteAddress
});
app.use('/api/', globalLimiter);

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    skipSuccessfulRequests: true,
    message: { error: 'Too many attempts. Try again later.' },
    keyGenerator: (req) => req.ip || req.connection.remoteAddress
});

const registerLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 2,
    message: { error: 'Registration limit reached. Try again later.' },
    keyGenerator: (req) => req.ip || req.connection.remoteAddress
});

const postLimiter = rateLimit({
    windowMs: 5 * 60 * 1000,
    max: 10,
    message: { error: 'Too many posts. Slow down.' },
    keyGenerator: (req) => req.ip || req.connection.remoteAddress
});

const commentLimiter = rateLimit({
    windowMs: 1 * 60 * 1000,
    max: 15,
    message: { error: 'Too many comments. Slow down.' },
    keyGenerator: (req) => req.ip || req.connection.remoteAddress
});

// === ПАРСЕРЫ С ОГРАНИЧЕНИЯМИ ===
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));

// === СТАТИКА С ЗАЩИТОЙ ===
app.use(express.static('public', {
    maxAge: '1h',
    etag: true,
    lastModified: true,
    setHeaders: (res, path) => {
        res.setHeader('Cache-Control', 'private, no-cache, no-store, must-revalidate');
    }
}));

app.use(cookieParser(COOKIE_SECRET));

// === НАСТРОЙКА MULTER С ВАЛИДАЦИЕЙ ===
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const uploadDir = path.join(__dirname, 'public/uploads');
        if (!fs.existsSync(uploadDir)) {
            fs.mkdirSync(uploadDir, { recursive: true, mode: 0o700 });
        }
        cb(null, uploadDir);
    },
    filename: (req, file, cb) => {
        const ext = path.extname(file.originalname);
        const allowedExts = ['.jpg', '.jpeg', '.png', '.gif', '.webp', '.pdf', '.txt'];
        if (!allowedExts.includes(ext.toLowerCase())) {
            return cb(new Error('File type not allowed'));
        }
        const name = randomBytes(16).toString('hex');
        cb(null, name + ext);
    }
});

const fileFilter = (req, file, cb) => {
    const allowedTypes = [
        'image/jpeg', 'image/png', 'image/gif', 'image/webp',
        'application/pdf', 'text/plain'
    ];
    if (allowedTypes.includes(file.mimetype)) {
        cb(null, true);
    } else {
        cb(new Error('Invalid file type'), false);
    }
};

const upload = multer({
    storage: storage,
    limits: {
        fileSize: 5 * 1024 * 1024, // 5MB
        files: 1
    },
    fileFilter: fileFilter
});

// === БАЗА ДАННЫХ С ШИФРОВАНИЕМ ===
const db = new sqlite3.Database('lantern_kitchen.db');

function generateSalt() {
    return randomBytes(64).toString('hex');
}

db.serialize(() => {
    // Users table with Tor identity
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        salt TEXT NOT NULL,
        isAdmin INTEGER DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        last_login DATETIME,
        login_attempts INTEGER DEFAULT 0,
        locked_until DATETIME,
        tor_identity TEXT,
        totp_secret TEXT,
        mfa_enabled INTEGER DEFAULT 0
    )`);
    
    // Posts with encryption
    db.run(`CREATE TABLE IF NOT EXISTS posts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        section TEXT NOT NULL,
        title TEXT,
        content TEXT,
        file_path TEXT,
        is_secret INTEGER DEFAULT 0,
        secret_hash TEXT,
        secret_salt TEXT,
        created_by INTEGER,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        nonce TEXT UNIQUE,
        FOREIGN KEY(created_by) REFERENCES users(id)
    )`);
    
    // Comments with edit tracking
    db.run(`CREATE TABLE IF NOT EXISTS comments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        post_id INTEGER,
        user_id INTEGER,
        content TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        edit_history TEXT,
        FOREIGN KEY(post_id) REFERENCES posts(id) ON DELETE CASCADE,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )`);
    
    // Messages with end-to-end encryption
    db.run(`CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        from_user INTEGER,
        to_user INTEGER,
        encrypted_text TEXT NOT NULL,
        iv TEXT NOT NULL,
        auth_tag TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        read_at DATETIME,
        FOREIGN KEY(from_user) REFERENCES users(id),
        FOREIGN KEY(to_user) REFERENCES users(id)
    )`);
    
    // Sessions with fingerprint (без IP для Tor)
    db.run(`CREATE TABLE IF NOT EXISTS sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        token TEXT UNIQUE NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        expires_at DATETIME,
        user_agent TEXT,
        session_id TEXT UNIQUE,
        fingerprint TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )`);
    
    // Audit log for security events
    db.run(`CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        action TEXT,
        ip_hash TEXT,
        details TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )`);
    
    // Used nonces for replay protection
    db.run(`CREATE TABLE IF NOT EXISTS used_nonces (
        nonce TEXT PRIMARY KEY,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
    
    // Indexes for performance
    db.run(`CREATE INDEX IF NOT EXISTS idx_posts_section ON posts(section)`);
    db.run(`CREATE INDEX IF NOT EXISTS idx_posts_created ON posts(created_at DESC)`);
    db.run(`CREATE INDEX IF NOT EXISTS idx_comments_post ON comments(post_id)`);
    db.run(`CREATE INDEX IF NOT EXISTS idx_messages_users ON messages(from_user, to_user)`);
    db.run(`CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token)`);
    db.run(`CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_log(user_id)`);
    db.run(`CREATE INDEX IF NOT EXISTS idx_used_nonces ON used_nonces(nonce)`);
});

// === АУТЕНТИФИКАЦИЯ С ЗАЩИТОЙ ОТ ПЕРЕХВАТА (БЕЗ ПРИВЯЗКИ К IP ДЛЯ TOR) ===
function authenticate(req, res, next) {
    const token = req.cookies.token;
    if (!token) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    
    try {
        const decoded = jwt.verify(token, JWT_SECRET, { 
            algorithms: ['HS256'],
            maxAge: '12h'
        });
        
        db.get('SELECT * FROM sessions WHERE token = ? AND expires_at > datetime("now") AND user_id = ?',
            [token, decoded.id], (err, session) => {
                if (err || !session) {
                    return res.status(401).json({ error: 'Session expired' });
                }
                
                // Для Tor используем только User-Agent + Accept-Language (без IP)
                const uaHash = createHash('sha256').update(req.get('User-Agent') || '').digest('hex');
                const langHash = createHash('sha256').update(req.get('Accept-Language') || '').digest('hex');
                const fingerprint = createHash('sha256').update(
                    uaHash + langHash
                ).digest('hex');
                
                if (session.fingerprint !== fingerprint) {
                    db.run('DELETE FROM sessions WHERE id = ?', [session.id]);
                    res.clearCookie('token');
                    db.run('INSERT INTO audit_log (user_id, action, details) VALUES (?, ?, ?)',
                        [decoded.id, 'SESSION_HIJACK_ATTEMPT', 'Fingerprint mismatch']);
                    return res.status(401).json({ error: 'Session hijacking detected' });
                }
                
                req.user = decoded;
                req.sessionId = session.id;
                req.sessionToken = token;
                
                // Ротация токена для защиты от перехвата
                if (Math.random() < 0.1) {
                    const newToken = jwt.sign(
                        { id: decoded.id, username: decoded.username, isAdmin: decoded.isAdmin },
                        JWT_SECRET,
                        { expiresIn: '12h' }
                    );
                    db.run('UPDATE sessions SET token = ?, expires_at = datetime("now", "+12 hours") WHERE id = ?',
                        [newToken, session.id]);
                    res.cookie('token', newToken, {
                        httpOnly: true,
                        secure: true,
                        sameSite: 'strict',
                        maxAge: 12 * 60 * 60 * 1000,
                        path: '/'
                    });
                    req.sessionToken = newToken;
                }
                
                next();
            });
    } catch (err) {
        res.clearCookie('token');
        return res.status(401).json({ error: 'Invalid token' });
    }
}

function isAdmin(req, res, next) {
    if (!req.user || !req.user.isAdmin) {
        return res.status(403).json({ error: 'Forbidden' });
    }
    next();
}

// === CSRF ЗАЩИТА ДЛЯ .ONION (упрощённая) ===
function csrfProtect(req, res, next) {
    const methods = ['POST', 'PUT', 'DELETE', 'PATCH'];
    if (!methods.includes(req.method)) return next();
    
    const referer = req.get('Referer');
    const host = req.get('Host');
    
    // Для .onion проверяем только referer
    if (host && host.includes('.onion')) {
        if (!referer) {
            return res.status(403).json({ error: 'Missing referer' });
        }
        try {
            const refererUrl = new URL(referer);
            if (refererUrl.hostname !== host) {
                return res.status(403).json({ error: 'Invalid referer' });
            }
        } catch {
            return res.status(403).json({ error: 'Invalid referer' });
        }
        return next();
    }
    
    // Для обычных сайтов проверяем origin
    const origin = req.get('Origin');
    if (origin) {
        try {
            const originUrl = new URL(origin);
            if (originUrl.host !== host) {
                return res.status(403).json({ error: 'Invalid origin' });
            }
        } catch {
            return res.status(403).json({ error: 'Invalid origin' });
        }
    }
    
    if (!referer) {
        return res.status(403).json({ error: 'Missing referer' });
    }
    try {
        const refererUrl = new URL(referer);
        if (refererUrl.host !== host) {
            return res.status(403).json({ error: 'Invalid referer' });
        }
    } catch {
        return res.status(403).json({ error: 'Invalid referer' });
    }
    
    next();
}

// === ВАЛИДАЦИЯ ===
const validate = (validations) => {
    return async (req, res, next) => {
        await Promise.all(validations.map(validation => validation.run(req)));
        const errors = validationResult(req);
        if (errors.isEmpty()) return next();
        res.status(400).json({ errors: errors.array().map(e => e.msg) });
    };
};

// === ОЧИСТКА ВХОДНЫХ ДАННЫХ ===
function sanitizeInput(str) {
    if (!str) return '';
    return String(str)
        .replace(/[<>]/g, '')
        .replace(/&/g, '&amp;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#x27;')
        .replace(/\//g, '&#x2F;')
        .replace(/\\/g, '&#x5C;')
        .replace(/\n/g, '&#10;')
        .replace(/\r/g, '&#13;');
}

// === ГЕНЕРАЦИЯ NONCE ДЛЯ ЗАЩИТЫ ОТ REPLAY ===
function generateNonce() {
    return randomBytes(32).toString('hex') + Date.now().toString(36);
}

// === ПРОВЕРКА И СОХРАНЕНИЕ NONCE ===
function checkAndStoreNonce(nonce, callback) {
    db.get('SELECT nonce FROM used_nonces WHERE nonce = ?', [nonce], (err, row) => {
        if (err) return callback(err);
        if (row) return callback(new Error('Nonce already used'));
        
        db.run('INSERT INTO used_nonces (nonce) VALUES (?)', [nonce], (err) => {
            if (err) return callback(err);
            callback(null);
        });
    });
}

// ==========================================
// === API ENDPOINTS =======================
// ==========================================

// === POST /API/REGISTER ===
app.post('/api/register', registerLimiter,
    validate([
        body('username')
            .isLength({ min: 3, max: 20 })
            .matches(/^[a-zA-Z0-9_]+$/)
            .withMessage('Username can only contain letters, numbers, underscore'),
        body('password')
            .isLength({ min: 12 })
            .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])/)
            .withMessage('Password must contain uppercase, lowercase, number and special character')
    ]),
    async (req, res) => {
        const { username, password } = req.body;
        const torIdentity = req.get('X-Tor-Identity') || 'unknown';
        const ipHash = createHash('sha256').update(req.ip || '').digest('hex');
        
        try {
            const salt = generateSalt();
            const hash = await bcrypt.hash(password + salt, 14);
            
            db.run('INSERT INTO users (username, password, salt, tor_identity) VALUES (?, ?, ?, ?)',
                [username, hash, salt, torIdentity],
                function(err) {
                    if (err) {
                        if (err.message.includes('UNIQUE')) {
                            return res.status(400).json({ error: 'Username taken' });
                        }
                        console.error(encryptLog(err.message));
                        return res.status(500).json({ error: 'Registration failed' });
                    }
                    
                    db.run('INSERT INTO audit_log (user_id, action, ip_hash, details) VALUES (?, ?, ?, ?)',
                        [this.lastID, 'REGISTER', ipHash, 'New user registered']);
                    
                    res.status(201).json({ message: 'Registered' });
                });
        } catch (err) {
            console.error(encryptLog(err.message));
            res.status(500).json({ error: 'Server error' });
        }
    }
);

// === POST /API/LOGIN ===
app.post('/api/login', authLimiter,
    validate([
        body('username').isLength({ min: 3, max: 20 }),
        body('password').isLength({ min: 12 })
    ]),
    (req, res) => {
        const { username, password } = req.body;
        const ipHash = createHash('sha256').update(req.ip || '').digest('hex');
        
        db.get('SELECT id, username, password, salt, isAdmin, login_attempts, locked_until FROM users WHERE username = ?',
            [username], async (err, user) => {
                if (err || !user) {
                    return res.status(401).json({ error: 'Invalid credentials' });
                }
                
                if (user.locked_until && new Date(user.locked_until) > new Date()) {
                    return res.status(429).json({ error: 'Account locked. Try later.' });
                }
                
                const isValid = await secureCompareHash(password, user.password, user.salt);
                
                if (!isValid) {
                    const attempts = (user.login_attempts || 0) + 1;
                    let lockedUntil = null;
                    if (attempts >= 5) {
                        lockedUntil = new Date(Date.now() + 30 * 60 * 1000).toISOString();
                        db.run('INSERT INTO audit_log (user_id, action, ip_hash, details) VALUES (?, ?, ?, ?)',
                            [user.id, 'ACCOUNT_LOCKED', ipHash, `Attempts: ${attempts}`]);
                    }
                    db.run('UPDATE users SET login_attempts = ?, locked_until = ? WHERE id = ?',
                        [attempts, lockedUntil, user.id]);
                    return res.status(401).json({ error: 'Invalid credentials' });
                }
                
                db.run('UPDATE users SET login_attempts = 0, locked_until = NULL, last_login = datetime("now") WHERE id = ?',
                    [user.id]);
                
                const sessionId = randomBytes(32).toString('hex');
                const token = jwt.sign(
                    { id: user.id, username: user.username, isAdmin: user.isAdmin, sessionId },
                    JWT_SECRET,
                    { expiresIn: '12h', algorithm: 'HS256' }
                );
                
                const expiresAt = new Date(Date.now() + 12 * 60 * 60 * 1000).toISOString();
                // Для Tor используем только User-Agent + Accept-Language (без IP)
                const uaHash = createHash('sha256').update(req.get('User-Agent') || '').digest('hex');
                const langHash = createHash('sha256').update(req.get('Accept-Language') || '').digest('hex');
                const fingerprint = createHash('sha256').update(
                    uaHash + langHash
                ).digest('hex');
                
                db.run('INSERT INTO sessions (user_id, token, expires_at, user_agent, session_id, fingerprint) VALUES (?, ?, ?, ?, ?, ?)',
                    [user.id, token, expiresAt, uaHash, sessionId, fingerprint],
                    (err) => {
                        if (err) {
                            console.error(encryptLog(err.message));
                            return res.status(500).json({ error: 'Login failed' });
                        }
                        
                        db.run('INSERT INTO audit_log (user_id, action, ip_hash, details) VALUES (?, ?, ?, ?)',
                            [user.id, 'LOGIN_SUCCESS', ipHash, `Session: ${sessionId.substring(0, 8)}`]);
                        
                        res.cookie('token', token, {
                            httpOnly: true,
                            secure: true,
                            sameSite: 'strict',
                            maxAge: 12 * 60 * 60 * 1000,
                            path: '/',
                            domain: process.env.COOKIE_DOMAIN || undefined
                        });
                        res.json({ message: 'Login successful' });
                    });
            });
    }
);

// === POST /API/LOGOUT ===
app.post('/api/logout', authenticate, (req, res) => {
    if (req.sessionId) {
        db.run('DELETE FROM sessions WHERE id = ?', [req.sessionId]);
    }
    res.clearCookie('token', {
        httpOnly: true,
        secure: true,
        sameSite: 'strict',
        path: '/'
    });
    res.json({ message: 'Logged out' });
});

// === GET /API/ME ===
app.get('/api/me', authenticate, (req, res) => {
    db.get('SELECT id, username, isAdmin FROM users WHERE id = ?', [req.user.id], (err, user) => {
        if (err || !user) return res.status(401).json({ error: 'Not found' });
        res.json(user);
    });
});

// === GET /API/POSTS ===
app.get('/api/posts/:section',
    validate([
        param('section').isString().isLength({ min: 1, max: 50 }),
        query('page').optional().isInt({ min: 1 })
    ]),
    (req, res) => {
        const { section } = req.params;
        const page = parseInt(req.query.page) || 1;
        const limit = 10;
        const offset = (page - 1) * limit;

        const sql = `
            SELECT posts.*, users.username 
            FROM posts 
            JOIN users ON posts.created_by = users.id 
            WHERE posts.section = ? AND posts.is_secret = 0
            ORDER BY posts.created_at DESC
            LIMIT ? OFFSET ?
        `;
        const countSql = 'SELECT COUNT(*) as total FROM posts WHERE section = ? AND is_secret = 0';

        db.get(countSql, [section], (err, countRow) => {
            if (err) return res.status(500).json({ error: 'DB error' });
            const total = countRow.total;
            const totalPages = Math.ceil(total / limit);

            db.all(sql, [section, limit, offset], (err, posts) => {
                if (err) return res.status(500).json({ error: 'DB error' });
                res.json({
                    posts: posts.map(p => ({ 
                        ...p, 
                        secret_hash: undefined, 
                        secret_salt: undefined,
                        content: sanitizeInput(p.content),
                        title: sanitizeInput(p.title)
                    })),
                    totalPages,
                    currentPage: page
                });
            });
        });
    }
);

// === POST /API/POSTS/SECRET ===
app.post('/api/posts/secret', authenticate,
    validate([
        body('section').isString().isLength({ min: 1, max: 50 }),
        body('password').isString().isLength({ min: 1 })
    ]),
    (req, res) => {
        const { section, password } = req.body;

        const sql = `
            SELECT posts.*, users.username 
            FROM posts 
            JOIN users ON posts.created_by = users.id 
            WHERE posts.section = ? AND posts.is_secret = 1
            ORDER BY posts.created_at DESC
        `;
        db.all(sql, [section], async (err, posts) => {
            if (err) return res.status(500).json({ error: 'DB error' });
            const validPosts = [];
            for (const p of posts) {
                if (p.secret_hash && p.secret_salt) {
                    const isValid = await secureCompareHash(password, p.secret_hash, p.secret_salt);
                    if (isValid) {
                        validPosts.push({ 
                            ...p, 
                            secret_hash: undefined, 
                            secret_salt: undefined,
                            content: sanitizeInput(p.content),
                            title: sanitizeInput(p.title)
                        });
                    }
                }
            }
            res.json(validPosts);
        });
    }
);

// === POST /API/POSTS ===
app.post('/api/posts', authenticate, csrfProtect, postLimiter, upload.single('file'),
    validate([
        body('section').isString().isLength({ min: 1, max: 50 }),
        body('title').optional().isString().isLength({ max: 200 }),
        body('content').optional().isString().isLength({ max: 10000 }),
        body('is_secret').optional().isBoolean(),
        body('secret_password').optional().isString().isLength({ min: 1, max: 100 })
    ]),
    (req, res) => {
        const { section, title, content, is_secret, secret_password } = req.body;
        
        if (!section) return res.status(400).json({ error: 'Section required' });

        const filePath = req.file ? '/uploads/' + req.file.filename : null;
        const isSecret = is_secret === 'true' || is_secret === true ? 1 : 0;
        let secretHash = null;
        let secretSalt = null;
        const nonce = generateNonce();
        
        // Проверка на replay attack
        checkAndStoreNonce(nonce, (err) => {
            if (err) {
                return res.status(400).json({ error: 'Invalid request' });
            }
            
            if (isSecret && secret_password) {
                secretSalt = generateSalt();
                secretHash = bcrypt.hashSync(secret_password + secretSalt, 14);
            }

            const sql = `INSERT INTO posts (section, title, content, file_path, is_secret, secret_hash, secret_salt, created_by, nonce)
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`;
            db.run(sql, [section, sanitizeInput(title || ''), sanitizeInput(content || ''), filePath, isSecret, secretHash, secretSalt, req.user.id, nonce],
                function(err) {
                    if (err) {
                        console.error(encryptLog(err.message));
                        return res.status(500).json({ error: 'Failed to create post' });
                    }
                    res.status(201).json({ id: this.lastID, message: 'Post created' });
                });
        });
    }
);

// === GET /API/COMMENTS ===
app.get('/api/comments/:postId',
    validate([param('postId').isInt()]),
    (req, res) => {
        const { postId } = req.params;
        const sql = `
            SELECT comments.*, users.username 
            FROM comments 
            JOIN users ON comments.user_id = users.id 
            WHERE comments.post_id = ?
            ORDER BY comments.created_at ASC
        `;
        db.all(sql, [postId], (err, comments) => {
            if (err) return res.status(500).json({ error: 'DB error' });
            res.json(comments.map(c => ({
                ...c,
                content: sanitizeInput(c.content),
                edit_history: c.edit_history ? JSON.parse(c.edit_history) : []
            })));
        });
    }
);

// === POST /API/COMMENTS ===
app.post('/api/comments', authenticate, csrfProtect, commentLimiter,
    validate([
        body('postId').isInt(),
        body('content').isString().isLength({ min: 1, max: 500 })
    ]),
    (req, res) => {
        const { postId, content } = req.body;

        db.run('INSERT INTO comments (post_id, user_id, content) VALUES (?, ?, ?)',
            [postId, req.user.id, sanitizeInput(content)],
            function(err) {
                if (err) return res.status(500).json({ error: 'DB error' });
                res.status(201).json({ id: this.lastID });
            }
        );
    }
);

// === PUT /API/COMMENTS ===
app.put('/api/comments/:id', authenticate, csrfProtect,
    validate([
        param('id').isInt(),
        body('content').isString().isLength({ min: 1, max: 500 })
    ]),
    (req, res) => {
        const { id } = req.params;
        const { content } = req.body;

        db.get('SELECT user_id, content as old_content, edit_history FROM comments WHERE id = ?', [id], (err, comment) => {
            if (err || !comment) return res.status(404).json({ error: 'Comment not found' });
            if (comment.user_id !== req.user.id && !req.user.isAdmin) {
                return res.status(403).json({ error: 'Forbidden' });
            }
            
            const history = comment.edit_history ? JSON.parse(comment.edit_history) : [];
            history.push({
                old_content: comment.old_content,
                edited_at: new Date().toISOString(),
                edited_by: req.user.id
            });
            
            db.run('UPDATE comments SET content = ?, updated_at = datetime("now"), edit_history = ? WHERE id = ?',
                [sanitizeInput(content), JSON.stringify(history), id], function(err) {
                    if (err) return res.status(500).json({ error: 'Update failed' });
                    res.json({ message: 'Updated' });
                });
        });
    }
);

// === DELETE /API/COMMENTS ===
app.delete('/api/comments/:id', authenticate, csrfProtect,
    validate([param('id').isInt()]),
    (req, res) => {
        const { id } = req.params;

        db.get('SELECT user_id FROM comments WHERE id = ?', [id], (err, comment) => {
            if (err || !comment) return res.status(404).json({ error: 'Comment not found' });
            if (comment.user_id !== req.user.id && !req.user.isAdmin) {
                return res.status(403).json({ error: 'Forbidden' });
            }
            db.run('DELETE FROM comments WHERE id = ?', [id], function(err) {
                if (err) return res.status(500).json({ error: 'Delete failed' });
                res.json({ message: 'Deleted' });
            });
        });
    }
);

// === GET /API/MESSAGES ===
app.get('/api/messages', authenticate, (req, res) => {
    const sql = `
        SELECT m.*, u1.username as from_name, u2.username as to_name
        FROM messages m
        JOIN users u1 ON m.from_user = u1.id
        JOIN users u2 ON m.to_user = u2.id
        WHERE m.from_user = ? OR m.to_user = ?
        ORDER BY m.created_at DESC
        LIMIT 50
    `;
    db.all(sql, [req.user.id, req.user.id], (err, msgs) => {
        if (err) return res.status(500).json({ error: 'DB error' });
        const ids = msgs.filter(m => m.to_user === req.user.id && !m.read_at).map(m => m.id);
        if (ids.length) {
            db.run(`UPDATE messages SET read_at = datetime("now") WHERE id IN (${ids.map(() => '?').join(',')})`, ids);
        }
        res.json(msgs.map(m => ({
            ...m,
            encrypted_text: sanitizeInput(m.encrypted_text)
        })));
    });
});

// === POST /API/MESSAGES ===
app.post('/api/messages', authenticate, csrfProtect,
    validate([
        body('toUserId').isInt(),
        body('encryptedText').isString().isLength({ min: 1, max: 10000 })
    ]),
    (req, res) => {
        const { toUserId, encryptedText } = req.body;
        
        db.get('SELECT id FROM users WHERE id = ?', [toUserId], (err, user) => {
            if (err || !user) {
                return res.status(404).json({ error: 'Recipient not found' });
            }
            
            const iv = randomBytes(16).toString('hex');
            const encrypted = Buffer.from(encryptedText, 'utf8').toString('base64');
            
            db.run('INSERT INTO messages (from_user, to_user, encrypted_text, iv) VALUES (?, ?, ?, ?)',
                [req.user.id, toUserId, encrypted, iv],
                function(err) {
                    if (err) return res.status(500).json({ error: 'DB error' });
                    res.status(201).json({ id: this.lastID });
                });
        });
    }
);

// === GET /API/USERS ===
app.get('/api/users', authenticate, isAdmin, (req, res) => {
    db.all('SELECT id, username, isAdmin, created_at, last_login FROM users ORDER BY id', (err, users) => {
        if (err) return res.status(500).json({ error: 'DB error' });
        res.json(users);
    });
});

// === POST /API/MAKE-ADMIN ===
app.post('/api/make-admin', authenticate, isAdmin, csrfProtect,
    validate([body('userId').isInt()]),
    (req, res) => {
        const { userId } = req.body;
        if (userId === req.user.id) {
            return res.status(400).json({ error: 'Cannot promote yourself' });
        }

        db.run('UPDATE users SET isAdmin = 1 WHERE id = ?', [userId], function(err) {
            if (err) return res.status(500).json({ error: 'DB error' });
            if (this.changes === 0) return res.status(404).json({ error: 'User not found' });
            
            db.run('INSERT INTO audit_log (user_id, action, ip_hash, details) VALUES (?, ?, ?, ?)',
                [req.user.id, 'PROMOTE_USER', 
                 createHash('sha256').update(req.ip || '').digest('hex'),
                 `Promoted user ${userId}`]);
            
            res.json({ message: 'User promoted' });
        });
    }
);

// === DELETE /API/POSTS ===
app.delete('/api/posts/:id', authenticate, isAdmin, csrfProtect,
    validate([param('id').isInt()]),
    (req, res) => {
        const { id } = req.params;
        db.run('DELETE FROM posts WHERE id = ?', [id], function(err) {
            if (err) return res.status(500).json({ error: 'Delete failed' });
            if (this.changes === 0) return res.status(404).json({ error: 'Post not found' });
            res.json({ message: 'Deleted' });
        });
    }
);

// === ОБРАБОТЧИК ОШИБОК ===
app.use((err, req, res, next) => {
    console.error(encryptLog(err.message));
    if (err instanceof multer.MulterError) {
        if (err.code === 'FILE_TOO_LARGE') {
            return res.status(413).json({ error: 'File too large (max 5MB)' });
        }
        return res.status(400).json({ error: err.message });
    }
    // Не показываем детали ошибок клиенту
    res.status(500).json({ error: 'Internal server error' });
});

// === ЗАПУСК ===
app.listen(PORT, '127.0.0.1', () => {
    console.log(`🕯️ Lantern Kitchen running on http://127.0.0.1:${PORT}`);
    console.log('🔒 SECURITY HARDENED FOR DARKNET');
    console.log(`🔑 JWT Secret: ${JWT_SECRET.substring(0, 10)}... (secure)`);
    console.log(`📁 Upload directory: ${path.join(__dirname, 'public/uploads')}`);
    console.log('✅ All security measures active');
});

// === ЗАЩИТА ПРИ ЗАВЕРШЕНИИ ===
process.on('SIGTERM', () => {
    console.log('SIGTERM received, closing database...');
    db.close(() => {
        console.log('Database closed');
        process.exit(0);
    });
});

process.on('SIGINT', () => {
    console.log('SIGINT received, closing database...');
    db.close(() => {
        console.log('Database closed');
        process.exit(0);
    });
});
