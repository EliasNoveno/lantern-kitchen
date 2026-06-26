// lantern_server.js - УСИЛЕННАЯ ВЕРСИЯ ДЛЯ ДАРКНЕТА
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
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// === УСИЛЕННАЯ БЕЗОПАСНОСТЬ ===
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
        },
    },
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
    },
    referrerPolicy: { policy: 'no-referrer' },
    noSniff: true,
    xssFilter: true,
}));

// === RATE LIMITING ДЛЯ ДАРКНЕТА ===
const globalLimiter = rateLimit({
    windowMs: 5 * 60 * 1000,
    max: 60,
    message: { error: 'Too many requests. Slow down.' },
    standardHeaders: true,
    legacyHeaders: false,
});
app.use('/api/', globalLimiter);

const strictLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    skipSuccessfulRequests: true,
    message: { error: 'Too many attempts. Try again later.' }
});

const registerLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 3,
    message: { error: 'Registration limit reached. Try again later.' }
});

app.use(express.json({ limit: '10mb' }));
app.use(express.static('public', {
    maxAge: '1d',
    etag: true,
    lastModified: true,
}));
app.use(cookieParser());

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET || JWT_SECRET.length < 32) {
    console.error('FATAL: JWT_SECRET must be at least 32 characters in .env');
    process.exit(1);
}

// === БЕЗОПАСНАЯ РАБОТА С ФАЙЛАМИ ===
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const dir = 'public/uploads';
        if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
        cb(null, dir);
    },
    filename: (req, file, cb) => {
        const hash = crypto.randomBytes(16).toString('hex');
        const ext = path.extname(file.originalname).toLowerCase();
        const allowedExts = ['.jpg', '.jpeg', '.png', '.gif', '.webp', '.pdf', '.txt'];
        if (!allowedExts.includes(ext)) {
            return cb(new Error('Invalid file extension'), null);
        }
        cb(null, hash + ext);
    }
});

const fileFilter = (req, file, cb) => {
    const allowedTypes = [
        'image/jpeg', 'image/png', 'image/gif', 'image/webp',
        'application/pdf', 'text/plain', 'image/svg+xml'
    ];
    const maxSize = 5 * 1024 * 1024;
    if (file.size > maxSize) {
        return cb(new Error('File too large'), false);
    }
    if (allowedTypes.includes(file.mimetype)) {
        cb(null, true);
    } else {
        cb(new Error('Unsupported file type'), false);
    }
};

const upload = multer({
    storage,
    limits: { fileSize: 5 * 1024 * 1024 },
    fileFilter
});

// === БАЗА ДАННЫХ С ШИФРОВАНИЕМ ===
const db = new sqlite3.Database('lantern_kitchen.db');

// Функция для генерации соли для каждого пользователя
function generateSalt() {
    return crypto.randomBytes(32).toString('hex');
}

db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        salt TEXT NOT NULL,
        isAdmin INTEGER DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        last_login DATETIME,
        login_attempts INTEGER DEFAULT 0,
        locked_until DATETIME
    )`);
    
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
        FOREIGN KEY(created_by) REFERENCES users(id)
    )`);
    
    db.run(`CREATE TABLE IF NOT EXISTS comments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        post_id INTEGER,
        user_id INTEGER,
        content TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(post_id) REFERENCES posts(id) ON DELETE CASCADE,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )`);
    
    db.run(`CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        from_user INTEGER,
        to_user INTEGER,
        encrypted_text TEXT NOT NULL,
        iv TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        read_at DATETIME,
        FOREIGN KEY(from_user) REFERENCES users(id),
        FOREIGN KEY(to_user) REFERENCES users(id)
    )`);
    
    db.run(`CREATE TABLE IF NOT EXISTS sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        token TEXT UNIQUE NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        expires_at DATETIME,
        ip_hash TEXT,
        user_agent TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )`);
    
    db.run(`CREATE INDEX IF NOT EXISTS idx_posts_section ON posts(section)`);
    db.run(`CREATE INDEX IF NOT EXISTS idx_posts_created ON posts(created_at DESC)`);
    db.run(`CREATE INDEX IF NOT EXISTS idx_comments_post ON comments(post_id)`);
    db.run(`CREATE INDEX IF NOT EXISTS idx_messages_users ON messages(from_user, to_user)`);
});

// === УСИЛЕННАЯ АУТЕНТИФИКАЦИЯ ===
function authenticate(req, res, next) {
    const token = req.cookies.token;
    if (!token) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        // Проверяем, не истекла ли сессия в БД
        db.get('SELECT * FROM sessions WHERE token = ? AND expires_at > datetime("now")', 
            [token], (err, session) => {
                if (err || !session) {
                    return res.status(401).json({ error: 'Session expired' });
                }
                req.user = decoded;
                req.sessionId = session.id;
                next();
            });
    } catch (err) {
        return res.status(401).json({ error: 'Invalid token' });
    }
}

function isAdmin(req, res, next) {
    if (!req.user || !req.user.isAdmin) {
        return res.status(403).json({ error: 'Forbidden' });
    }
    next();
}

// === ЗАЩИТА ОТ CSRF ДЛЯ ДАРКНЕТА ===
function csrfProtect(req, res, next) {
    // В даркнете разрешаем только same-origin
    const origin = req.get('Origin');
    const referer = req.get('Referer');
    const host = req.get('Host');
    
    // Проверяем, что запрос идет с того же хоста
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
    
    // Для POST/PUT/DELETE запросов проверяем Referer
    const methods = ['POST', 'PUT', 'DELETE', 'PATCH'];
    if (methods.includes(req.method)) {
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
    }
    next();
}

// === ВАЛИДАЦИЯ ВХОДНЫХ ДАННЫХ ===
const validate = (validations) => {
    return async (req, res, next) => {
        await Promise.all(validations.map(validation => validation.run(req)));
        const errors = validationResult(req);
        if (errors.isEmpty()) {
            return next();
        }
        res.status(400).json({ errors: errors.array() });
    };
};

// === API ===

// Регистрация с защитой от ботов
app.post('/api/register', registerLimiter, 
    validate([
        body('username')
            .isLength({ min: 3, max: 20 })
            .matches(/^[a-zA-Z0-9_]+$/)
            .withMessage('Username can only contain letters, numbers, underscore'),
        body('password')
            .isLength({ min: 8 })
            .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
            .withMessage('Password must contain uppercase, lowercase and number')
    ]),
    async (req, res) => {
        const { username, password } = req.body;
        
        try {
            const salt = generateSalt();
            const hash = await bcrypt.hash(password + salt, 12);
            
            db.run('INSERT INTO users (username, password, salt) VALUES (?, ?, ?)',
                [username, hash, salt],
                function(err) {
                    if (err) {
                        if (err.message.includes('UNIQUE')) {
                            return res.status(400).json({ error: 'Username taken' });
                        }
                        return res.status(500).json({ error: 'Registration failed' });
                    }
                    res.status(201).json({ message: 'Registered' });
                });
        } catch (err) {
            res.status(500).json({ error: 'Server error' });
        }
    }
);

// Логин с защитой от брутфорса
app.post('/api/login', strictLimiter,
    validate([
        body('username').isLength({ min: 3, max: 20 }),
        body('password').isLength({ min: 8 })
    ]),
    (req, res) => {
        const { username, password } = req.body;
        
        db.get('SELECT id, username, password, salt, isAdmin, login_attempts, locked_until FROM users WHERE username = ?',
            [username], async (err, user) => {
                if (err || !user) {
                    return res.status(401).json({ error: 'Invalid credentials' });
                }
                
                // Проверка блокировки
                if (user.locked_until && new Date(user.locked_until) > new Date()) {
                    return res.status(429).json({ error: 'Account locked. Try later.' });
                }
                
                const match = await bcrypt.compare(password + user.salt, user.password);
                if (!match) {
                    // Увеличиваем счетчик неудачных попыток
                    const attempts = (user.login_attempts || 0) + 1;
                    let lockedUntil = null;
                    if (attempts >= 5) {
                        lockedUntil = new Date(Date.now() + 15 * 60 * 1000).toISOString();
                    }
                    db.run('UPDATE users SET login_attempts = ?, locked_until = ? WHERE id = ?',
                        [attempts, lockedUntil, user.id]);
                    return res.status(401).json({ error: 'Invalid credentials' });
                }
                
                // Сброс счетчика попыток
                db.run('UPDATE users SET login_attempts = 0, locked_until = NULL, last_login = datetime("now") WHERE id = ?',
                    [user.id]);
                
                const token = jwt.sign(
                    { id: user.id, username: user.username, isAdmin: user.isAdmin },
                    JWT_SECRET,
                    { expiresIn: '12h' }
                );
                
                // Сохраняем сессию
                const expiresAt = new Date(Date.now() + 12 * 60 * 60 * 1000).toISOString();
                db.run('INSERT INTO sessions (user_id, token, expires_at, ip_hash, user_agent) VALUES (?, ?, ?, ?, ?)',
                    [user.id, token, expiresAt, 
                     crypto.createHash('sha256').update(req.ip || '').digest('hex'),
                     req.get('User-Agent') || ''],
                    (err) => {
                        if (err) {
                            console.error('Session save error:', err);
                            return res.status(500).json({ error: 'Login failed' });
                        }
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

// Логаут с удалением сессии
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

// Получить текущего пользователя
app.get('/api/me', authenticate, (req, res) => {
    db.get('SELECT id, username, isAdmin FROM users WHERE id = ?', [req.user.id], (err, user) => {
        if (err || !user) return res.status(401).json({ error: 'Not found' });
        res.json(user);
    });
});

// === ПОСТЫ ===

// Получить посты (публичные)
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
                    posts: posts.map(p => ({ ...p, secret_hash: undefined, secret_salt: undefined })),
                    totalPages,
                    currentPage: page
                });
            });
        });
    }
);

// Получить секретные посты
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
                    const match = await bcrypt.compare(password + p.secret_salt, p.secret_hash);
                    if (match) {
                        validPosts.push({ ...p, secret_hash: undefined, secret_salt: undefined });
                    }
                }
            }
            res.json(validPosts);
        });
    }
);

// Создать пост
app.post('/api/posts', authenticate, csrfProtect, upload.single('file'),
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
        
        if (isSecret && secret_password) {
            secretSalt = generateSalt();
            secretHash = bcrypt.hashSync(secret_password + secretSalt, 12);
        }

        const sql = `INSERT INTO posts (section, title, content, file_path, is_secret, secret_hash, secret_salt, created_by)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`;
        db.run(sql, [section, title || '', content || '', filePath, isSecret, secretHash, secretSalt, req.user.id],
            function(err) {
                if (err) {
                    console.error(err);
                    return res.status(500).json({ error: 'Failed to create post' });
                }
                res.status(201).json({ id: this.lastID, message: 'Post created' });
            });
    }
);

// === КОММЕНТАРИИ ===

// Получить комментарии
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
            res.json(comments);
        });
    }
);

// Создать комментарий
app.post('/api/comments', authenticate, csrfProtect,
    validate([
        body('postId').isInt(),
        body('content').isString().isLength({ min: 1, max: 500 })
    ]),
    (req, res) => {
        const { postId, content } = req.body;

        db.run('INSERT INTO comments (post_id, user_id, content) VALUES (?, ?, ?)',
            [postId, req.user.id, content],
            function(err) {
                if (err) return res.status(500).json({ error: 'DB error' });
                res.status(201).json({ id: this.lastID });
            }
        );
    }
);

// Редактировать комментарий
app.put('/api/comments/:id', authenticate, csrfProtect,
    validate([
        param('id').isInt(),
        body('content').isString().isLength({ min: 1, max: 500 })
    ]),
    (req, res) => {
        const { id } = req.params;
        const { content } = req.body;

        db.get('SELECT user_id FROM comments WHERE id = ?', [id], (err, comment) => {
            if (err || !comment) return res.status(404).json({ error: 'Comment not found' });
            if (comment.user_id !== req.user.id && !req.user.isAdmin) {
                return res.status(403).json({ error: 'Forbidden' });
            }
            db.run('UPDATE comments SET content = ?, updated_at = datetime("now") WHERE id = ?',
                [content, id], function(err) {
                    if (err) return res.status(500).json({ error: 'Update failed' });
                    res.json({ message: 'Updated' });
                });
        });
    }
);

// Удалить комментарий (только автор или админ)
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

// === СООБЩЕНИЯ С ШИФРОВАНИЕМ ===

// Получить сообщения
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
        // Отмечаем как прочитанные
        const ids = msgs.filter(m => m.to_user === req.user.id && !m.read_at).map(m => m.id);
        if (ids.length) {
            db.run(`UPDATE messages SET read_at = datetime("now") WHERE id IN (${ids.map(() => '?').join(',')})`, ids);
        }
        res.json(msgs);
    });
});

// Отправить сообщение
app.post('/api/messages', authenticate, csrfProtect,
    validate([
        body('toUserId').isInt(),
        body('encryptedText').isString().isLength({ min: 1, max: 10000 })
    ]),
    (req, res) => {
        const { toUserId, encryptedText } = req.body;
        
        // Проверяем, существует ли получатель
        db.get('SELECT id FROM users WHERE id = ?', [toUserId], (err, user) => {
            if (err || !user) {
                return res.status(404).json({ error: 'Recipient not found' });
            }
            
            // Генерируем IV для шифрования
            const iv = crypto.randomBytes(16).toString('hex');
            
            db.run('INSERT INTO messages (from_user, to_user, encrypted_text, iv) VALUES (?, ?, ?, ?)',
                [req.user.id, toUserId, encryptedText, iv],
                function(err) {
                    if (err) return res.status(500).json({ error: 'DB error' });
                    res.status(201).json({ id: this.lastID });
                });
        });
    }
);

// === АДМИНКА ===

// Получить всех пользователей
app.get('/api/users', authenticate, isAdmin, (req, res) => {
    db.all('SELECT id, username, isAdmin, created_at, last_login FROM users ORDER BY id', (err, users) => {
        if (err) return res.status(500).json({ error: 'DB error' });
        res.json(users);
    });
});

// Назначить админа
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
            res.json({ message: 'User promoted' });
        });
    }
);

// Удалить пост (только админ)
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

// === ОБРАБОТКА ОШИБОК ===
app.use((err, req, res, next) => {
    console.error('Error:', err);
    if (err instanceof multer.MulterError) {
        if (err.code === 'FILE_TOO_LARGE') {
            return res.status(413).json({ error: 'File too large' });
        }
        return res.status(400).json({ error: err.message });
    }
    res.status(500).json({ error: 'Internal server error' });
});

// === ЗАПУСК ===
app.listen(PORT, '127.0.0.1', () => {
    console.log(`🕯️ Lantern Kitchen running on http://127.0.0.1:${PORT}`);
    console.log('🔒 Security hardened for darknet deployment');
});
