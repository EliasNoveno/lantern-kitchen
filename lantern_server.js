// lantern_server.js (полная версия)
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
require('dotenv').config();

const app = express();
const PORT = 3000;

// === Безопасность заголовков ===
app.use(helmet({
    contentSecurityPolicy: false, // отключаем, чтобы не мешать клиентскому коду (но в проде лучше настроить)
}));

// === Rate Limiting ===
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 минут
    max: 100,
    message: { error: 'Too many requests, please try again later.' },
    standardHeaders: true,
    legacyHeaders: false,
});
app.use('/api/', limiter);

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    skipSuccessfulRequests: true,
    message: { error: 'Too many login attempts. Try again later.' }
});

app.use(express.json());
app.use(express.static('public'));
app.use(cookieParser());

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
    console.error('FATAL ERROR: JWT_SECRET is not defined in .env');
    process.exit(1);
}

// === Валидация файлов ===
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const dir = 'public/uploads';
        if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
        cb(null, dir);
    },
    filename: (req, file, cb) => {
        const safeName = Date.now() + '-' + Math.round(Math.random() * 1E9) + path.extname(file.originalname);
        cb(null, safeName);
    }
});

const fileFilter = (req, file, cb) => {
    const allowedTypes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp', 'application/pdf', 'text/plain'];
    if (allowedTypes.includes(file.mimetype)) {
        cb(null, true);
    } else {
        cb(new Error('Unsupported file type'), false);
    }
};

const upload = multer({
    storage,
    limits: { fileSize: 10 * 1024 * 1024 },
    fileFilter
});

// === База данных ===
const db = new sqlite3.Database('lantern_kitchen.db');

db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        isAdmin INTEGER DEFAULT 0
    )`);
    db.run(`CREATE TABLE IF NOT EXISTS posts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        section TEXT NOT NULL,
        title TEXT,
        content TEXT,
        file_path TEXT,
        is_secret INTEGER DEFAULT 0,
        secret_hash TEXT,
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
        FOREIGN KEY(post_id) REFERENCES posts(id),
        FOREIGN KEY(user_id) REFERENCES users(id)
    )`);
    db.run(`CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        from_user INTEGER,
        to_user INTEGER,
        encrypted_text TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(from_user) REFERENCES users(id),
        FOREIGN KEY(to_user) REFERENCES users(id)
    )`);
});

// === Middleware: проверка JWT ===
function authenticate(req, res, next) {
    const token = req.cookies.token;
    if (!token) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (err) {
        return res.status(401).json({ error: 'Invalid token' });
    }
}

// === Middleware: проверка админа ===
function isAdmin(req, res, next) {
    if (!req.user || !req.user.isAdmin) {
        return res.status(403).json({ error: 'Forbidden' });
    }
    next();
}

// === Middleware: CSRF защита (проверка Origin/Referer) ===
function csrfProtect(req, res, next) {
    const origin = req.get('Origin');
    const referer = req.get('Referer');
    if (!origin && !referer) {
        return res.status(403).json({ error: 'CSRF token missing' });
    }
    // Разрешаем только localhost в dev, в проде нужно указать домен
    const allowedHosts = ['http://localhost:3000', 'http://127.0.0.1:3000'];
    const valid = (origin && allowedHosts.includes(origin)) || (referer && allowedHosts.some(h => referer.startsWith(h)));
    if (!valid) {
        return res.status(403).json({ error: 'Invalid origin' });
    }
    next();
}

// === API ===

// Регистрация
app.post('/api/register', loginLimiter, async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password required' });
    }
    if (password.length < 6) {
        return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }
    if (!/^[a-zA-Z0-9_]+$/.test(username)) {
        return res.status(400).json({ error: 'Username can only contain letters, numbers, underscore' });
    }
    try {
        const hash = await bcrypt.hash(password, 10);
        db.run('INSERT INTO users (username, password) VALUES (?, ?)', [username, hash], function(err) {
            if (err) {
                if (err.message.includes('UNIQUE')) {
                    return res.status(400).json({ error: 'Username already taken' });
                }
                return res.status(500).json({ error: 'Registration failed' });
            }
            res.status(201).json({ message: 'Registered successfully' });
        });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

// Логин
app.post('/api/login', loginLimiter, (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password required' });
    }
    db.get('SELECT id, username, password, isAdmin FROM users WHERE username = ?', [username], async (err, user) => {
        if (err || !user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        const match = await bcrypt.compare(password, user.password);
        if (!match) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        const token = jwt.sign(
            { id: user.id, username: user.username, isAdmin: user.isAdmin },
            JWT_SECRET,
            { expiresIn: '7d' }
        );
        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'lax',
            maxAge: 7 * 24 * 60 * 60 * 1000 // 7 дней
        });
        res.json({ message: 'Login successful' });
    });
});

// Логаут
app.post('/api/logout', (req, res) => {
    res.clearCookie('token');
    res.json({ message: 'Logged out' });
});

// Получить текущего пользователя
app.get('/api/me', authenticate, (req, res) => {
    db.get('SELECT id, username, isAdmin FROM users WHERE id = ?', [req.user.id], (err, user) => {
        if (err || !user) return res.status(401).json({ error: 'Not found' });
        res.json(user);
    });
});

// === Посты ===

// Получить посты (публичные)
app.get('/api/posts/:section', (req, res) => {
    const { section } = req.params;
    const page = parseInt(req.query.page) || 1;
    const limit = 10;
    const offset = (page - 1) * limit;

    // Только несекретные посты
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
                posts: posts.map(p => ({ ...p, secret_hash: undefined })),
                totalPages,
                currentPage: page
            });
        });
    });
});

// Получить секретные посты (только с паролем)
app.post('/api/posts/secret', authenticate, (req, res) => {
    const { section, password } = req.body;
    if (!password) return res.status(400).json({ error: 'Password required' });

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
            if (p.secret_hash) {
                const match = await bcrypt.compare(password, p.secret_hash);
                if (match) {
                    validPosts.push({ ...p, secret_hash: undefined });
                }
            }
        }
        res.json(validPosts);
    });
});

// Создать пост (только авторизованные)
app.post('/api/posts', authenticate, csrfProtect, upload.single('file'), (req, res) => {
    const { section, title, content, is_secret, secret_password } = req.body;
    if (!section) return res.status(400).json({ error: 'Section required' });

    const filePath = req.file ? '/uploads/' + req.file.filename : null;
    const isSecret = is_secret === 'true' || is_secret === true ? 1 : 0;
    let secretHash = null;
    if (isSecret && secret_password) {
        secretHash = bcrypt.hashSync(secret_password, 10);
    }

    const sql = `INSERT INTO posts (section, title, content, file_path, is_secret, secret_hash, created_by)
                 VALUES (?, ?, ?, ?, ?, ?, ?)`;
    db.run(sql, [section, title || '', content || '', filePath, isSecret, secretHash, req.user.id], function(err) {
        if (err) {
            console.error(err);
            return res.status(500).json({ error: 'Failed to create post' });
        }
        res.status(201).json({ id: this.lastID, message: 'Post created' });
    });
});

// === Комментарии ===

// Получить комментарии
app.get('/api/comments/:postId', (req, res) => {
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
});

// Создать комментарий
app.post('/api/comments', authenticate, csrfProtect, (req, res) => {
    const { postId, content } = req.body;
    if (!postId || !content) return res.status(400).json({ error: 'Missing data' });
    if (content.length > 500) return res.status(400).json({ error: 'Comment too long' });

    db.run('INSERT INTO comments (post_id, user_id, content) VALUES (?, ?, ?)',
        [postId, req.user.id, content],
        function(err) {
            if (err) return res.status(500).json({ error: 'DB error' });
            res.status(201).json({ id: this.lastID });
        }
    );
});

// Редактировать комментарий (только автор или админ)
app.put('/api/comments/:id', authenticate, csrfProtect, (req, res) => {
    const { id } = req.params;
    const { content } = req.body;
    if (!content) return res.status(400).json({ error: 'Content required' });

    db.get('SELECT user_id FROM comments WHERE id = ?', [id], (err, comment) => {
        if (err || !comment) return res.status(404).json({ error: 'Comment not found' });
        if (comment.user_id !== req.user.id && !req.user.isAdmin) {
            return res.status(403).json({ error: 'Forbidden' });
        }
        db.run('UPDATE comments SET content = ? WHERE id = ?', [content, id], function(err) {
            if (err) return res.status(500).json({ error: 'Update failed' });
            res.json({ message: 'Updated' });
        });
    });
});

// === Сообщения ===

// Получить сообщения пользователя
app.get('/api/messages', authenticate, (req, res) => {
    const sql = `
        SELECT m.*, u1.username as from_name, u2.username as to_name
        FROM messages m
        JOIN users u1 ON m.from_user = u1.id
        JOIN users u2 ON m.to_user = u2.id
        WHERE m.from_user = ? OR m.to_user = ?
        ORDER BY m.created_at DESC
    `;
    db.all(sql, [req.user.id, req.user.id], (err, msgs) => {
        if (err) return res.status(500).json({ error: 'DB error' });
        res.json(msgs);
    });
});

// Отправить сообщение
app.post('/api/messages', authenticate, csrfProtect, (req, res) => {
    const { toUserId, encryptedText } = req.body;
    if (!toUserId || !encryptedText) return res.status(400).json({ error: 'Missing data' });

    db.run('INSERT INTO messages (from_user, to_user, encrypted_text) VALUES (?, ?, ?)',
        [req.user.id, toUserId, encryptedText],
        function(err) {
            if (err) return res.status(500).json({ error: 'DB error' });
            res.status(201).json({ id: this.lastID });
        }
    );
});

// === Админка ===

// Получить всех пользователей (только админ)
app.get('/api/users', authenticate, isAdmin, (req, res) => {
    db.all('SELECT id, username, isAdmin FROM users ORDER BY id', (err, users) => {
        if (err) return res.status(500).json({ error: 'DB error' });
        res.json(users);
    });
});

// Назначить админа (только админ)
app.post('/api/make-admin', authenticate, isAdmin, csrfProtect, (req, res) => {
    const { userId } = req.body;
    if (!userId) return res.status(400).json({ error: 'User ID required' });

    db.run('UPDATE users SET isAdmin = 1 WHERE id = ?', [userId], function(err) {
        if (err) return res.status(500).json({ error: 'DB error' });
        if (this.changes === 0) return res.status(404).json({ error: 'User not found' });
        res.json({ message: 'User promoted to admin' });
    });
});

// === Запуск ===
app.listen(PORT, () => {
    console.log(`🕯️ Lantern Kitchen running on http://localhost:${PORT}`);
});
