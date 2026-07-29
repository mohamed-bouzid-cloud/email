const express = require('express');
const Database = require('better-sqlite3');
const cors = require('cors');
const path = require('path');
const bcrypt = require('bcrypt');
const cookieParser = require('cookie-parser');

const app = express();
const PORT = 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(cookieParser());

// Initialize SQLite database
const dbPath = process.env.VERCEL ? path.join('/tmp', 'emails.db') : path.join(__dirname, 'emails.db');
const db = new Database(dbPath);

// Create tables if they don't exist
db.exec(`
    CREATE TABLE IF NOT EXISTS emails (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT NOT NULL,
        datetime TEXT,
        is_invalid INTEGER DEFAULT 0,
        button_text TEXT DEFAULT 'Use',
        valid_date TEXT
    )
`);

db.exec(`
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )
`);

// Create default admin user if it doesn't exist
const adminExists = db.prepare('SELECT * FROM users WHERE username = ?').get('admin');
if (!adminExists) {
    const hashedPassword = bcrypt.hashSync('admin', 10);
    db.prepare('INSERT INTO users (username, password) VALUES (?, ?)').run('admin', hashedPassword);
    console.log('Default admin user created (username: admin, password: admin)');
}

// Create default user 'me' with password 'admin' if it doesn't exist
const meExists = db.prepare('SELECT * FROM users WHERE username = ?').get('me');
if (!meExists) {
    const mePassword = bcrypt.hashSync('admin', 10);
    db.prepare('INSERT INTO users (username, password) VALUES (?, ?)').run('me', mePassword);
    console.log('Default user created (username: me, password: admin)');
}

// API Routes

// Login endpoint
app.post('/api/login', (req, res) => {
    try {
        const { username, password } = req.body;
        
        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password required' });
        }
        
        const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
        
        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        const passwordMatch = bcrypt.compareSync(password, user.password);
        
        if (!passwordMatch) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        // Set a simple session cookie (in production, use proper session management)
        res.cookie('user_id', user.id, { 
            httpOnly: true,
            maxAge: 24 * 60 * 60 * 1000 // 24 hours
        });
        
        res.json({ message: 'Login successful', userId: user.id });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Logout endpoint
app.post('/api/logout', (req, res) => {
    res.clearCookie('user_id');
    res.json({ message: 'Logout successful' });
});

// Authentication middleware
function authenticate(req, res, next) {
    const userId = req.cookies.user_id;
    if (!userId) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
    if (!user) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    
    req.user = user;
    next();
}

// Protected Page Routes (must come before static middleware)

// Root route: redirect based on auth status
app.get('/', (req, res) => {
    const userId = req.cookies.user_id;
    if (userId) {
        const user = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
        if (user) {
            return res.sendFile(path.join(__dirname, 'email-table.html'));
        }
    }
    res.sendFile(path.join(__dirname, 'login.html'));
});

// Protect email-table.html direct access
app.get('/email-table.html', (req, res) => {
    const userId = req.cookies.user_id;
    if (userId) {
        const user = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
        if (user) {
            return res.sendFile(path.join(__dirname, 'email-table.html'));
        }
    }
    res.redirect('/login.html');
});

// Protect login.html direct access (redirect to app if already logged in)
app.get('/login.html', (req, res) => {
    const userId = req.cookies.user_id;
    if (userId) {
        const user = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
        if (user) {
            return res.redirect('/email-table.html');
        }
    }
    res.sendFile(path.join(__dirname, 'login.html'));
});

// Serve static files (after protected HTML routes)
app.use(express.static(path.join(__dirname)));

// API Routes

// Login endpoint
app.post('/api/login', (req, res) => {
    try {
        const { username, password } = req.body;
        
        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password required' });
        }
        
        const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
        
        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        const passwordMatch = bcrypt.compareSync(password, user.password);
        
        if (!passwordMatch) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        // Set session cookie
        res.cookie('user_id', user.id, { 
            httpOnly: true,
            sameSite: 'lax',
            maxAge: 24 * 60 * 60 * 1000 // 24 hours
        });
        
        res.json({ message: 'Login successful', userId: user.id });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Logout endpoint
app.post('/api/logout', (req, res) => {
    res.clearCookie('user_id');
    res.json({ message: 'Logout successful' });
});

// Get all emails
app.get('/api/emails', authenticate, (req, res) => {
    try {
        const emails = db.prepare('SELECT * FROM emails ORDER BY id').all();
        res.json(emails);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Add new email
app.post('/api/emails', authenticate, (req, res) => {
    try {
        const { email, datetime } = req.body;
        
        if (!email || typeof email !== 'string' || !email.trim()) {
            return res.status(400).json({ error: 'Valid email is required' });
        }
        
        const cleanEmail = email.trim();
        const cleanDatetime = datetime ?? '';
        
        const stmt = db.prepare('INSERT INTO emails (email, datetime) VALUES (?, ?)');
        const result = stmt.run(cleanEmail, cleanDatetime);
        res.json({ id: result.lastInsertRowid, email: cleanEmail, datetime: cleanDatetime, is_invalid: 0, button_text: 'Use', valid_date: null });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Update email
app.put('/api/emails/:id', authenticate, (req, res) => {
    try {
        const { email, datetime, is_invalid, button_text, valid_date } = req.body;
        
        if (!email || typeof email !== 'string' || !email.trim()) {
            return res.status(400).json({ error: 'Valid email is required' });
        }
        
        const cleanEmail = email.trim();
        const cleanDatetime = datetime ?? '';
        const cleanIsInvalid = is_invalid ? 1 : 0;
        const cleanButtonText = button_text || 'Use';
        const cleanValidDate = valid_date != null ? String(valid_date) : null;
        
        const stmt = db.prepare(`
            UPDATE emails 
            SET email = ?, datetime = ?, is_invalid = ?, button_text = ?, valid_date = ?
            WHERE id = ?
        `);
        stmt.run(cleanEmail, cleanDatetime, cleanIsInvalid, cleanButtonText, cleanValidDate, req.params.id);
        res.json({ id: req.params.id, email: cleanEmail, datetime: cleanDatetime, is_invalid: cleanIsInvalid, button_text: cleanButtonText, valid_date: cleanValidDate });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Delete email
app.delete('/api/emails/:id', authenticate, (req, res) => {
    try {
        const stmt = db.prepare('DELETE FROM emails WHERE id = ?');
        stmt.run(req.params.id);
        res.json({ message: 'Email deleted' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

if (require.main === module) {
    app.listen(PORT, () => {
        console.log(`Server running on http://localhost:${PORT}`);
    });
}

module.exports = app;

