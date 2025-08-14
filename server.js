// server.js - Node.js Backend for Ringless Drop Platform

const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2/promise');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const fetch = require('node-fetch');
require('dotenv').config();

const app = express();

// Trust proxy for Heroku
app.set('trust proxy', 1);

// Middleware
app.use(helmet());
app.use(cors({
    origin: process.env.FRONTEND_URL || '*', // Allow any origin or set to your frontend URL
    credentials: true
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Rate limiting - fixed for Heroku proxy
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    keyGenerator: (req) => req.ip, // Fix ERR_ERL_UNEXPECTED_X_FORWARDED_FOR
    message: 'Too many requests from this IP'
});
app.use(limiter);

// Serve static files from current directory (optional)
app.use(express.static(__dirname));

// Database connection
const dbConfig = {
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME || 'ringless_drop',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
};

let db;

async function initDatabase() {
    try {
        db = mysql.createPool(dbConfig);
        console.log('Database connected successfully');
        await createTables();
    } catch (error) {
        console.error('Database connection failed:', error);
        process.exit(1);
    }
}

async function createTables() {
    await db.execute(`
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            email VARCHAR(255) UNIQUE NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            credits INT DEFAULT 0,
            is_admin BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        )
    `);

    await db.execute(`
        CREATE TABLE IF NOT EXISTS campaigns (
            id VARCHAR(50) PRIMARY KEY,
            user_id INT NOT NULL,
            sender_id VARCHAR(20) NOT NULL,
            recipient_count INT NOT NULL,
            audio_file_url TEXT NOT NULL,
            audio_file_type VARCHAR(10) NOT NULL,
            status ENUM('pending', 'running', 'completed', 'failed') DEFAULT 'pending',
            progress INT DEFAULT 0,
            slybroadcast_response TEXT,
            credits_used INT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    `);

    await db.execute(`
        CREATE TABLE IF NOT EXISTS campaign_recipients (
            id INT AUTO_INCREMENT PRIMARY KEY,
            campaign_id VARCHAR(50) NOT NULL,
            phone_number VARCHAR(20) NOT NULL,
            status ENUM('pending', 'sent', 'failed') DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (campaign_id) REFERENCES campaigns(id) ON DELETE CASCADE
        )
    `);

    await db.execute(`
        CREATE TABLE IF NOT EXISTS admin_logs (
            id INT AUTO_INCREMENT PRIMARY KEY,
            admin_id INT NOT NULL,
            action VARCHAR(255) NOT NULL,
            target_user_id INT,
            details TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (admin_id) REFERENCES users(id)
        )
    `);

    console.log('Database tables created/verified');
}

// Authentication middleware
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Access token required' });

    jwt.verify(token, process.env.JWT_SECRET || 'fallback_secret_key', (err, user) => {
        if (err) return res.status(403).json({ error: 'Invalid token' });
        req.user = user;
        next();
    });
}

function requireAdmin(req, res, next) {
    if (!req.user.isAdmin) return res.status(403).json({ error: 'Admin access required' });
    next();
}

// Auth Routes
app.post('/api/auth/register', async (req, res) => {
    try {
        const { name, email, password } = req.body;
        if (!name || !email || !password) return res.status(400).json({ error: 'All fields are required' });

        const [existingUsers] = await db.execute('SELECT id FROM users WHERE email = ?', [email]);
        if (existingUsers.length > 0) return res.status(400).json({ error: 'Email already registered' });

        const passwordHash = await bcrypt.hash(password, 12);
        const [result] = await db.execute(
            'INSERT INTO users (name, email, password_hash, credits) VALUES (?, ?, ?, ?)',
            [name, email, passwordHash, 100]
        );

        const token = jwt.sign({ id: result.insertId, email, isAdmin: false }, process.env.JWT_SECRET || 'fallback_secret_key', { expiresIn: '24h' });

        res.status(201).json({ user: { id: result.insertId, name, email, credits: 100, isAdmin: false }, token });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Registration failed' });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

        const [users] = await db.execute('SELECT id, name, email, password_hash, credits, is_admin FROM users WHERE email = ?', [email]);
        if (users.length === 0) return res.status(401).json({ error: 'Invalid credentials' });

        const user = users[0];
        const validPassword = await bcrypt.compare(password, user.password_hash);
        if (!validPassword) return res.status(401).json({ error: 'Invalid credentials' });

        const token = jwt.sign({ id: user.id, email: user.email, isAdmin: user.is_admin }, process.env.JWT_SECRET || 'fallback_secret_key', { expiresIn: '24h' });

        res.json({ user: { id: user.id, name: user.name, email: user.email, credits: user.credits, isAdmin: user.is_admin }, token });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Login failed' });
    }
});

// Campaign Routes (unchanged from your original, keeping same functionality)
app.post('/api/campaigns', authenticateToken, async (req, res) => {
    try {
        const { senderId, receiverNumbers, audioFile, audioFileType } = req.body;
        const userId = req.user.id;
        if (!senderId || !receiverNumbers || !audioFile || !audioFileType) return res.status(400).json({ error: 'All fields are required' });

        const phoneRegex = /^[0-9]{10,15}$/;
        for (let number of receiverNumbers) {
            if (!phoneRegex.test(number.trim())) return res.status(400).json({ error: `Invalid phone number: ${number}` });
        }

        const recipientCount = receiverNumbers.length;
        const [users] = await db.execute('SELECT credits FROM users WHERE id = ?', [userId]);
        if (users.length === 0) return res.status(404).json({ error: 'User not found' });

        const userCredits = users[0].credits;
        if (userCredits < recipientCount) return res.status(400).json({ error: `Insufficient credits. Required: ${recipientCount}, Available: ${userCredits}` });

        const campaignId = 'RD' + Date.now();
        await db.execute(
            `INSERT INTO campaigns (id, user_id, sender_id, recipient_count, audio_file_url, audio_file_type, status, credits_used) 
            VALUES (?, ?, ?, ?, ?, ?, 'pending', ?)`,
            [campaignId, userId, senderId, recipientCount, audioFile, audioFileType, recipientCount]
        );

        const recipientValues = receiverNumbers.map(number => [campaignId, number.trim()]);
        await db.query('INSERT INTO campaign_recipients (campaign_id, phone_number) VALUES ?', [recipientValues]);
        await db.execute('UPDATE users SET credits = credits - ? WHERE id = ?', [recipientCount, userId]);

        const slyResponse = await sendToSlybroadcast({ campaignId, senderId, receiverNumbers, audioFile, audioFileType });
        await db.execute('UPDATE campaigns SET status = ?, slybroadcast_response = ? WHERE id = ?', ['running', JSON.stringify(slyResponse), campaignId]);

        res.status(201).json({ campaignId, status: 'success', message: 'Campaign created successfully' });
        simulateCampaignProgress(campaignId);
    } catch (error) {
        console.error('Campaign creation error:', error);
        res.status(500).json({ error: 'Failed to create campaign' });
    }
});

// Slybroadcast API call
async function sendToSlybroadcast(campaignData) {
    const { senderId, receiverNumbers, audioFile, audioFileType } = campaignData;
    const USERNAME = process.env.SLYBROADCAST_USERNAME || 'YOUR_USERNAME_HERE';
    const PASSWORD = process.env.SLYBROADCAST_PASSWORD || 'YOUR_PASSWORD_HERE';
    const ENDPOINT = 'https://www.mobile-sphere.com/gateway/vmb.php';

    const formData = new URLSearchParams();
    formData.append('c', 'vmb');
    formData.append('user', USERNAME);
    formData.append('pass', PASSWORD);
    formData.append('callerid', senderId);
    formData.append('phone', receiverNumbers.join(','));
    formData.append('audio_url', audioFile);
    formData.append('audio_format', audioFileType);

    const response = await fetch(ENDPOINT, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: formData });
    const result = await response.text();
    if (result.includes('SENT OK') || result.includes('SUCCESS')) return { status: 'success', response: result };
    throw new Error('Slybroadcast API Error: ' + result);
}

// Progress simulation
async function simulateCampaignProgress(campaignId) {
    let progress = 0;
    const interval = setInterval(async () => {
        progress += Math.random() * 15;
        if (progress >= 100) {
            clearInterval(interval);
            await db.execute('UPDATE campaigns SET status = ?, progress = ? WHERE id = ?', ['completed', 100, campaignId]);
        } else {
            await db.execute('UPDATE campaigns SET progress = ? WHERE id = ?', [Math.round(progress), campaignId]);
        }
    }, 5000);
}

// Admin routes (same as before)

// User profile routes (same as before)

// Health check
app.get('/api/health', (req, res) => {
    res.json({ status: 'healthy', timestamp: new Date().toISOString(), version: '1.0.0' });
});

// Homepage route
app.get('/', (req, res) => {
    res.send(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>Ringless Drop Platform</title>
        </head>
        <body>
            <h1>Ringless Drop Platform is Live!</h1>
        </body>
        </html>
    `);
});

const PORT = process.env.PORT || 5000;
async function startServer() {
    await initDatabase();
    app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
}
startServer();
module.exports = app;
