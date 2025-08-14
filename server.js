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

// ✅ Fix for Heroku rate-limit bug
app.set('trust proxy', 1);

// Middleware
app.use(helmet());
app.use(cors({
    origin: [
        process.env.FRONTEND_URL || 'http://localhost:3000',
        'https://your-netlify-site.netlify.app', // change this to your actual frontend URL
    ],
    credentials: true
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// ✅ Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    standardHeaders: true,
    legacyHeaders: false
});
app.use(limiter);

// ✅ Serve static files
app.use(express.static(__dirname));

/* -------------------- DATABASE SETUP -------------------- */
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
    db = mysql.createPool(dbConfig);
    console.log('✅ Database connected');
    await createTables();
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
    console.log('✅ Tables ready');
}

/* -------------------- AUTH MIDDLEWARE -------------------- */
function authenticateToken(req, res, next) {
    const token = req.headers['authorization']?.split(' ')[1];
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

/* -------------------- API ROUTES -------------------- */
// (keep all your original routes exactly as they are here — no changes except trust proxy + CORS fix)

/* -------------------- HEALTH CHECK -------------------- */
app.get('/api/health', (req, res) => {
    res.json({ status: 'healthy', timestamp: new Date().toISOString() });
});

/* -------------------- START SERVER -------------------- */
const PORT = process.env.PORT || 5000;
async function startServer() {
    await initDatabase();
    app.listen(PORT, () => {
        console.log(`🚀 Server running on port ${PORT}`);
    });
}
startServer();
