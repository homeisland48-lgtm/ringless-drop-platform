// Database setup script for Heroku deployment
// This runs automatically after deployment

const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');

async function setupDatabase() {
    console.log('🚀 Setting up Ringless Drop database...');
    
    try {
        // Parse JawsDB connection URL (Heroku MySQL addon)
        const dbUrl = process.env.JAWSDB_URL || process.env.DATABASE_URL;
        
        if (!dbUrl) {
            console.error('❌ No database URL found. Make sure JawsDB addon is installed.');
            process.exit(1);
        }
        
        // Parse the URL: mysql://user:pass@host:port/dbname
        const url = new URL(dbUrl);
        const connection = await mysql.createConnection({
            host: url.hostname,
            port: url.port || 3306,
            user: url.username,
            password: url.password,
            database: url.pathname.slice(1), // Remove leading slash
            ssl: {
                rejectUnauthorized: false
            }
        });
        
        console.log('✅ Connected to database');
        
        // Create tables
        console.log('📋 Creating tables...');
        
        // Users table
        await connection.execute(`
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                email VARCHAR(255) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                credits INT DEFAULT 0,
                is_admin BOOLEAN DEFAULT FALSE,
                phone VARCHAR(20),
                company VARCHAR(255),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                last_login TIMESTAMP NULL,
                is_active BOOLEAN DEFAULT TRUE,
                
                INDEX idx_email (email),
                INDEX idx_credits (credits),
                INDEX idx_is_admin (is_admin)
            )
        `);
        
        // Campaigns table
        await connection.execute(`
            CREATE TABLE IF NOT EXISTS campaigns (
                id VARCHAR(50) PRIMARY KEY,
                user_id INT NOT NULL,
                sender_id VARCHAR(20) NOT NULL,
                recipient_count INT NOT NULL,
                audio_file_url TEXT NOT NULL,
                audio_file_type VARCHAR(10) NOT NULL,
                status ENUM('pending', 'running', 'completed', 'failed', 'paused') DEFAULT 'pending',
                progress INT DEFAULT 0,
                slybroadcast_response TEXT,
                credits_used INT NOT NULL,
                campaign_name VARCHAR(255),
                notes TEXT,
                scheduled_at TIMESTAMP NULL,
                started_at TIMESTAMP NULL,
                completed_at TIMESTAMP NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                INDEX idx_user_id (user_id),
                INDEX idx_status (status),
                INDEX idx_created_at (created_at)
            )
        `);
        
        // Campaign recipients table
        await connection.execute(`
            CREATE TABLE IF NOT EXISTS campaign_recipients (
                id INT AUTO_INCREMENT PRIMARY KEY,
                campaign_id VARCHAR(50) NOT NULL,
                phone_number VARCHAR(20) NOT NULL,
                status ENUM('pending', 'sent', 'failed', 'delivered') DEFAULT 'pending',
                error_message TEXT,
                sent_at TIMESTAMP NULL,
                delivered_at TIMESTAMP NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                
                FOREIGN KEY (campaign_id) REFERENCES campaigns(id) ON DELETE CASCADE,
                INDEX idx_campaign_id (campaign_id),
                INDEX idx_phone_number (phone_number)
            )
        `);
        
        // Admin logs table
        await connection.execute(`
            CREATE TABLE IF NOT EXISTS admin_logs (
                id INT AUTO_INCREMENT PRIMARY KEY,
                admin_id INT NOT NULL,
                action VARCHAR(255) NOT NULL,
                target_user_id INT,
                target_campaign_id VARCHAR(50),
                details TEXT,
                ip_address VARCHAR(45),
                user_agent TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                
                FOREIGN KEY (admin_id) REFERENCES users(id),
                INDEX idx_admin_id (admin_id),
                INDEX idx_action (action)
            )
        `);
        
        // Credit transactions table
        await connection.execute(`
            CREATE TABLE IF NOT EXISTS credit_transactions (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                transaction_type ENUM('purchase', 'usage', 'refund', 'bonus') NOT NULL,
                amount INT NOT NULL,
                balance_after INT NOT NULL,
                description TEXT,
                campaign_id VARCHAR(50),
                processed_by INT,
                payment_method VARCHAR(50),
                payment_reference VARCHAR(255),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (campaign_id) REFERENCES campaigns(id) ON DELETE SET NULL,
                FOREIGN KEY (processed_by) REFERENCES users(id) ON DELETE SET NULL,
                INDEX idx_user_id (user_id),
                INDEX idx_transaction_type (transaction_type)
            )
        `);
        
        console.log('✅ Tables created successfully');
        
        // Check if admin user already exists
        const [existingAdmin] = await connection.execute(
            'SELECT id FROM users WHERE email = ?',
            ['admin@ringlessdrop.com']
        );
        
        if (existingAdmin.length === 0) {
            console.log('👤 Creating default admin user...');
            
            // Create admin user (password: admin123)
            const adminPassword = await bcrypt.hash('admin123', 12);
            
            await connection.execute(`
                INSERT INTO users (name, email, password_hash, credits, is_admin) 
                VALUES (?, ?, ?, ?, ?)
            `, ['Jay (Admin)', 'admin@ringlessdrop.com', adminPassword, 10000, true]);
            
            console.log('✅ Admin user created');
            console.log('📧 Admin login: admin@ringlessdrop.com');
            console.log('🔑 Admin password: admin123');
            console.log('⚠️  IMPORTANT: Change the admin password after first login!');
        } else {
            console.log('👤 Admin user already exists');
        }
        
        // Create a demo user
        const [existingDemo] = await connection.execute(
            'SELECT id FROM users WHERE email = ?',
            ['demo@ringlessdrop.com']
        );
        
        if (existingDemo.length === 0) {
            console.log('👤 Creating demo user...');
            
            const demoPassword = await bcrypt.hash('demo123', 12);
            
            await connection.execute(`
                INSERT INTO users (name, email, password_hash, credits, is_admin) 
                VALUES (?, ?, ?, ?, ?)
            `, ['Demo User', 'demo@ringlessdrop.com', demoPassword, 500, false]);
            
            console.log('✅ Demo user created');
            console.log('📧 Demo login: demo@ringlessdrop.com');
            console.log('🔑 Demo password: demo123');
        }
        
        await connection.end();
        
        console.log('🎉 Database setup completed successfully!');
        console.log('🚀 Your Ringless Drop platform is ready!');
        console.log('');
        console.log('Next steps:');
        console.log('1. Visit your Heroku app URL');
        console.log('2. Login with admin credentials');
        console.log('3. Add your Slybroadcast username/password in Heroku settings');
        console.log('4. Start adding users and campaigns!');
        
    } catch (error) {
        console.error('❌ Database setup failed:', error);
        process.exit(1);
    }
}

// Run setup if this file is executed directly
if (require.main === module) {
    setupDatabase();
}

module.exports = setupDatabase;