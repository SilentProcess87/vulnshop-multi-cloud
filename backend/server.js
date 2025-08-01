import express from 'express';
import sqlite3 from 'sqlite3';
import { open } from 'sqlite';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import cors from 'cors';
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';
import fs from 'fs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3001;

// VULNERABILITY 1: Weak CORS configuration - allows all origins
app.use(cors({
  origin: '*', // Vulnerable: Should be specific domains
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// VULNERABILITY 2: No rate limiting - unlimited requests
app.use(express.json({ limit: '50mb' })); // VULNERABILITY 11: Large payload acceptance
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// VULNERABILITY 3: Weak JWT secret
const JWT_SECRET = process.env.JWT_SECRET || '123456'; // Vulnerable: Should be strong random secret

// SQLite database setup
let db;

async function initializeDatabase() {
  try {
    // Create database in the current directory (local to the host)
    const dbPath = path.join(process.cwd(), 'vulnshop.db');
    console.log('Database path:', dbPath);
    
    db = await open({
      filename: dbPath,
      driver: sqlite3.Database
    });

    // Create tables
    await db.exec(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT DEFAULT 'user' CHECK(role IN ('user', 'admin')),
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS products (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        description TEXT NOT NULL,
        price REAL NOT NULL,
        image TEXT NOT NULL,
        category TEXT NOT NULL,
        created_by INTEGER,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (created_by) REFERENCES users(id)
      );

      CREATE TABLE IF NOT EXISTS orders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        total REAL NOT NULL,
        status TEXT DEFAULT 'pending' CHECK(status IN ('pending', 'processing', 'shipped', 'delivered', 'cancelled')),
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
      );

      CREATE TABLE IF NOT EXISTS order_items (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        order_id INTEGER NOT NULL,
        product_id INTEGER NOT NULL,
        quantity INTEGER NOT NULL,
        price REAL NOT NULL,
        FOREIGN KEY (order_id) REFERENCES orders(id),
        FOREIGN KEY (product_id) REFERENCES products(id)
      );

      CREATE TABLE IF NOT EXISTS reviews (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        product_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        rating INTEGER NOT NULL CHECK(rating >= 1 AND rating <= 5),
        comment TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (product_id) REFERENCES products(id),
        FOREIGN KEY (user_id) REFERENCES users(id)
      );

      CREATE TABLE IF NOT EXISTS cart_items (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        product_id INTEGER NOT NULL,
        quantity INTEGER NOT NULL,
        added_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id),
        FOREIGN KEY (product_id) REFERENCES products(id),
        UNIQUE(user_id, product_id)
      );
    `);

    console.log('Database initialized successfully');
    return db;
  } catch (error) {
    console.error('Database initialization error:', error);
    throw error;
  }
}

// Initialize sample data
async function initializeData() {
  try {
    const userCount = await db.get('SELECT COUNT(*) as count FROM users');
    if (userCount.count > 0) {
      console.log('Data already exists, skipping initialization');
      return;
    }

    // Read and execute the seed SQL file
    const seedSql = fs.readFileSync(path.join(__dirname, 'seed.sql')).toString();
    await db.exec(seedSql);

    console.log('Database seeded successfully from seed.sql');
  } catch (error) {
    console.error('Error initializing data:', error);
  }
}

// Authentication middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ 
      error: 'Access token required',
      details: 'No token provided in Authorization header' // VULNERABILITY 7: Information disclosure
    });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ 
        error: 'Invalid token',
        details: err.message // VULNERABILITY 7: Information disclosure
      });
    }
    req.user = user;
    next();
  });
};

// VULNERABILITY 8: Missing authorization check for admin operations
const requireAdmin = (req, res, next) => {
  // VULNERABILITY 12: Weak role validation - only checks if role exists, not if it's actually admin
  if (!req.user || !req.user.role) {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
};

// Routes

// Register endpoint
app.post('/api/register', async (req, res) => {
  try {
    const { username, email, password, ...extraFields } = req.body;

    // VULNERABILITY 6: Mass assignment - accepts any additional fields
    const role = extraFields.role || 'user'; // Could be exploited to create admin users

    const hashedPassword = await bcrypt.hash(password, 10);

    const result = await db.run(
      'INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)',
      [username, email, hashedPassword, role]
    );

    const token = jwt.sign(
      { userId: result.lastID, username, role },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.status(201).json({
      message: 'User created successfully',
      token,
      user: { id: result.lastID, username, email, role }
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ 
      error: 'Registration failed',
      details: error.message // VULNERABILITY 7: Information disclosure
    });
  }
});

// Login endpoint
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    const user = await db.get('SELECT * FROM users WHERE username = ?', [username]);
    
    if (!user || !await bcrypt.compare(password, user.password)) {
      return res.status(401).json({ 
        error: 'Invalid credentials',
        details: 'Username or password is incorrect' // VULNERABILITY 7: Information disclosure
      });
    }

    const token = jwt.sign(
      { userId: user.id, username: user.username, role: user.role },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({
      message: 'Login successful',
      token,
      user: { id: user.id, username: user.username, email: user.email, role: user.role }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ 
      error: 'Login failed',
      details: error.message // VULNERABILITY 7: Information disclosure
    });
  }
});

// Get products endpoint
app.get('/api/products', async (req, res) => {
  try {
    const products = await db.all('SELECT * FROM products ORDER BY created_at DESC');
    res.json(products);
  } catch (error) {
    console.error('Products fetch error:', error);
    res.status(500).json({ 
      error: 'Failed to fetch products',
      details: error.message // VULNERABILITY 7: Information disclosure
    });
  }
});

// VULNERABILITY 4: SQL Injection in search
app.get('/api/products/search', async (req, res) => {
  try {
    const { q } = req.query;
    
    // Vulnerable SQL query - directly concatenating user input
    const query = `SELECT * FROM products WHERE name LIKE '%${q}%' OR description LIKE '%${q}%'`;
    
    const products = await db.all(query);
    res.json(products);
  } catch (error) {
    console.error('Search error:', error);
    res.status(500).json({ 
      error: 'Search failed',
      details: error.message, // VULNERABILITY 7: Information disclosure
      query: req.query // Additional information disclosure
    });
  }
});

// Get single product
app.get('/api/products/:id', async (req, res) => {
  try {
    const product = await db.get('SELECT * FROM products WHERE id = ?', [req.params.id]);
    
    if (!product) {
      return res.status(404).json({ error: 'Product not found' });
    }

    // Get reviews for this product
    const reviews = await db.all(`
      SELECT r.*, u.username 
      FROM reviews r 
      JOIN users u ON r.user_id = u.id 
      WHERE r.product_id = ?
      ORDER BY r.created_at DESC
    `, [req.params.id]);

    res.json({ ...product, reviews });
  } catch (error) {
    console.error('Product fetch error:', error);
    res.status(500).json({ 
      error: 'Failed to fetch product',
      details: error.message // VULNERABILITY 7: Information disclosure
    });
  }
});

// VULNERABILITY 8: Create product without proper authorization
app.post('/api/products', authenticateToken, async (req, res) => {
  try {
    const { name, description, price, image, category } = req.body;

    const result = await db.run(
      'INSERT INTO products (name, description, price, image, category, created_by) VALUES (?, ?, ?, ?, ?, ?)',
      [name, description, price, image, category, req.user.userId]
    );

    const product = await db.get('SELECT * FROM products WHERE id = ?', [result.lastID]);
    res.status(201).json(product);
  } catch (error) {
    console.error('Product creation error:', error);
    res.status(500).json({ 
      error: 'Failed to create product',
      details: error.message // VULNERABILITY 7: Information disclosure
    });
  }
});

// Create order endpoint
app.post('/api/orders', authenticateToken, async (req, res) => {
  try {
    const { items } = req.body;
    
    // Calculate total
    let total = 0;
    for (const item of items) {
      const product = await db.get('SELECT price FROM products WHERE id = ?', [item.productId]);
      total += product.price * item.quantity;
    }

    // VULNERABILITY 9: Race condition - no transaction isolation
    const orderResult = await db.run(
      'INSERT INTO orders (user_id, total) VALUES (?, ?)',
      [req.user.userId, total]
    );

    // Add order items
    for (const item of items) {
      const product = await db.get('SELECT price FROM products WHERE id = ?', [item.productId]);
      await db.run(
        'INSERT INTO order_items (order_id, product_id, quantity, price) VALUES (?, ?, ?, ?)',
        [orderResult.lastID, item.productId, item.quantity, product.price]
      );
    }

    const order = await db.get(`
      SELECT o.*, 
        GROUP_CONCAT(p.name || ' (x' || oi.quantity || ')') as items
      FROM orders o
      LEFT JOIN order_items oi ON o.id = oi.order_id
      LEFT JOIN products p ON oi.product_id = p.id
      WHERE o.id = ?
      GROUP BY o.id
    `, [orderResult.lastID]);

    res.status(201).json(order);
  } catch (error) {
    console.error('Order creation error:', error);
    res.status(500).json({ 
      error: 'Failed to create order',
      details: error.message // VULNERABILITY 7: Information disclosure
    });
  }
});

// VULNERABILITY 5: IDOR - Direct object reference without authorization
app.get('/api/orders/:id', authenticateToken, async (req, res) => {
  try {
    const order = await db.get(`
      SELECT o.*, u.username,
        GROUP_CONCAT(p.name || ' (x' || oi.quantity || ')') as items
      FROM orders o
      JOIN users u ON o.user_id = u.id
      LEFT JOIN order_items oi ON o.id = oi.order_id
      LEFT JOIN products p ON oi.product_id = p.id
      WHERE o.id = ?
      GROUP BY o.id
    `, [req.params.id]);

    if (!order) {
      return res.status(404).json({ error: 'Order not found' });
    }

    // Should check if order belongs to user, but doesn't (IDOR vulnerability)
    res.json(order);
  } catch (error) {
    console.error('Order fetch error:', error);
    res.status(500).json({ 
      error: 'Failed to fetch order',
      details: error.message // VULNERABILITY 7: Information disclosure
    });
  }
});

// Get user's orders
app.get('/api/orders', authenticateToken, async (req, res) => {
  try {
    const orders = await db.all(`
      SELECT o.*, 
        GROUP_CONCAT(p.name || ' (x' || oi.quantity || ')') as items
      FROM orders o
      LEFT JOIN order_items oi ON o.id = oi.order_id
      LEFT JOIN products p ON oi.product_id = p.id
      WHERE o.user_id = ?
      GROUP BY o.id
      ORDER BY o.created_at DESC
    `, [req.user.userId]);

    res.json(orders);
  } catch (error) {
    console.error('Orders fetch error:', error);
    res.status(500).json({ 
      error: 'Failed to fetch orders',
      details: error.message // VULNERABILITY 7: Information disclosure
    });
  }
});

// VULNERABILITY 10: XSS in reviews - no input sanitization
app.post('/api/products/:id/reviews', authenticateToken, async (req, res) => {
  try {
    const { rating, comment } = req.body;
    const productId = req.params.id;

    const result = await db.run(
      'INSERT INTO reviews (product_id, user_id, rating, comment) VALUES (?, ?, ?, ?)',
      [productId, req.user.userId, rating, comment] // No sanitization of comment
    );

    const review = await db.get(`
      SELECT r.*, u.username 
      FROM reviews r 
      JOIN users u ON r.user_id = u.id 
      WHERE r.id = ?
    `, [result.lastID]);

    res.status(201).json(review);
  } catch (error) {
    console.error('Review creation error:', error);
    res.status(500).json({ 
      error: 'Failed to create review',
      details: error.message // VULNERABILITY 7: Information disclosure
    });
  }
});

// Admin routes (with weak authorization)
app.get('/api/admin/users', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const users = await db.all('SELECT id, username, email, role, created_at FROM users ORDER BY created_at DESC');
    res.json(users);
  } catch (error) {
    console.error('Users fetch error:', error);
    res.status(500).json({ 
      error: 'Failed to fetch users',
      details: error.message // VULNERABILITY 7: Information disclosure
    });
  }
});

app.get('/api/admin/orders', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const orders = await db.all(`
      SELECT o.*, u.username,
        GROUP_CONCAT(p.name || ' (x' || oi.quantity || ')') as items
      FROM orders o
      JOIN users u ON o.user_id = u.id
      LEFT JOIN order_items oi ON o.id = oi.order_id
      LEFT JOIN products p ON oi.product_id = p.id
      GROUP BY o.id
      ORDER BY o.created_at DESC
    `);

    res.json(orders);
  } catch (error) {
    console.error('Admin orders fetch error:', error);
    res.status(500).json({ 
      error: 'Failed to fetch orders',
      details: error.message // VULNERABILITY 7: Information disclosure
    });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ 
    error: 'Internal server error',
    details: err.message, // VULNERABILITY 7: Information disclosure
    stack: err.stack // Additional vulnerability - stack trace exposure
  });
});

// NEW: Public APIs without authentication that expose sensitive data

// VULNERABILITY: Exposed user data endpoint without authentication
app.get('/api/public/users', async (req, res) => {
  try {
    const { page = 1, limit = 10 } = req.query;
    const offset = (page - 1) * limit;

    const users = await db.all(`
      SELECT id, username, email, role, created_at 
      FROM users 
      ORDER BY created_at DESC
      LIMIT ? OFFSET ?
    `, [limit, offset]);
    
    const totalUsers = await db.get('SELECT COUNT(*) as count FROM users');

    res.json({
      message: 'Public user listing - paginated',
      page: parseInt(page),
      limit: parseInt(limit),
      totalPages: Math.ceil(totalUsers.count / limit),
      totalUsers: totalUsers.count,
      users: users
    });
  } catch (error) {
    console.error('Public users fetch error:', error);
    res.status(500).json({ 
      error: 'Failed to fetch users',
      details: error.message,
      stack: error.stack
    });
  }
});

// VULNERABILITY: Exposed system information
app.get('/api/public/system-info', (req, res) => {
  res.json({
    message: 'System information endpoint - publicly accessible',
    system: {
      node_version: process.version,
      platform: process.platform,
      memory: process.memoryUsage(),
      uptime: process.uptime(),
      env: process.env, // CRITICAL: Exposes all environment variables
      cwd: process.cwd(),
      pid: process.pid
    }
  });
});

// VULNERABILITY: Database schema exposure
app.get('/api/public/db-schema', async (req, res) => {
  try {
    const schema = await db.all("SELECT sql FROM sqlite_master WHERE type='table'");
    res.json({
      message: 'Database schema - publicly accessible',
      tables: schema
    });
  } catch (error) {
    res.status(500).json({ 
      error: 'Failed to fetch schema',
      details: error.message 
    });
  }
});

// VULNERABILITY: User search without authentication (with SQL injection)
app.get('/api/public/user-search', async (req, res) => {
  try {
    const { username, email } = req.query;
    let query = 'SELECT * FROM users WHERE 1=1';
    
    if (username) {
      query += ` AND username LIKE '%${username}%'`; // SQL Injection vulnerability
    }
    if (email) {
      query += ` AND email LIKE '%${email}%'`; // SQL Injection vulnerability
    }
    
    const users = await db.all(query);
    res.json({
      message: 'User search - no authentication required',
      query: query,
      results: users
    });
  } catch (error) {
    res.status(500).json({ 
      error: 'Search failed',
      details: error.message,
      query: req.query
    });
  }
});

// VULNERABILITY: Order details exposure without proper authentication
app.get('/api/public/recent-orders', async (req, res) => {
  try {
    const orders = await db.all(`
      SELECT o.*, u.username, u.email,
        GROUP_CONCAT(p.name || ' (x' || oi.quantity || ')') as items
      FROM orders o
      JOIN users u ON o.user_id = u.id
      LEFT JOIN order_items oi ON o.id = oi.order_id
      LEFT JOIN products p ON oi.product_id = p.id
      GROUP BY o.id
      ORDER BY o.created_at DESC
      LIMIT 50
    `);

    res.json({
      message: 'Recent orders - publicly accessible',
      count: orders.length,
      orders: orders
    });
  } catch (error) {
    res.status(500).json({ 
      error: 'Failed to fetch orders',
      details: error.message 
    });
  }
});

// VULNERABILITY: Config endpoint exposing sensitive configuration
app.get('/api/public/config', (req, res) => {
  res.json({
    message: 'Application configuration - publicly accessible',
    config: {
      jwt_secret: JWT_SECRET, // CRITICAL: Exposes JWT secret
      database_path: path.join(process.cwd(), 'vulnshop.db'),
      cors_origin: '*',
      rate_limit: 'disabled',
      authentication: {
        enabled: true,
        type: 'JWT',
        expiry: '24h'
      },
      features: {
        registration_open: true,
        allow_admin_creation: true,
        debug_mode: true
      }
    }
  });
});

// VULNERABILITY: Debug endpoint with sensitive information
app.get('/api/public/debug', async (req, res) => {
  try {
    const userCount = await db.get('SELECT COUNT(*) as count FROM users');
    const productCount = await db.get('SELECT COUNT(*) as count FROM products');
    const orderCount = await db.get('SELECT COUNT(*) as count FROM orders');
    
    res.json({
      message: 'Debug information - publicly accessible',
      stats: {
        users: userCount.count,
        products: productCount.count,
        orders: orderCount.count
      },
      routes: app._router.stack
        .filter(r => r.route)
        .map(r => ({
          path: r.route.path,
          methods: Object.keys(r.route.methods)
        })),
      middleware: app._router.stack
        .filter(r => r.name)
        .map(r => r.name)
    });
  } catch (error) {
    res.status(500).json({ 
      error: 'Debug info failed',
      details: error.message 
    });
  }
});

// VULNERABILITY: File read endpoint (path traversal vulnerability)
app.get('/api/public/files', (req, res) => {
  const { path: filePath } = req.query;
  
  if (!filePath) {
    return res.status(400).json({ error: 'Path parameter required' });
  }
  
  try {
    // VULNERABILITY: No path sanitization
    const content = fs.readFileSync(filePath, 'utf8');
    res.json({
      message: 'File content - publicly accessible',
      path: filePath,
      content: content
    });
  } catch (error) {
    res.status(500).json({ 
      error: 'File read failed',
      details: error.message,
      path: filePath
    });
  }
});

// NEW: Additional authenticated endpoints with sensitive data

// Get all user sessions (admin only but weak check)
app.get('/api/admin/sessions', authenticateToken, requireAdmin, async (req, res) => {
  try {
    // In a real app, this would track active sessions
    const users = await db.all('SELECT * FROM users');
    const sessions = users.map(user => ({
      userId: user.id,
      username: user.username,
      email: user.email,
      lastActive: new Date().toISOString(),
      ipAddress: req.ip,
      userAgent: req.headers['user-agent']
    }));
    
    res.json({
      message: 'Active user sessions',
      count: sessions.length,
      sessions: sessions
    });
  } catch (error) {
    res.status(500).json({ 
      error: 'Failed to fetch sessions',
      details: error.message 
    });
  }
});

// Export user data (GDPR endpoint but insecure)
app.get('/api/users/:id/export', authenticateToken, async (req, res) => {
  try {
    // VULNERABILITY: No check if user can access this data
    const userId = req.params.id;
    
    const user = await db.get('SELECT * FROM users WHERE id = ?', [userId]);
    const orders = await db.all('SELECT * FROM orders WHERE user_id = ?', [userId]);
    const reviews = await db.all('SELECT * FROM reviews WHERE user_id = ?', [userId]);
    
    res.json({
      message: 'User data export',
      user: user,
      orders: orders,
      reviews: reviews,
      export_date: new Date().toISOString()
    });
  } catch (error) {
    res.status(500).json({ 
      error: 'Export failed',
      details: error.message 
    });
  }
});

// Analytics endpoint with business intelligence data
app.get('/api/analytics/revenue', authenticateToken, async (req, res) => {
  try {
    const revenue = await db.get('SELECT SUM(total) as total FROM orders');
    const topProducts = await db.all(`
      SELECT p.name, p.price, COUNT(oi.id) as sold, SUM(oi.quantity * oi.price) as revenue
      FROM products p
      JOIN order_items oi ON p.id = oi.product_id
      GROUP BY p.id
      ORDER BY revenue DESC
      LIMIT 10
    `);
    
    res.json({
      message: 'Revenue analytics',
      total_revenue: revenue.total,
      top_products: topProducts,
      period: 'all-time'
    });
  } catch (error) {
    res.status(500).json({ 
      error: 'Analytics failed',
      details: error.message 
    });
  }
});

// NEW: Cart management endpoints
// Get user's cart
app.get('/api/cart', authenticateToken, async (req, res) => {
  try {
    const cartItems = await db.all(`
      SELECT p.id, p.name, p.price, p.image, c.quantity 
      FROM cart_items c
      JOIN products p ON c.product_id = p.id
      WHERE c.user_id = ?
    `, [req.user.userId]);
    res.json(cartItems);
  } catch (error) {
    console.error('Cart fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch cart' });
  }
});

// Add item to cart
app.post('/api/cart', authenticateToken, async (req, res) => {
  try {
    const { productId, quantity } = req.body;
    
    // Use INSERT OR IGNORE and UPDATE to handle existing items
    await db.run(
      'INSERT INTO cart_items (user_id, product_id, quantity) VALUES (?, ?, ?) ON CONFLICT(user_id, product_id) DO UPDATE SET quantity = quantity + ?',
      [req.user.userId, productId, quantity, quantity]
    );

    res.status(201).json({ message: 'Item added to cart' });
  } catch (error) {
    console.error('Add to cart error:', error);
    res.status(500).json({ error: 'Failed to add item to cart' });
  }
});

// Remove item from cart
app.delete('/api/cart/items/:productId', authenticateToken, async (req, res) => {
  try {
    await db.run(
      'DELETE FROM cart_items WHERE user_id = ? AND product_id = ?',
      [req.user.userId, req.params.productId]
    );
    res.status(204).send();
  } catch (error) {
    console.error('Remove from cart error:', error);
    res.status(500).json({ error: 'Failed to remove item from cart' });
  }
});


// Start server
async function startServer() {
  try {
    await initializeDatabase();
    await initializeData();
    
    app.listen(PORT, '0.0.0.0', () => {
      console.log(`VulnShop backend running on port ${PORT}`);
      console.log('Database path:', path.join(process.cwd(), 'vulnshop.db'));
      console.log('\n=== SECURITY VULNERABILITIES ===');
      console.log('1. Weak CORS (allows all origins)');
      console.log('2. No rate limiting');
      console.log('3. Weak JWT secret');
      console.log('4. SQL Injection in search');
      console.log('5. IDOR in order access');
      console.log('6. Mass Assignment in registration');
      console.log('7. Information Disclosure in errors');
      console.log('8. Missing Authorization for product creation');
      console.log('9. Race Conditions in order processing');
      console.log('10. XSS in review system');
      console.log('11. Large payload acceptance');
      console.log('12. Privilege escalation through weak role validation');
      console.log('\n=== NEW PUBLIC ENDPOINTS (NO AUTH) ===');
      console.log('- /api/public/users - Exposes all user data');
      console.log('- /api/public/system-info - Exposes system information');
      console.log('- /api/public/db-schema - Exposes database schema');
      console.log('- /api/public/user-search - User search with SQL injection');
      console.log('- /api/public/recent-orders - Exposes order details');
      console.log('- /api/public/config - Exposes sensitive configuration');
      console.log('- /api/public/debug - Debug information');
              console.log('- /api/public/files - File read with path traversal');
        console.log('=====================================\n');
      });
  } catch (error) {
    console.error('Failed to start server:', error);
    process.exit(1);
  }
}

// API Discovery endpoint - makes all endpoints discoverable
app.get('/api/discovery', (req, res) => {
  const endpoints = [];
  
  // Extract all routes from Express
  app._router.stack.forEach(middleware => {
    if (middleware.route) {
      const methods = Object.keys(middleware.route.methods);
      endpoints.push({
        path: middleware.route.path,
        methods: methods,
        auth_required: middleware.route.path.includes('/public/') ? false : true,
        description: getEndpointDescription(middleware.route.path)
      });
    }
  });
  
  res.json({
    service: 'VulnShop API',
    version: '2.0.0',
    description: 'E-commerce API with intentional vulnerabilities for security testing',
    documentation: '/api/swagger',
    endpoints: endpoints,
    vulnerabilities: {
      'A01 - Broken Access Control': ['/api/admin/execute-command', '/api/orders/:id', '/api/users/:id/export'],
      'A02 - Cryptographic Failures': ['/api/admin/generate-hash', '/api/public/config'],
      'A03 - Injection (SQL)': ['/api/products/search', '/api/public/user-search', '/api/admin/search-users', '/api/admin/execute-sql'],
      'A04 - Insecure Design': ['/api/admin/execute-sql'],
      'A05 - Security Misconfiguration': ['/api/admin/read-file', '/api/public/files'],
      'A06 - Vulnerable Components (XXE)': ['/api/admin/process-xml'],
      'A07 - Authentication Failures': ['/api/admin/impersonate'],
      'A08 - Software Integrity Failures': ['/api/admin/load-preferences'],
      'A09 - Logging Failures': ['/api/admin/security-logs'],
      'A10 - SSRF': ['/api/admin/process-redirect'],
      'Mass Assignment': ['/api/register', '/api/admin/create-user'],
      'Information Disclosure': ['/api/public/users', '/api/public/system-info', '/api/admin/settings'],
      'XSS': ['/api/products/:id/reviews']
    },
    security_features: {
      'OWASP Top 10 Protection': 'Available via Azure APIM policies',
      'Rate Limiting': 'Configurable in APIM',
      'JWT Authentication': 'Required for protected endpoints',
      'CORS': 'Configured but permissive'
    }
  });
});

// Swagger/OpenAPI endpoint
app.get('/api/swagger', (req, res) => {
  const fs = require('fs');
  const swaggerPath = path.join(process.cwd(), 'apim-swagger.json');
  
  try {
    const swaggerDoc = JSON.parse(fs.readFileSync(swaggerPath, 'utf8'));
    res.json(swaggerDoc);
  } catch (error) {
    res.status(500).json({ error: 'Failed to load API documentation' });
  }
});

// ADMIN SETTINGS ENDPOINTS - ALL OWASP TOP 10 VULNERABILITIES FOR EDUCATION

// A01 - Broken Access Control: Admin command execution without proper checks
app.post('/api/admin/execute-command', authenticateToken, async (req, res) => {
  try {
    const { command } = req.body;
    
    // VULNERABILITY: No admin role check - any authenticated user can execute commands
    const allowedCommands = {
      'restart-server': 'Server restart initiated (simulated)',
      'delete-all-logs': 'All logs deleted (simulated)',
      'backup-database': 'Database backup started (simulated)',
      'reset-user-passwords': 'All user passwords reset (simulated)'
    };
    
    const result = allowedCommands[command] || 'Command not recognized';
    
    res.json({
      message: result,
      executedBy: req.user.username,
      timestamp: new Date().toISOString(),
      // VULNERABILITY: Information disclosure
      systemInfo: {
        nodeVersion: process.version,
        platform: process.platform,
        memory: process.memoryUsage()
      }
    });
  } catch (error) {
    res.status(500).json({ 
      error: 'Command execution failed',
      details: error.message,
      stack: error.stack // VULNERABILITY: Stack trace exposure
    });
  }
});

// A02 - Cryptographic Failures: Weak hashing algorithms
app.post('/api/admin/generate-hash', authenticateToken, async (req, res) => {
  try {
    const { password, method = 'md5' } = req.body;
    const crypto = require('crypto');
    
    let hash;
    switch (method) {
      case 'md5':
        // VULNERABILITY: MD5 is cryptographically broken
        hash = crypto.createHash('md5').update(password).digest('hex');
        break;
      case 'sha1':
        // VULNERABILITY: SHA1 is deprecated and weak
        hash = crypto.createHash('sha1').update(password).digest('hex');
        break;
      case 'plain':
        // VULNERABILITY: Plain text storage
        hash = password;
        break;
      default:
        hash = crypto.createHash('md5').update(password).digest('hex');
    }
    
    res.json({
      hash,
      method,
      warning: 'This hash method is insecure!',
      // VULNERABILITY: Expose original password in response
      originalPassword: password
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// A03 - Injection: SQL Injection in user search
app.get('/api/admin/search-users', authenticateToken, async (req, res) => {
  try {
    const { query } = req.query;
    
    // VULNERABILITY: Direct SQL injection - concatenating user input
    const sqlQuery = `SELECT * FROM users WHERE username LIKE '%${query}%' OR email LIKE '%${query}%'`;
    
    console.log('Executing SQL:', sqlQuery); // Log for educational purposes
    
    const users = await db.all(sqlQuery);
    
    res.json({
      users: users.map(user => ({
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role,
        // VULNERABILITY: Expose password hashes
        password: user.password,
        created_at: user.created_at
      })),
      query: sqlQuery, // VULNERABILITY: Expose SQL query
      count: users.length
    });
  } catch (error) {
    res.status(500).json({ 
      error: 'Search failed',
      details: error.message,
      sqlQuery: `SELECT * FROM users WHERE username LIKE '%${req.query.query}%'` // VULNERABILITY: Expose SQL in error
    });
  }
});

// A04 - Insecure Design: Direct SQL execution interface
app.post('/api/admin/execute-sql', authenticateToken, async (req, res) => {
  try {
    const { sql } = req.body;
    
    // VULNERABILITY: Allow direct SQL execution - extremely dangerous
    console.log('Admin SQL execution:', sql);
    
    let result;
    if (sql.toLowerCase().startsWith('select')) {
      result = await db.all(sql);
    } else {
      result = await db.run(sql);
    }
    
    res.json({
      message: 'SQL executed successfully',
      results: result,
      changes: result?.changes || 0,
      lastID: result?.lastID || null,
      executedSQL: sql // VULNERABILITY: Echo back the SQL
    });
  } catch (error) {
    res.status(500).json({ 
      error: 'SQL execution failed',
      details: error.message,
      sql: req.body.sql // VULNERABILITY: Expose failed SQL
    });
  }
});

// A05 - Security Misconfiguration: File reading with path traversal
app.get('/api/admin/read-file', authenticateToken, async (req, res) => {
  try {
    const { path: filePath } = req.query;
    const fs = require('fs');
    
    // VULNERABILITY: No path sanitization - path traversal attack
    console.log('Reading file:', filePath);
    
    const content = fs.readFileSync(filePath, 'utf8');
    
    res.json({
      content,
      path: filePath,
      size: content.length,
      // VULNERABILITY: Expose server information
      serverPath: process.cwd(),
      message: 'File read successfully'
    });
  } catch (error) {
    res.status(500).json({ 
      error: 'File reading failed',
      details: error.message,
      path: req.query.path, // VULNERABILITY: Expose attempted path
      serverInfo: {
        cwd: process.cwd(),
        platform: process.platform
      }
    });
  }
});

// A06 - Vulnerable Components: XML processing with XXE
app.post('/api/admin/process-xml', authenticateToken, async (req, res) => {
  try {
    const { xml, enableExternalEntities = false } = req.body;
    
    // VULNERABILITY: XML External Entity (XXE) processing
    // In a real scenario, this would use a vulnerable XML parser
    console.log('Processing XML with external entities:', enableExternalEntities);
    
    // Simulate XML processing (in reality, this would be vulnerable to XXE)
    const simulatedResult = {
      theme: 'dark',
      notifications: true,
      processedXML: xml,
      // VULNERABILITY: Simulate reading external entities
      externalData: enableExternalEntities ? 'file:///etc/passwd content would be here' : null
    };
    
    res.json({
      message: 'XML processed successfully',
      settings: simulatedResult,
      warning: 'XML processing with external entities is dangerous!',
      // VULNERABILITY: Expose original XML in response
      originalXML: xml
    });
  } catch (error) {
    res.status(500).json({ 
      error: 'XML processing failed',
      details: error.message 
    });
  }
});

// A07 - Authentication Failures: Session hijacking
app.post('/api/admin/impersonate', authenticateToken, async (req, res) => {
  try {
    const { sessionId } = req.body;
    
    // VULNERABILITY: No validation of session ownership
    // In a real app, this would hijack actual sessions
    const fakeUsers = [
      { sessionId: 'sess_123', username: 'john_doe', role: 'user' },
      { sessionId: 'sess_456', username: 'admin_user', role: 'admin' },
      { sessionId: 'sess_789', username: 'guest_user', role: 'guest' }
    ];
    
    const targetUser = fakeUsers.find(u => u.sessionId === sessionId) || 
                      { sessionId, username: 'unknown_user', role: 'user' };
    
    res.json({
      message: `Session hijack successful`,
      impersonatedUser: targetUser,
      originalUser: req.user.username,
      // VULNERABILITY: Expose session information
      allActiveSessions: fakeUsers,
      warning: 'Session impersonation is a serious security vulnerability!'
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// A08 - Software Integrity Failures: Unsafe deserialization
app.post('/api/admin/load-preferences', authenticateToken, async (req, res) => {
  try {
    const { serializedData, unsafe = false } = req.body;
    
    if (unsafe) {
      // VULNERABILITY: Unsafe deserialization
      console.log('WARNING: Unsafe deserialization enabled!');
      
      // Simulate unsafe deserialization (in reality, this could execute code)
      const preferences = JSON.parse(serializedData);
      
      // VULNERABILITY: Execute any functions in the deserialized data
      if (preferences.onLoad && typeof preferences.onLoad === 'string') {
        console.log('Executing onLoad function:', preferences.onLoad);
        // In reality: eval(preferences.onLoad) - EXTREMELY DANGEROUS
      }
      
      res.json({
        message: 'Preferences loaded with unsafe deserialization',
        preferences,
        warning: 'Unsafe deserialization can lead to remote code execution!',
        // VULNERABILITY: Expose deserialization process
        deserializationMethod: 'unsafe',
        originalData: serializedData
      });
    } else {
      const preferences = JSON.parse(serializedData);
      res.json({
        message: 'Preferences loaded safely',
        preferences
      });
    }
  } catch (error) {
    res.status(500).json({ 
      error: 'Preference loading failed',
      details: error.message,
      serializedData: req.body.serializedData // VULNERABILITY: Expose failed data
    });
  }
});

// A09 - Logging and Monitoring Failures: Clear logs without proper logging
app.delete('/api/admin/security-logs', authenticateToken, async (req, res) => {
  try {
    // VULNERABILITY: Critical action not properly logged
    // This should be logged as a security event, but isn't
    
    console.log(`User ${req.user.username} cleared security logs`); // Minimal logging
    
    res.json({
      message: 'Security logs cleared',
      clearedBy: req.user.username,
      timestamp: new Date().toISOString(),
      // VULNERABILITY: This critical action is not properly audited
      warning: 'This action should be properly logged and monitored!'
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// A10 - Server-Side Request Forgery (SSRF): URL processing
app.post('/api/admin/process-redirect', authenticateToken, async (req, res) => {
  try {
    const { url } = req.body;
    const https = require('https');
    const http = require('http');
    
    // VULNERABILITY: No URL validation - SSRF attack vector
    console.log('Processing redirect to:', url);
    
    // Simulate fetching the URL (SSRF vulnerability)
    if (url.startsWith('http://') || url.startsWith('https://')) {
      // VULNERABILITY: No validation of internal IPs or localhost
      const client = url.startsWith('https://') ? https : http;
      
      res.json({
        message: 'Redirect processed',
        originalUrl: url,
        finalUrl: url,
        // VULNERABILITY: Could expose internal services
        warning: 'SSRF vulnerability: Could access internal services!',
        internalIPs: [
          '127.0.0.1',
          '192.168.1.1',
          '10.0.0.1',
          'localhost'
        ],
        accessiblePorts: [22, 80, 443, 3000, 3001, 5432, 3306]
      });
    } else {
      res.json({
        message: 'Invalid URL format',
        providedUrl: url
      });
    }
  } catch (error) {
    res.status(500).json({ 
      error: 'Redirect processing failed',
      details: error.message,
      url: req.body.url // VULNERABILITY: Expose attempted URL
    });
  }
});

// Mass Assignment Vulnerability: Create user with elevated privileges
app.post('/api/admin/create-user', authenticateToken, async (req, res) => {
  try {
    // VULNERABILITY: Accept all fields from request body (mass assignment)
    const userData = req.body;
    
    // This should validate and sanitize input, but doesn't
    const hashedPassword = await bcrypt.hash(userData.password || 'defaultpass123', 10);
    
    const result = await db.run(
      `INSERT INTO users (username, email, password, role, created_at) VALUES (?, ?, ?, ?, ?)`,
      [
        userData.username,
        userData.email,
        hashedPassword,
        userData.role || 'user', // VULNERABILITY: Could set admin role
        new Date().toISOString()
      ]
    );
    
    res.json({
      message: 'User created successfully',
      userId: result.lastID,
      // VULNERABILITY: Echo back all submitted data
      submittedData: userData,
      warning: 'Mass assignment vulnerability: Any field can be set!'
    });
  } catch (error) {
    res.status(500).json({ 
      error: 'User creation failed',
      details: error.message,
      submittedData: req.body // VULNERABILITY: Expose all submitted data
    });
  }
});

// Admin settings endpoints
app.get('/api/admin/settings', authenticateToken, async (req, res) => {
  try {
    // VULNERABILITY: Expose sensitive configuration
    res.json({
      database: {
        type: 'SQLite',
        path: 'vulnshop.db',
        // VULNERABILITY: Expose connection string
        connectionString: 'sqlite:///vulnshop.db'
      },
      server: {
        port: PORT,
        environment: process.env.NODE_ENV || 'development',
        // VULNERABILITY: Expose environment variables
        envVars: process.env
      },
      security: {
        jwtSecret: JWT_SECRET, // VULNERABILITY: Expose JWT secret
        corsOrigin: '*',
        rateLimit: 'disabled'
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/admin/system-info', authenticateToken, async (req, res) => {
  try {
    res.json({
      hostname: require('os').hostname(),
      platform: process.platform,
      memory: process.memoryUsage(),
      uptime: process.uptime(),
      // VULNERABILITY: Expose system information
      version: process.version,
      arch: process.arch,
      env: process.env.NODE_ENV,
      database: path.join(process.cwd(), 'vulnshop.db')
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/admin/security-logs', authenticateToken, async (req, res) => {
  try {
    // Simulate security logs
    const logs = [
      { timestamp: new Date().toISOString(), event: 'Admin login successful', user: 'admin' },
      { timestamp: new Date(Date.now() - 60000).toISOString(), event: 'Failed login attempt', ip: '192.168.1.100' },
      { timestamp: new Date(Date.now() - 120000).toISOString(), event: 'Password change', user: 'john_doe' },
      { timestamp: new Date(Date.now() - 180000).toISOString(), event: 'Privilege escalation attempt', user: 'guest' }
    ];
    
    res.json({ logs });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Update endpoint descriptions to include new admin settings endpoints
function getEndpointDescription(path) {
  const descriptions = {
    '/api/public/users': 'Lists all users with sensitive data - NO AUTHENTICATION',
    '/api/public/system-info': 'Exposes system information including environment variables',
    '/api/public/db-schema': 'Returns complete database schema',
    '/api/public/user-search': 'Search users with SQL injection vulnerability',
    '/api/public/recent-orders': 'Shows recent orders with user information',
    '/api/public/config': 'Exposes application configuration including JWT secret',
    '/api/public/debug': 'Debug information including routes and middleware',
    '/api/public/files': 'File reader with path traversal vulnerability',
    '/api/products': 'Product catalog',
    '/api/products/search': 'Product search with SQL injection vulnerability',
    '/api/login': 'User authentication',
    '/api/register': 'User registration with mass assignment vulnerability',
    '/api/orders': 'Order management',
    '/api/orders/:id': 'Get specific order - IDOR vulnerability',
    '/api/users/:id/export': 'Export user data - broken access control',
    '/api/admin/users': 'Admin user management',
    '/api/admin/orders': 'Admin order management',
    '/api/admin/sessions': 'View active user sessions',
    '/api/admin/settings': 'Admin configuration settings - exposes sensitive data',
    '/api/admin/system-info': 'System information exposure',
    '/api/admin/security-logs': 'Security logging interface',
    '/api/admin/execute-command': 'Admin command execution - broken access control',
    '/api/admin/generate-hash': 'Weak cryptographic hash generation',
    '/api/admin/search-users': 'User search with SQL injection vulnerability',
    '/api/admin/execute-sql': 'Direct SQL execution interface - insecure design',
    '/api/admin/read-file': 'File reading with path traversal vulnerability',
    '/api/admin/process-xml': 'XML processing with XXE vulnerability',
    '/api/admin/impersonate': 'Session hijacking/impersonation',
    '/api/admin/load-preferences': 'Unsafe deserialization vulnerability',
    '/api/admin/process-redirect': 'SSRF vulnerability in URL processing',
    '/api/admin/create-user': 'User creation with mass assignment vulnerability',
    '/api/analytics/revenue': 'Business intelligence data',
    '/api/discovery': 'API discovery endpoint',
    '/api/swagger': 'OpenAPI documentation',
    '/api/admin/execute-command': 'Execute admin commands (dangerous)',
    '/api/admin/generate-hash': 'Generate password hashes with weak algorithms',
    '/api/admin/search-users': 'Search users with SQL injection vulnerability',
    '/api/admin/execute-sql': 'Execute arbitrary SQL commands (dangerous)',
    '/api/admin/read-file': 'Read server files with path traversal (dangerous)',
    '/api/admin/process-xml': 'Process XML with XXE vulnerability',
    '/api/admin/impersonate': 'Session hijacking (dangerous)',
    '/api/admin/load-preferences': 'Load preferences with unsafe deserialization',
    '/api/admin/security-logs': 'View security logs',
    '/api/admin/process-redirect': 'Process redirects with SSRF vulnerability',
    '/api/admin/create-user': 'Create user with elevated privileges (mass assignment)',
    '/api/admin/settings': 'View admin settings and configuration',
    '/api/admin/system-info': 'View system information',
    '/api/admin/security-logs': 'View security logs'
  };
  
  return descriptions[path] || 'API endpoint';
}

startServer();