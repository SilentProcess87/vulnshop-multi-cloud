import express from 'express';
import cors from 'cors';
import sqlite3 from 'sqlite3';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

// VULNERABILITY 1: Weak CORS configuration
app.use(cors({
  origin: '*', // Should be specific origins
  credentials: true
}));

// VULNERABILITY 2: No rate limiting on sensitive endpoints
app.use(express.json({ limit: '50mb' })); // Large payload allowed
app.use(express.urlencoded({ extended: true }));

// Serve static files
app.use(express.static(path.join(__dirname, 'public')));

// VULNERABILITY 3: Weak JWT secret
const JWT_SECRET = '123456'; // Weak secret

// Initialize SQLite database
const db = new sqlite3.Database('./ecommerce.db');

// Initialize database tables
db.serialize(() => {
  // Users table
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    email TEXT UNIQUE,
    password TEXT,
    role TEXT DEFAULT 'customer',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // Products table
  db.run(`CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    description TEXT,
    price REAL,
    stock INTEGER,
    image_url TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // Orders table
  db.run(`CREATE TABLE IF NOT EXISTS orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    total_amount REAL,
    status TEXT DEFAULT 'pending',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id)
  )`);

  // Order items table
  db.run(`CREATE TABLE IF NOT EXISTS order_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    order_id INTEGER,
    product_id INTEGER,
    quantity INTEGER,
    price REAL,
    FOREIGN KEY (order_id) REFERENCES orders (id),
    FOREIGN KEY (product_id) REFERENCES products (id)
  )`);

  // Reviews table
  db.run(`CREATE TABLE IF NOT EXISTS reviews (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    product_id INTEGER,
    user_id INTEGER,
    review TEXT,
    rating INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (product_id) REFERENCES products (id),
    FOREIGN KEY (user_id) REFERENCES users (id)
  )`);

  // Insert sample data
  db.run(`INSERT OR IGNORE INTO users (username, email, password, role) VALUES 
    ('admin', 'admin@shop.com', '$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'admin'),
    ('john_doe', 'john@example.com', '$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'customer')`);

  db.run(`INSERT OR IGNORE INTO products (name, description, price, stock, image_url) VALUES 
    ('Gaming Laptop', 'High-performance gaming laptop', 1299.99, 10, '/images/laptop.jpg'),
    ('Wireless Headphones', 'Noise-cancelling wireless headphones', 199.99, 25, '/images/headphones.jpg'),
    ('Smartphone', 'Latest smartphone with advanced features', 899.99, 15, '/images/phone.jpg'),
    ('Tablet', '10-inch tablet for productivity', 449.99, 20, '/images/tablet.jpg')`);
});

// VULNERABILITY 4: No authentication middleware validation
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  // VULNERABILITY 5: Not validating JWT properly
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(403).json({ error: 'Invalid token' });
  }
}

// VULNERABILITY 6: SQL Injection in search endpoint
app.get('/api/products/search', (req, res) => {
  const { q } = req.query;
  
  // Vulnerable SQL query - directly concatenating user input
  const query = `SELECT * FROM products WHERE name LIKE '%${q}%' OR description LIKE '%${q}%'`;
  
  db.all(query, (err, rows) => {
    if (err) {
      return res.status(500).json({ error: 'Database error: ' + err.message });
    }
    res.json(rows);
  });
});

// VULNERABILITY 7: Insecure Direct Object Reference (IDOR)
app.get('/api/orders/:id', (req, res) => {
  const { id } = req.params;
  
  // No authorization check - any user can access any order
  db.get('SELECT * FROM orders WHERE id = ?', [id], (err, row) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    if (!row) {
      return res.status(404).json({ error: 'Order not found' });
    }
    res.json(row);
  });
});

// VULNERABILITY 8: Mass assignment vulnerability
app.post('/api/users/register', (req, res) => {
  const { username, email, password, role } = req.body; // Role can be manipulated
  
  if (!username || !email || !password) {
    return res.status(400).json({ error: 'Username, email, and password are required' });
  }

  const hashedPassword = bcrypt.hashSync(password, 10);
  
  // Vulnerable - allows setting role directly
  db.run(
    'INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)',
    [username, email, hashedPassword, role || 'customer'],
    function(err) {
      if (err) {
        return res.status(400).json({ error: 'User already exists' });
      }
      res.json({ message: 'User created successfully', userId: this.lastID });
    }
  );
});

// Login endpoint
app.post('/api/users/login', (req, res) => {
  const { username, password } = req.body;
  
  db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
    if (err || !user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    if (!bcrypt.compareSync(password, user.password)) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const token = jwt.sign(
      { userId: user.id, username: user.username, role: user.role },
      JWT_SECRET,
      { expiresIn: '24h' }
    );
    
    res.json({ token, user: { id: user.id, username: user.username, role: user.role } });
  });
});

// Get all products
app.get('/api/products', (req, res) => {
  db.all('SELECT * FROM products', (err, rows) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json(rows);
  });
});

// VULNERABILITY 9: No input validation on product creation
app.post('/api/products', authenticateToken, (req, res) => {
  const { name, description, price, stock, image_url } = req.body;
  
  // No role check - any authenticated user can create products
  db.run(
    'INSERT INTO products (name, description, price, stock, image_url) VALUES (?, ?, ?, ?, ?)',
    [name, description, price, stock, image_url],
    function(err) {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      res.json({ message: 'Product created', productId: this.lastID });
    }
  );
});

// VULNERABILITY 10: Information disclosure in error messages
app.post('/api/orders', authenticateToken, (req, res) => {
  const { items } = req.body;
  const userId = req.user.userId;
  
  let totalAmount = 0;
  
  // Calculate total (vulnerable to race conditions)
  db.serialize(() => {
    db.run(
      'INSERT INTO orders (user_id, total_amount) VALUES (?, ?)',
      [userId, totalAmount],
      function(err) {
        if (err) {
          return res.status(500).json({ error: 'Database error: ' + err.message });
        }
        
        const orderId = this.lastID;
        
        items.forEach(item => {
          db.run(
            'INSERT INTO order_items (order_id, product_id, quantity, price) VALUES (?, ?, ?, ?)',
            [orderId, item.productId, item.quantity, item.price]
          );
          totalAmount += item.price * item.quantity;
        });
        
        db.run('UPDATE orders SET total_amount = ? WHERE id = ?', [totalAmount, orderId]);
        
        res.json({ message: 'Order created', orderId });
      }
    );
  });
});

// VULNERABILITY 11: No rate limiting on sensitive endpoints
app.get('/api/admin/users', authenticateToken, (req, res) => {
  // Weak role check
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  
  db.all('SELECT id, username, email, role, created_at FROM users', (err, rows) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json(rows);
  });
});

// VULNERABILITY 12: XSS vulnerability in comments/reviews
app.post('/api/products/:id/review', authenticateToken, (req, res) => {
  const { review } = req.body;
  const productId = req.params.id;
  
  // No sanitization of review content
  db.run(
    'INSERT INTO reviews (product_id, user_id, review) VALUES (?, ?, ?)',
    [productId, req.user.userId, review],
    function(err) {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      res.json({ message: 'Review added' });
    }
  );
});

// Serve the main page
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Health check endpoint for Azure APIM
app.get('/health', (req, res) => {
  res.json({ status: 'healthy', timestamp: new Date().toISOString() });
});

app.listen(PORT, () => {
  console.log(`Vulnerable e-commerce server running on port ${PORT}`);
  console.log(`Access the application at: http://localhost:${PORT}`);
}); 