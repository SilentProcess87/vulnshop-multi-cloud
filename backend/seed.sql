-- Pre-configured seed data for VulnShop

-- Users
-- 1 admin, 1 test user, and 18 fake users
-- Passwords are bcrypt hashes
INSERT INTO "users" ("username", "email", "password", "role") VALUES
('admin', 'admin@vulnshop.com', '$2a$12$4YX.az.p2e145S14pX5wzOa5A/L2jL0c5yS4f2y/E.q0m9E5b1g1W', 'admin'),      -- admin123
('testuser', 'user@vulnshop.com', '$2a$12$XbV9V6/X9L1a2n3n4O/n5u8y2x7Y.j9K.z5f.L3p9q9r1e.w6/O.q', 'user'),  -- user123
('j.doe', 'jane.doe@example.com', '$2a$12$D/i1e.x0b.X5e/p4o/n6f.u8v.z7c.J6f.L9v.B1q.R8e.T9g.C3e', 'user'),      -- password123
('e.smith', 'eric.smith@example.com', '$2a$12$D/i1e.x0b.X5e/p4o/n6f.u8v.z7c.J6f.L9v.B1q.R8e.T9g.C3e', 'user'),
('s.jones', 'susan.jones@example.com', '$2a$12$D/i1e.x0b.X5e/p4o/n6f.u8v.z7c.J6f.L9v.B1q.R8e.T9g.C3e', 'user'),
('m.brown', 'mike.brown@example.com', '$2a$12$D/i1e.x0b.X5e/p4o/n6f.u8v.z7c.J6f.L9v.B1q.R8e.T9g.C3e', 'user'),
('a.davis', 'anna.davis@example.com', '$2a$12$D/i1e.x0b.X5e/p4o/n6f.u8v.z7c.J6f.L9v.B1q.R8e.T9g.C3e', 'user'),
('c.wilson', 'chris.wilson@example.com', '$2a$12$D/i1e.x0b.X5e/p4o/n6f.u8v.z7c.J6f.L9v.B1q.R8e.T9g.C3e', 'user'),
('k.taylor', 'karen.taylor@example.com', '$2a$12$D/i1e.x0b.X5e/p4o/n6f.u8v.z7c.J6f.L9v.B1q.R8e.T9g.C3e', 'user'),
('b.moore', 'brian.moore@example.com', '$2a$12$D/i1e.x0b.X5e/p4o/n6f.u8v.z7c.J6f.L9v.B1q.R8e.T9g.C3e', 'user'),
('l.white', 'linda.white@example.com', '$2a$12$D/i1e.x0b.X5e/p4o/n6f.u8v.z7c.J6f.L9v.B1q.R8e.T9g.C3e', 'user'),
('t.harris', 'tom.harris@example.com', '$2a$12$D/i1e.x0b.X5e/p4o/n6f.u8v.z7c.J6f.L9v.B1q.R8e.T9g.C3e', 'user'),
('p.martin', 'paula.martin@example.com', '$2a$12$D/i1e.x0b.X5e/p4o/n6f.u8v.z7c.J6f.L9v.B1q.R8e.T9g.C3e', 'user'),
('d.jackson', 'david.jackson@example.com', '$2a$12$D/i1e.x0b.X5e/p4o/n6f.u8v.z7c.J6f.L9v.B1q.R8e.T9g.C3e', 'user'),
('g.lee', 'gary.lee@example.com', '$2a$12$D/i1e.x0b.X5e/p4o/n6f.u8v.z7c.J6f.L9v.B1q.R8e.T9g.C3e', 'user'),
('n.lewis', 'nancy.lewis@example.com', '$2a$12$D/i1e.x0b.X5e/p4o/n6f.u8v.z7c.J6f.L9v.B1q.R8e.T9g.C3e', 'user'),
('s.clark', 'steve.clark@example.com', '$2a$12$D/i1e.x0b.X5e/p4o/n6f.u8v.z7c.J6f.L9v.B1q.R8e.T9g.C3e', 'user'),
('j.robinson', 'jessica.robinson@example.com', '$2a$12$D/i1e.x0b.X5e/p4o/n6f.u8v.z7c.J6f.L9v.B1q.R8e.T9g.C3e', 'user'),
('r.walker', 'robert.walker@example.com', '$2a$12$D/i1e.x0b.X5e/p4o/n6f.u8v.z7c.J6f.L9v.B1q.R8e.T9g.C3e', 'user'),
('p.young', 'patricia.young@example.com', '$2a$12$D/i1e.x0b.X5e/p4o/n6f.u8v.z7c.J6f.L9v.B1q.R8e.T9g.C3e', 'user');

-- Products
INSERT INTO "products" ("name", "description", "price", "image", "category", "created_by") VALUES
('Vulnerable Laptop', 'High-performance laptop with known security vulnerabilities for penetration testing', 999.99, 'https://images.unsplash.com/photo-1496181133206-80ce9b88a853?w=500&q=80', 'Laptops', 1),
('Insecure Router', 'Network router with default credentials and open ports', 149.99, 'https://images.unsplash.com/photo-1606904825846-647eb07f5be2?w=500&q=80', 'Networking', 1),
('Pwned Phone', 'Smartphone with pre-installed vulnerable apps and weak encryption', 599.99, 'https://images.unsplash.com/photo-1511707171634-5f897ff02aa9?w=500&q=80', 'Phones', 1),
('Hackable Smartwatch', 'Wearable device with exploitable Bluetooth vulnerabilities', 299.99, 'https://images.unsplash.com/photo-1523275335684-37898b6baf30?w=500&q=80', 'Wearables', 1),
('Leaky Database Server', 'Server hardware optimized for demonstrating SQL injection attacks', 1999.99, 'https://images.unsplash.com/photo-1558494949-ef010cbdcc31?w=500&q=80', 'Servers', 1),
('Vulnerable Webcam', 'IP camera with hardcoded credentials and no encryption', 89.99, 'https://images.unsplash.com/photo-1567653418876-5bb0e566e1c2?w=500&q=80', 'Security', 1),
('Exploitable Smart Speaker', 'Voice assistant with weak authentication protocols', 129.99, 'https://images.unsplash.com/photo-1543512214-318c7553f230?w=500&q=80', 'Smart Home', 1),
('Insecure USB Drive', '32GB USB drive with disabled write protection and autorun enabled', 39.99, 'https://images.unsplash.com/photo-1597872200969-2b65d56bd16b?w=500&q=80', 'Storage', 1),
('Hackable Drone', 'Quadcopter with unencrypted control signals and open telemetry', 899.99, 'https://images.unsplash.com/photo-1579829366248-204fe8413f31?w=500&q=80', 'Drones', 1),
('Vulnerable Smart Lock', 'Bluetooth door lock with replay attack vulnerabilities', 199.99, 'https://images.unsplash.com/photo-1558618666-fcd25c85cd64?w=500&q=80', 'Smart Home', 1); 