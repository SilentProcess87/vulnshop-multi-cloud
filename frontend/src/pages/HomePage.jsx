import React, { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import { ShoppingBag, Shield, AlertTriangle, Lock, Bug, Search, Database, Globe, Zap } from 'lucide-react'
import { products } from '../services/api'

const HomePage = () => {
  const [featuredProducts, setFeaturedProducts] = useState([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const fetchFeaturedProducts = async () => {
      try {
        const response = await products.getAll()
        // Show first 3 products as featured
        setFeaturedProducts(response.data.slice(0, 3))
      } catch (error) {
        console.error('Error fetching products:', error)
      } finally {
        setLoading(false)
      }
    }

    fetchFeaturedProducts()
  }, [])

  return (
    <div className="page">
      {/* Hero Section */}
      <section className="hero" style={{ 
        background: 'linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%)',
        color: 'white',
        padding: '5rem 0',
        textAlign: 'center',
        position: 'relative'
      }}>
        <div className="container">
          <h1 style={{ 
            fontSize: '3.5rem', 
            fontWeight: '800', 
            marginBottom: '1.5rem',
            letterSpacing: '-0.02em',
            lineHeight: '1.1'
          }}>
            Welcome to VulnShop
          </h1>
          <p style={{ 
            fontSize: '1.5rem', 
            marginBottom: '3rem', 
            opacity: 0.95,
            maxWidth: '700px',
            margin: '0 auto 3rem',
            lineHeight: '1.6'
          }}>
            A deliberately vulnerable e-commerce platform designed for security testing and learning with Azure APIM
          </p>
          <div style={{ display: 'flex', gap: '1rem', justifyContent: 'center', flexWrap: 'wrap' }}>
            <Link to="/products" className="btn" style={{ 
              fontSize: '1.125rem',
              padding: '1rem 2.5rem',
              background: 'white',
              color: '#6366f1',
              fontWeight: '700',
              boxShadow: '0 4px 14px 0 rgba(0,0,0,0.1)'
            }}>
              <ShoppingBag size={20} />
              Explore Products
            </Link>
            <Link to="/admin" className="btn" style={{ 
              fontSize: '1.125rem',
              padding: '1rem 2.5rem',
              background: 'rgba(255,255,255,0.15)',
              backdropFilter: 'blur(10px)',
              border: '2px solid rgba(255,255,255,0.3)',
              color: 'white'
            }}>
              <Shield size={20} />
              Admin Dashboard
            </Link>
          </div>
        </div>
      </section>

      {/* Vulnerability Features */}
      <section style={{ padding: '5rem 0', background: 'white' }}>
        <div className="container">
          <div className="page-header">
            <h2 className="page-title" style={{ fontSize: '2.5rem', marginBottom: '1rem' }}>
              Security Vulnerabilities
            </h2>
            <p className="page-subtitle" style={{ fontSize: '1.125rem', color: '#64748b' }}>
              This application demonstrates common security vulnerabilities that Azure APIM can help protect against
            </p>
          </div>
          
          <div className="grid grid-3" style={{ gap: '2rem' }}>
            <div className="vulnerability-card">
              <div className="vulnerability-icon">
                <Database size={24} />
              </div>
              <h3>SQL/NoSQL Injection</h3>
              <p>Search functionality vulnerable to database injection attacks.</p>
              <code className="vulnerability-code">' OR '1'='1</code>
            </div>
            
            <div className="vulnerability-card">
              <div className="vulnerability-icon">
                <Lock size={24} />
              </div>
              <h3>IDOR Vulnerabilities</h3>
              <p>Insecure Direct Object References allow unauthorized access.</p>
              <code className="vulnerability-code">/api/orders/1</code>
            </div>
            
            <div className="vulnerability-card">
              <div className="vulnerability-icon">
                <Bug size={24} />
              </div>
              <h3>XSS Attacks</h3>
              <p>Cross-site scripting vulnerabilities in user inputs.</p>
              <code className="vulnerability-code">&lt;script&gt;alert('XSS')&lt;/script&gt;</code>
            </div>
            
            <div className="vulnerability-card">
              <div className="vulnerability-icon">
                <Globe size={24} />
              </div>
              <h3>Weak CORS Policy</h3>
              <p>Overly permissive CORS configuration allows any origin.</p>
              <code className="vulnerability-code">Access-Control-Allow-Origin: *</code>
            </div>
            
            <div className="vulnerability-card">
              <div className="vulnerability-icon">
                <Zap size={24} />
              </div>
              <h3>No Rate Limiting</h3>
              <p>API endpoints lack request rate limiting protection.</p>
              <code className="vulnerability-code">Unlimited requests/sec</code>
            </div>
            
            <div className="vulnerability-card">
              <div className="vulnerability-icon">
                <Shield size={24} />
              </div>
              <h3>Mass Assignment</h3>
              <p>User registration allows unauthorized role manipulation.</p>
              <code className="vulnerability-code">{`{"role": "admin"}`}</code>
            </div>
          </div>
        </div>
      </section>

      {/* Featured Products */}
      <section style={{ padding: '5rem 0', background: '#f8fafc' }}>
        <div className="container">
          <div className="page-header">
            <h2 className="page-title" style={{ fontSize: '2.5rem', marginBottom: '1rem' }}>Featured Products</h2>
            <p className="page-subtitle" style={{ fontSize: '1.125rem', color: '#64748b' }}>
              Explore our collection of intentionally vulnerable products
            </p>
          </div>
          
          {loading ? (
            <div style={{ textAlign: 'center', padding: '3rem' }}>
              <div className="spinner"></div>
              <p style={{ marginTop: '1rem', color: '#64748b' }}>Loading products...</p>
            </div>
          ) : (
            <div className="grid grid-3">
              {featuredProducts.map((product) => (
                <div key={product.id} className="product-card">
                  <img 
                    src={product.image} 
                    alt={product.name}
                    className="product-image"
                  />
                  <div className="product-info">
                    <h3 className="product-name">{product.name}</h3>
                    <p className="product-description">{product.description}</p>
                    <div className="product-price">${product.price}</div>
                    <Link 
                      to={`/products/${product.id}`}
                      className="btn btn-primary"
                      style={{ width: '100%', marginTop: 'auto' }}
                    >
                      View Details
                    </Link>
                  </div>
                </div>
              ))}
            </div>
          )}
          
          <div style={{ textAlign: 'center', marginTop: '3rem' }}>
            <Link to="/products" className="btn btn-outline" style={{ padding: '0.875rem 2rem' }}>
              View All Products
            </Link>
          </div>
        </div>
      </section>

      {/* Default Credentials */}
      <section style={{ padding: '5rem 0', background: 'white' }}>
        <div className="container">
          <div className="page-header">
            <h2 className="page-title" style={{ fontSize: '2.5rem', marginBottom: '1rem' }}>Test Credentials</h2>
            <p className="page-subtitle" style={{ fontSize: '1.125rem', color: '#64748b' }}>
              Use these default credentials for testing the application
            </p>
          </div>
          
          <div className="grid grid-2" style={{ maxWidth: '800px', margin: '0 auto' }}>
            <div className="credential-card">
              <div className="credential-icon admin">
                <Shield size={32} />
              </div>
              <h3>Admin Account</h3>
              <div className="credential-details">
                <p><strong>Username:</strong> <code>admin</code></p>
                <p><strong>Password:</strong> <code>admin123</code></p>
              </div>
              <p className="credential-desc">
                Full access to admin panel, user management, and all orders
              </p>
            </div>
            
            <div className="credential-card">
              <div className="credential-icon user">
                <ShoppingBag size={32} />
              </div>
              <h3>Regular User</h3>
              <div className="credential-details">
                <p><strong>Username:</strong> <code>testuser</code></p>
                <p><strong>Password:</strong> <code>user123</code></p>
              </div>
              <p className="credential-desc">
                Browse products, place orders, and write product reviews
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* CTA Section */}
      <section style={{ 
        padding: '5rem 0', 
        background: 'linear-gradient(135deg, #1e293b 0%, #334155 100%)',
        color: 'white',
        textAlign: 'center'
      }}>
        <div className="container">
          <h2 style={{ fontSize: '2.5rem', marginBottom: '1.5rem', fontWeight: '800' }}>
            Ready to Test Security Vulnerabilities?
          </h2>
          <p style={{ fontSize: '1.25rem', marginBottom: '2.5rem', opacity: 0.9, maxWidth: '600px', margin: '0 auto 2.5rem' }}>
            Explore our vulnerable e-commerce platform and learn how Azure APIM can protect your APIs
          </p>
          <Link to="/products" className="btn" style={{ 
            fontSize: '1.125rem',
            padding: '1rem 2.5rem',
            background: 'white',
            color: '#1e293b',
            fontWeight: '700'
          }}>
            Start Exploring
          </Link>
        </div>
      </section>
    </div>
  )
}

export default HomePage 