import React, { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import { ShoppingBag, Shield, AlertTriangle } from 'lucide-react'
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
      {/* Security Warning Banner */}
      <div className="container">
        <div className="alert alert-warning">
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <AlertTriangle size={20} />
            <strong>Educational Purpose Only:</strong> This application contains intentional security vulnerabilities for learning purposes.
          </div>
        </div>
      </div>

      {/* Hero Section */}
      <section className="hero" style={{ 
        background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
        color: 'white',
        padding: '4rem 0',
        textAlign: 'center'
      }}>
        <div className="container">
          <h1 style={{ fontSize: '3rem', fontWeight: 'bold', marginBottom: '1rem' }}>
            Welcome to VulnShop
          </h1>
          <p style={{ fontSize: '1.3rem', marginBottom: '2rem', opacity: 0.9 }}>
            A deliberately vulnerable e-commerce application for security testing with Azure APIM
          </p>
          <div style={{ display: 'flex', gap: '1rem', justifyContent: 'center', flexWrap: 'wrap' }}>
            <Link to="/products" className="btn btn-primary" style={{ 
              fontSize: '1.1rem',
              padding: '1rem 2rem',
              background: 'rgba(255,255,255,0.2)',
              border: '2px solid white',
              color: 'white'
            }}>
              <ShoppingBag size={20} style={{ marginRight: '0.5rem' }} />
              Shop Now
            </Link>
            <Link to="/admin" className="btn btn-outline" style={{ 
              fontSize: '1.1rem',
              padding: '1rem 2rem',
              background: 'transparent',
              border: '2px solid white',
              color: 'white'
            }}>
              <Shield size={20} style={{ marginRight: '0.5rem' }} />
              Admin Panel
            </Link>
          </div>
        </div>
      </section>

      {/* Vulnerability Features */}
      <section style={{ padding: '4rem 0', background: 'white' }}>
        <div className="container">
          <div className="page-header">
            <h2 className="page-title" style={{ fontSize: '2.5rem' }}>Security Vulnerabilities</h2>
            <p className="page-subtitle">
              This application demonstrates common security vulnerabilities that Azure APIM can help protect against
            </p>
          </div>
          
          <div className="grid grid-3">
            <div className="card">
              <div className="card-body">
                <h3 style={{ color: '#dc3545', marginBottom: '1rem' }}>SQL/NoSQL Injection</h3>
                <p>Search functionality vulnerable to database injection attacks.</p>
                <p style={{ fontSize: '0.9rem', color: '#666', marginTop: '1rem' }}>
                  <strong>Test:</strong> Try searching for: <code>' OR '1'='1</code>
                </p>
              </div>
            </div>
            
            <div className="card">
              <div className="card-body">
                <h3 style={{ color: '#dc3545', marginBottom: '1rem' }}>IDOR</h3>
                <p>Insecure Direct Object References allow unauthorized access to orders.</p>
                <p style={{ fontSize: '0.9rem', color: '#666', marginTop: '1rem' }}>
                  <strong>Test:</strong> Access /api/orders/1, /api/orders/2 directly
                </p>
              </div>
            </div>
            
            <div className="card">
              <div className="card-body">
                <h3 style={{ color: '#dc3545', marginBottom: '1rem' }}>XSS</h3>
                <p>Cross-site scripting vulnerabilities in user reviews.</p>
                <p style={{ fontSize: '0.9rem', color: '#666', marginTop: '1rem' }}>
                  <strong>Test:</strong> Add review with: <code>&lt;script&gt;alert('XSS')&lt;/script&gt;</code>
                </p>
              </div>
            </div>
            
            <div className="card">
              <div className="card-body">
                <h3 style={{ color: '#dc3545', marginBottom: '1rem' }}>Weak CORS</h3>
                <p>Overly permissive CORS policy allows any origin.</p>
                <p style={{ fontSize: '0.9rem', color: '#666', marginTop: '1rem' }}>
                  <strong>Protected by:</strong> APIM CORS policies
                </p>
              </div>
            </div>
            
            <div className="card">
              <div className="card-body">
                <h3 style={{ color: '#dc3545', marginBottom: '1rem' }}>No Rate Limiting</h3>
                <p>API endpoints have no request rate limiting.</p>
                <p style={{ fontSize: '0.9rem', color: '#666', marginTop: '1rem' }}>
                  <strong>Protected by:</strong> APIM rate limiting policies
                </p>
              </div>
            </div>
            
            <div className="card">
              <div className="card-body">
                <h3 style={{ color: '#dc3545', marginBottom: '1rem' }}>Mass Assignment</h3>
                <p>User registration allows role manipulation.</p>
                <p style={{ fontSize: '0.9rem', color: '#666', marginTop: '1rem' }}>
                  <strong>Test:</strong> Register with "admin" role selected
                </p>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Featured Products */}
      <section style={{ padding: '4rem 0', background: '#f8f9fa' }}>
        <div className="container">
          <div className="page-header">
            <h2 className="page-title">Featured Products</h2>
            <p className="page-subtitle">Check out our latest offerings</p>
          </div>
          
          {loading ? (
            <div style={{ textAlign: 'center', padding: '2rem' }}>
              <div className="spinner"></div>
              <p>Loading products...</p>
            </div>
          ) : (
            <div className="grid grid-3">
              {featuredProducts.map((product) => (
                <div key={product._id} className="product-card">
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
                      to={`/products/${product._id}`}
                      className="btn btn-primary"
                      style={{ width: '100%', marginTop: '1rem' }}
                    >
                      View Details
                    </Link>
                  </div>
                </div>
              ))}
            </div>
          )}
          
          <div style={{ textAlign: 'center', marginTop: '2rem' }}>
            <Link to="/products" className="btn btn-outline">
              View All Products
            </Link>
          </div>
        </div>
      </section>

      {/* Default Credentials */}
      <section style={{ padding: '4rem 0', background: 'white' }}>
        <div className="container">
          <div className="page-header">
            <h2 className="page-title">Test Credentials</h2>
            <p className="page-subtitle">Use these default credentials for testing</p>
          </div>
          
          <div className="grid grid-2">
            <div className="card">
              <div className="card-header">
                <h3>Admin Account</h3>
              </div>
              <div className="card-body">
                <p><strong>Username:</strong> admin</p>
                <p><strong>Password:</strong> password</p>
                <p style={{ fontSize: '0.9rem', color: '#666', marginTop: '1rem' }}>
                  Access admin panel, create products, view all orders
                </p>
              </div>
            </div>
            
            <div className="card">
              <div className="card-header">
                <h3>Regular User</h3>
              </div>
              <div className="card-body">
                <p><strong>Username:</strong> john_doe</p>
                <p><strong>Password:</strong> password</p>
                <p style={{ fontSize: '0.9rem', color: '#666', marginTop: '1rem' }}>
                  Browse products, place orders, write reviews
                </p>
              </div>
            </div>
          </div>
        </div>
      </section>
    </div>
  )
}

export default HomePage 