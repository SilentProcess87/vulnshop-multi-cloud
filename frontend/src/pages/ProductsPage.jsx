import React, { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import { Search, Plus, AlertTriangle } from 'lucide-react'
import { useAuth, useCart } from '../App'
import { products } from '../services/api'

const ProductsPage = () => {
  const [productsList, setProductsList] = useState([])
  const [loading, setLoading] = useState(true)
  const [searchQuery, setSearchQuery] = useState('')
  const [searching, setSearching] = useState(false)
  const [error, setError] = useState('')
  
  const { user } = useAuth()
  const { addToCart } = useCart()

  useEffect(() => {
    fetchProducts()
  }, [])

  const fetchProducts = async () => {
    try {
      setLoading(true)
      const response = await products.getAll()
      setProductsList(response.data)
    } catch (error) {
      setError('Failed to fetch products')
      console.error('Error fetching products:', error)
    } finally {
      setLoading(false)
    }
  }

  const handleSearch = async (e) => {
    e.preventDefault()
    if (!searchQuery.trim()) {
      fetchProducts()
      return
    }

    try {
      setSearching(true)
      setError('')
      
      // VULNERABILITY: Direct search without sanitization
      const response = await products.search(searchQuery)
      setProductsList(response.data)
    } catch (error) {
      setError(error.response?.data?.error || 'Search failed')
      console.error('Search error:', error)
    } finally {
      setSearching(false)
    }
  }

  const handleAddToCart = (product) => {
    addToCart(product)
    // Simple success feedback
    const button = document.querySelector(`#add-to-cart-${product._id}`)
    if (button) {
      const originalText = button.textContent
      button.textContent = 'Added!'
      button.style.background = '#28a745'
      setTimeout(() => {
        button.textContent = originalText
        button.style.background = ''
      }, 1000)
    }
  }

  const fillVulnerableSearch = (payload) => {
    setSearchQuery(payload)
  }

  return (
    <div className="page">
      <div className="container">
        <div className="page-header">
          <h1 className="page-title">Products</h1>
          <p className="page-subtitle">Browse our collection of products</p>
        </div>

        {/* Vulnerability Warning */}
        <div className="alert alert-warning">
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <AlertTriangle size={16} />
            <strong>NoSQL Injection Vulnerability:</strong> The search function is vulnerable to NoSQL injection attacks!
          </div>
        </div>

        {/* Search Bar */}
        <form onSubmit={handleSearch} className="search-bar">
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search products... (try vulnerable payloads)"
            className="search-input"
          />
          <button type="submit" className="search-button" disabled={searching}>
            <Search size={20} />
          </button>
        </form>

        {/* Vulnerability Test Buttons */}
        <div style={{ textAlign: 'center', marginBottom: '2rem' }}>
          <p style={{ fontSize: '0.9rem', color: '#666', marginBottom: '1rem' }}>
            <strong>Test NoSQL injection vulnerabilities:</strong>
          </p>
          <div style={{ display: 'flex', gap: '0.5rem', justifyContent: 'center', flexWrap: 'wrap' }}>
            <button
              onClick={() => fillVulnerableSearch('{"$ne": null}')}
              className="btn btn-secondary btn-small"
              style={{ fontSize: '0.8rem' }}
            >
              {'"$ne": null'}
            </button>
            <button
              onClick={() => fillVulnerableSearch('{"$regex": ".*"}')}
              className="btn btn-secondary btn-small"
              style={{ fontSize: '0.8rem' }}
            >
              {'"$regex": ".*"'}
            </button>
            <button
              onClick={() => fillVulnerableSearch('{"$where": "this.price > 0"}')}
              className="btn btn-secondary btn-small"
              style={{ fontSize: '0.8rem' }}
            >
              $where injection
            </button>
          </div>
        </div>

        {/* Add Product Button (if admin) */}
        {user?.role === 'admin' && (
          <div style={{ textAlign: 'center', marginBottom: '2rem' }}>
            <button
              onClick={() => {
                // Simple product creation for demo
                const name = prompt('Product name:')
                const description = prompt('Product description:')
                const price = prompt('Product price:')
                const image = prompt('Product image URL:') || 'https://via.placeholder.com/300x200?text=Product'
                const category = prompt('Product category:') || 'General'
                
                if (name && description && price) {
                  products.create({
                    name,
                    description,
                    price: parseFloat(price),
                    image,
                    category
                  }).then(() => {
                    fetchProducts()
                  }).catch(error => {
                    alert('Failed to create product: ' + (error.response?.data?.error || error.message))
                  })
                }
              }}
              className="btn btn-primary"
            >
              <Plus size={16} style={{ marginRight: '0.5rem' }} />
              Add Product
            </button>
          </div>
        )}

        {error && (
          <div className="alert alert-error">
            {error}
          </div>
        )}

        {/* Products Grid */}
        {loading ? (
          <div style={{ textAlign: 'center', padding: '2rem' }}>
            <div className="spinner"></div>
            <p>Loading products...</p>
          </div>
        ) : productsList.length === 0 ? (
          <div style={{ textAlign: 'center', padding: '2rem' }}>
            <p>No products found.</p>
          </div>
        ) : (
          <div className="grid grid-3">
            {productsList.map((product) => (
              <div key={product._id} className="product-card">
                <img 
                  src={product.image} 
                  alt={product.name}
                  className="product-image"
                  onError={(e) => {
                    e.target.src = 'https://via.placeholder.com/300x200?text=No+Image'
                  }}
                />
                <div className="product-info">
                  <h3 className="product-name">{product.name}</h3>
                  <p className="product-description">{product.description}</p>
                  <div className="product-price">${product.price}</div>
                  <p style={{ fontSize: '0.8rem', color: '#666', marginBottom: '1rem' }}>
                    Category: {product.category}
                  </p>
                  
                  <div style={{ display: 'flex', gap: '0.5rem' }}>
                    <Link 
                      to={`/products/${product._id}`}
                      className="btn btn-outline"
                      style={{ flex: 1 }}
                    >
                      View Details
                    </Link>
                    <button
                      id={`add-to-cart-${product._id}`}
                      onClick={() => handleAddToCart(product)}
                      className="btn btn-primary"
                      style={{ flex: 1 }}
                    >
                      Add to Cart
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}

        {/* NoSQL Injection Information */}
        <div className="card" style={{ marginTop: '3rem' }}>
          <div className="card-header">
            <h3>🔓 NoSQL Injection Vulnerability</h3>
          </div>
          <div className="card-body">
            <p style={{ marginBottom: '1rem' }}>
              This search functionality demonstrates <strong>NoSQL injection vulnerabilities</strong> where malicious queries can be executed against the MongoDB database.
            </p>
            <p style={{ marginBottom: '1rem' }}>
              <strong>Common NoSQL injection payloads:</strong>
            </p>
            <ul style={{ marginBottom: '1rem', paddingLeft: '1.5rem' }}>
              <li><code>{`{"$ne": null}`}</code> - Returns all documents</li>
              <li><code>{`{"$regex": ".*"}`}</code> - Pattern matching all strings</li>
              <li><code>{`{"$where": "this.price > 0"}`}</code> - JavaScript execution</li>
              <li><code>{`{"$or": [{"price": {"$gt": 0}}, {"name": ""}]}`}</code> - OR conditions</li>
            </ul>
            <p style={{ fontSize: '0.9rem', color: '#666' }}>
              <strong>How to fix:</strong> Sanitize user input, use parameterized queries, validate data types, and implement input validation.
            </p>
          </div>
        </div>
      </div>
    </div>
  )
}

export default ProductsPage 