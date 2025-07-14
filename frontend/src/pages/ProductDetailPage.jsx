import React, { useState, useEffect } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { Star, ShoppingCart, AlertTriangle } from 'lucide-react'
import { useAuth, useCart } from '../App'
import { products, reviews } from '../services/api'

const ProductDetailPage = () => {
  const { id } = useParams()
  const navigate = useNavigate()
  const { user } = useAuth()
  const { addToCart } = useCart()
  
  const [product, setProduct] = useState(null)
  const [productReviews, setProductReviews] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [reviewForm, setReviewForm] = useState({
    rating: 5,
    comment: ''
  })
  const [submittingReview, setSubmittingReview] = useState(false)

  useEffect(() => {
    fetchProductDetails()
  }, [id])

  const fetchProductDetails = async () => {
    try {
      setLoading(true)
      const productResponse = await products.getAll()
      const foundProduct = productResponse.data.find(p => p._id === id)
      
      if (!foundProduct) {
        setError('Product not found')
        return
      }
      
      setProduct(foundProduct)
      
      // Fetch reviews
      const reviewsResponse = await reviews.getByProduct(id)
      setProductReviews(reviewsResponse.data)
    } catch (error) {
      setError('Failed to load product details')
      console.error('Error fetching product:', error)
    } finally {
      setLoading(false)
    }
  }

  const handleAddToCart = () => {
    addToCart(product)
    // Simple success feedback
    const button = document.querySelector('#add-to-cart-btn')
    if (button) {
      const originalText = button.textContent
      button.textContent = 'Added to Cart!'
      button.style.background = '#28a745'
      setTimeout(() => {
        button.textContent = originalText
        button.style.background = ''
      }, 2000)
    }
  }

  const handleReviewSubmit = async (e) => {
    e.preventDefault()
    
    if (!user) {
      navigate('/login')
      return
    }

    try {
      setSubmittingReview(true)
      
      await reviews.create({
        productId: id,
        rating: reviewForm.rating,
        comment: reviewForm.comment // VULNERABILITY: XSS - raw comment sent without sanitization
      })
      
      setReviewForm({ rating: 5, comment: '' })
      fetchProductDetails() // Refresh reviews
    } catch (error) {
      setError(error.response?.data?.error || 'Failed to submit review')
    } finally {
      setSubmittingReview(false)
    }
  }

  const renderStars = (rating) => {
    return Array.from({ length: 5 }, (_, index) => (
      <Star
        key={index}
        size={16}
        fill={index < rating ? '#ffc107' : 'none'}
        color={index < rating ? '#ffc107' : '#ddd'}
      />
    ))
  }

  if (loading) {
    return (
      <div className="page">
        <div className="container">
          <div style={{ textAlign: 'center', padding: '2rem' }}>
            <div className="spinner"></div>
            <p>Loading product...</p>
          </div>
        </div>
      </div>
    )
  }

  if (error || !product) {
    return (
      <div className="page">
        <div className="container">
          <div className="alert alert-error">
            {error || 'Product not found'}
          </div>
          <button onClick={() => navigate('/products')} className="btn btn-primary">
            Back to Products
          </button>
        </div>
      </div>
    )
  }

  return (
    <div className="page">
      <div className="container">
        {/* Product Details */}
        <div className="grid grid-2" style={{ gap: '3rem', marginBottom: '3rem' }}>
          <div>
            <img
              src={product.image}
              alt={product.name}
              style={{
                width: '100%',
                height: '400px',
                objectFit: 'cover',
                borderRadius: '12px'
              }}
              onError={(e) => {
                e.target.src = 'https://via.placeholder.com/400x400?text=No+Image'
              }}
            />
          </div>
          
          <div>
            <h1 style={{ fontSize: '2.5rem', marginBottom: '1rem' }}>{product.name}</h1>
            <div style={{ fontSize: '2rem', color: '#007bff', fontWeight: 'bold', marginBottom: '1rem' }}>
              ${product.price}
            </div>
            <p style={{ fontSize: '1.1rem', lineHeight: '1.6', marginBottom: '2rem', color: '#666' }}>
              {product.description}
            </p>
            <p style={{ marginBottom: '2rem' }}>
              <strong>Category:</strong> {product.category}
            </p>
            
            <button
              id="add-to-cart-btn"
              onClick={handleAddToCart}
              className="btn btn-primary"
              style={{ fontSize: '1.2rem', padding: '1rem 2rem' }}
            >
              <ShoppingCart size={20} style={{ marginRight: '0.5rem' }} />
              Add to Cart
            </button>
          </div>
        </div>

        {/* Reviews Section */}
        <div className="card">
          <div className="card-header">
            <h3>Customer Reviews ({productReviews.length})</h3>
          </div>
          <div className="card-body">
            {/* XSS Vulnerability Warning */}
            <div className="alert alert-warning" style={{ marginBottom: '2rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <AlertTriangle size={16} />
                <strong>XSS Vulnerability:</strong> User reviews are displayed without sanitization!
              </div>
            </div>

            {/* Add Review Form */}
            {user ? (
              <form onSubmit={handleReviewSubmit} style={{ marginBottom: '2rem', padding: '1.5rem', background: '#f8f9fa', borderRadius: '8px' }}>
                <h4 style={{ marginBottom: '1rem' }}>Write a Review</h4>
                
                <div className="form-group">
                  <label className="form-label">Rating</label>
                  <select
                    value={reviewForm.rating}
                    onChange={(e) => setReviewForm({ ...reviewForm, rating: parseInt(e.target.value) })}
                    className="form-select"
                    style={{ width: 'auto' }}
                  >
                    <option value={5}>5 Stars - Excellent</option>
                    <option value={4}>4 Stars - Good</option>
                    <option value={3}>3 Stars - Average</option>
                    <option value={2}>2 Stars - Poor</option>
                    <option value={1}>1 Star - Terrible</option>
                  </select>
                </div>
                
                <div className="form-group">
                  <label className="form-label">
                    Comment 
                    <span style={{ fontSize: '0.8rem', color: '#dc3545', marginLeft: '0.5rem' }}>
                      (⚠️ XSS Vulnerable - try: {`<script>alert('XSS')</script>`})
                    </span>
                  </label>
                  <textarea
                    value={reviewForm.comment}
                    onChange={(e) => setReviewForm({ ...reviewForm, comment: e.target.value })}
                    placeholder="Share your experience with this product..."
                    className="form-input"
                    rows="4"
                    required
                  />
                  <small style={{ color: '#666', fontSize: '0.8rem' }}>
                    Try entering HTML/JavaScript code to test the XSS vulnerability!
                  </small>
                </div>
                
                <button
                  type="submit"
                  className="btn btn-primary"
                  disabled={submittingReview}
                >
                  {submittingReview ? 'Submitting...' : 'Submit Review'}
                </button>
              </form>
            ) : (
              <div className="alert alert-info" style={{ marginBottom: '2rem' }}>
                <a href="/login" style={{ color: '#007bff' }}>Sign in</a> to write a review.
              </div>
            )}

            {/* Reviews List */}
            {productReviews.length === 0 ? (
              <p style={{ textAlign: 'center', color: '#666', padding: '2rem' }}>
                No reviews yet. Be the first to review this product!
              </p>
            ) : (
              <div>
                {productReviews.map((review) => (
                  <div
                    key={review._id}
                    style={{
                      borderBottom: '1px solid #e9ecef',
                      padding: '1.5rem 0',
                      marginBottom: '1rem'
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', marginBottom: '1rem' }}>
                      <strong>{review.userId?.username || 'Anonymous'}</strong>
                      <div style={{ display: 'flex', gap: '0.2rem' }}>
                        {renderStars(review.rating)}
                      </div>
                      <span style={{ color: '#666', fontSize: '0.9rem' }}>
                        {new Date(review.createdAt).toLocaleDateString()}
                      </span>
                    </div>
                    
                    {/* VULNERABILITY: XSS - Displaying raw HTML content */}
                    <div
                      style={{ lineHeight: '1.6' }}
                      dangerouslySetInnerHTML={{ __html: review.comment }}
                    />
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* XSS Vulnerability Explanation */}
        <div className="card" style={{ marginTop: '2rem' }}>
          <div className="card-header">
            <h3>🔓 Cross-Site Scripting (XSS) Vulnerability</h3>
          </div>
          <div className="card-body">
            <p style={{ marginBottom: '1rem' }}>
              This review system demonstrates an <strong>XSS vulnerability</strong> where user input is displayed without proper sanitization.
            </p>
            <p style={{ marginBottom: '1rem' }}>
              <strong>Test payloads to try:</strong>
            </p>
            <ul style={{ marginBottom: '1rem', paddingLeft: '1.5rem' }}>
              <li><code>{`<script>alert('XSS Attack!')</script>`}</code></li>
              <li><code>{`<img src="x" onerror="alert('XSS')">`}</code></li>
              <li><code>{`<h1 style="color:red">HTML Injection</h1>`}</code></li>
              <li><code>{`<iframe src="javascript:alert('XSS')"></iframe>`}</code></li>
            </ul>
            <p style={{ fontSize: '0.9rem', color: '#666' }}>
              <strong>How to fix:</strong> Sanitize user input, escape HTML characters, use Content Security Policy (CSP), and validate on both client and server sides.
            </p>
          </div>
        </div>
      </div>
    </div>
  )
}

export default ProductDetailPage 