import React, { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { ShoppingCart, Minus, Plus, Trash2, CreditCard } from 'lucide-react'
import { useAuth, useCart } from '../App'
import { orders } from '../services/api'

const CartPage = () => {
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')
  
  const { user } = useAuth()
  const { cart, updateCartQuantity, removeFromCart, clearCart } = useCart()
  const navigate = useNavigate()

  const calculateTotal = () => {
    return cart.reduce((total, item) => total + (item.price * item.quantity), 0).toFixed(2)
  }

  const handleCheckout = async () => {
    if (!user) {
      navigate('/login')
      return
    }

    if (cart.length === 0) {
      setError('Your cart is empty')
      return
    }

    setLoading(true)
    setError('')
    setSuccess('')

    try {
      const orderItems = cart.map(item => ({
        productId: item.id,
        quantity: item.quantity
      }))

      const response = await orders.create({ items: orderItems })
      setSuccess('Order placed successfully!')
      clearCart()
      
      setTimeout(() => {
        navigate('/orders')
      }, 2000)
    } catch (error) {
      setError(error.response?.data?.error || 'Failed to place order')
    } finally {
      setLoading(false)
    }
  }

  if (cart.length === 0) {
    return (
      <div className="page">
        <div className="container">
          <div className="page-header">
            <h1 className="page-title">
              <ShoppingCart size={32} style={{ marginRight: '1rem' }} />
              Shopping Cart
            </h1>
          </div>
          
          <div style={{ textAlign: 'center', padding: '4rem 2rem' }}>
            <ShoppingCart size={64} style={{ color: '#ccc', marginBottom: '1rem' }} />
            <h2 style={{ color: '#666', marginBottom: '1rem' }}>Your cart is empty</h2>
            <p style={{ color: '#666', marginBottom: '2rem' }}>
              Add some products to your cart to get started!
            </p>
            <button
              onClick={() => navigate('/products')}
              className="btn btn-primary"
            >
              Browse Products
            </button>
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className="page">
      <div className="container">
        <div className="page-header">
          <h1 className="page-title">
            <ShoppingCart size={32} style={{ marginRight: '1rem' }} />
            Shopping Cart
          </h1>
          <p className="page-subtitle">Review your items and proceed to checkout</p>
        </div>

        {error && (
          <div className="alert alert-error">
            {error}
          </div>
        )}

        {success && (
          <div className="alert alert-success">
            {success}
          </div>
        )}

        <div className="grid grid-2" style={{ gap: '2rem', alignItems: 'start' }}>
          {/* Cart Items */}
          <div className="card">
            <div className="card-header">
              <h3>Cart Items ({cart.length})</h3>
            </div>
            <div className="card-body" style={{ padding: 0 }}>
              {cart.map((item) => (
                <div key={item.id} className="cart-item">
                  <img 
                    src={item.image} 
                    alt={item.name}
                    className="cart-item-image"
                    onError={(e) => {
                      e.target.src = 'https://via.placeholder.com/80x80?text=No+Image'
                    }}
                  />
                  
                  <div className="cart-item-info">
                    <h4 className="cart-item-name">{item.name}</h4>
                    <div className="cart-item-price">${item.price}</div>
                  </div>
                  
                  <div className="quantity-controls">
                    <button
                      onClick={() => updateCartQuantity(item.id, item.quantity - 1)}
                      className="quantity-btn"
                      disabled={item.quantity <= 1}
                    >
                      <Minus size={16} />
                    </button>
                    <input
                      type="number"
                      value={item.quantity}
                      onChange={(e) => {
                        const newQuantity = parseInt(e.target.value) || 1
                        updateCartQuantity(item.id, newQuantity)
                      }}
                      className="quantity-input"
                      min="1"
                    />
                    <button
                      onClick={() => updateCartQuantity(item.id, item.quantity + 1)}
                      className="quantity-btn"
                    >
                      <Plus size={16} />
                    </button>
                  </div>
                  
                  <div style={{ fontSize: '1.1rem', fontWeight: 'bold', color: '#007bff' }}>
                    ${(item.price * item.quantity).toFixed(2)}
                  </div>
                  
                  <button
                    onClick={() => removeFromCart(item.id)}
                    className="btn btn-danger btn-small"
                    style={{ marginLeft: '1rem' }}
                  >
                    <Trash2 size={16} />
                  </button>
                </div>
              ))}
            </div>
          </div>

          {/* Order Summary */}
          <div className="card">
            <div className="card-header">
              <h3>Order Summary</h3>
            </div>
            <div className="card-body">
              <div style={{ marginBottom: '1rem' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.5rem' }}>
                  <span>Subtotal:</span>
                  <span>${calculateTotal()}</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.5rem' }}>
                  <span>Shipping:</span>
                  <span>Free</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.5rem' }}>
                  <span>Tax:</span>
                  <span>$0.00</span>
                </div>
                <hr style={{ margin: '1rem 0' }} />
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '1.2rem', fontWeight: 'bold' }}>
                  <span>Total:</span>
                  <span>${calculateTotal()}</span>
                </div>
              </div>

              {!user && (
                <div className="alert alert-info" style={{ fontSize: '0.9rem' }}>
                  Please <a href="/login" style={{ color: '#007bff' }}>sign in</a> to proceed with checkout.
                </div>
              )}

              <button
                onClick={handleCheckout}
                className="btn btn-primary"
                style={{ width: '100%', fontSize: '1.1rem', padding: '1rem' }}
                disabled={loading || !user}
              >
                <CreditCard size={20} style={{ marginRight: '0.5rem' }} />
                {loading ? 'Processing...' : `Checkout - $${calculateTotal()}`}
              </button>

              <button
                onClick={clearCart}
                className="btn btn-secondary"
                style={{ width: '100%', marginTop: '0.5rem' }}
                disabled={loading}
              >
                Clear Cart
              </button>
            </div>
          </div>
        </div>

        {/* Continue Shopping */}
        <div style={{ textAlign: 'center', marginTop: '2rem' }}>
          <button
            onClick={() => navigate('/products')}
            className="btn btn-outline"
          >
            Continue Shopping
          </button>
        </div>
      </div>
    </div>
  )
}

export default CartPage 