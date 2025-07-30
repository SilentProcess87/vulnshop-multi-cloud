import React from 'react'
import { Link } from 'react-router-dom'
import { ShoppingCart, User, LogOut, Shield } from 'lucide-react'
import { useAuth, useCart } from '../App'

const Header = () => {
  const { user, logout } = useAuth()
  const { cart } = useCart()

  const cartItemCount = cart.reduce((sum, item) => sum + item.quantity, 0)

  return (
    <header className="header">
      <div className="header-content">
        <Link to="/" className="logo">
          🛒 VulnShop
        </Link>
        
        <nav className="nav">
          <Link to="/products" className="nav-link">Products</Link>
          {user && (
            <Link to="/orders" className="nav-link">My Orders</Link>
          )}
          {user?.role === 'admin' && (
            <>
              <Link to="/admin" className="nav-link">
                <Shield size={16} style={{ marginRight: '0.5rem' }} />
                Admin
              </Link>
              <Link to="/admin/settings" className="nav-link" style={{ color: '#dc2626' }}>
                ⚠️ Settings
              </Link>
            </>
          )}
        </nav>

        <div className="user-menu">
          <Link to="/cart" className="nav-link cart-icon">
            <ShoppingCart size={20} />
            {cartItemCount > 0 && (
              <span className="cart-count">{cartItemCount}</span>
            )}
          </Link>
          
          {user ? (
            <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
              <span className="nav-link">
                <User size={16} style={{ marginRight: '0.5rem' }} />
                {user.username}
              </span>
              <button
                onClick={logout}
                className="btn btn-secondary btn-small"
                style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}
              >
                <LogOut size={16} />
                Logout
              </button>
            </div>
          ) : (
            <div style={{ display: 'flex', gap: '0.5rem' }}>
              <Link to="/login" className="btn btn-outline btn-small">
                Login
              </Link>
              <Link to="/register" className="btn btn-primary btn-small">
                Register
              </Link>
            </div>
          )}
        </div>
      </div>
    </header>
  )
}

export default Header 