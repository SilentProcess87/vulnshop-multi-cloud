import React, { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { LogIn } from 'lucide-react'
import { useAuth } from '../App'
import { auth } from '../services/api'

const LoginPage = () => {
  const [formData, setFormData] = useState({
    username: '',
    password: ''
  })
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  
  const { login } = useAuth()
  const navigate = useNavigate()

  const handleChange = (e) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value
    })
  }

  const handleSubmit = async (e) => {
    e.preventDefault()
    setLoading(true)
    setError('')

    try {
      const response = await auth.login(formData)
      const { user, token } = response.data
      
      login(user, token)
      navigate('/')
    } catch (error) {
      setError(error.response?.data?.error || 'Login failed')
    } finally {
      setLoading(false)
    }
  }

  const fillTestCredentials = (type) => {
    if (type === 'admin') {
      setFormData({ username: 'admin', password: 'password' })
    } else {
      setFormData({ username: 'john_doe', password: 'password' })
    }
  }

  return (
    <div className="page">
      <div className="container" style={{ maxWidth: '500px' }}>
        <div className="page-header">
          <h1 className="page-title">
            <LogIn size={32} style={{ marginRight: '1rem' }} />
            Login
          </h1>
          <p className="page-subtitle">Sign in to your account</p>
        </div>

        {error && (
          <div className="alert alert-error">
            {error}
          </div>
        )}

        <div className="card">
          <div className="card-body">
            <form onSubmit={handleSubmit}>
              <div className="form-group">
                <label htmlFor="username" className="form-label">Username</label>
                <input
                  type="text"
                  id="username"
                  name="username"
                  value={formData.username}
                  onChange={handleChange}
                  className="form-input"
                  required
                  autoFocus
                />
              </div>

              <div className="form-group">
                <label htmlFor="password" className="form-label">Password</label>
                <input
                  type="password"
                  id="password"
                  name="password"
                  value={formData.password}
                  onChange={handleChange}
                  className="form-input"
                  required
                />
              </div>

              <button
                type="submit"
                className="btn btn-primary"
                style={{ width: '100%', marginBottom: '1rem' }}
                disabled={loading}
              >
                {loading ? 'Signing in...' : 'Sign In'}
              </button>
            </form>

            <div style={{ textAlign: 'center', marginBottom: '1rem' }}>
              <Link to="/register" className="nav-link">
                Don't have an account? Register here
              </Link>
            </div>

            {/* Test Credentials */}
            <div style={{ borderTop: '1px solid #e9ecef', paddingTop: '1rem' }}>
              <p style={{ fontSize: '0.9rem', color: '#666', marginBottom: '1rem', textAlign: 'center' }}>
                <strong>Test with default credentials:</strong>
              </p>
              <div style={{ display: 'flex', gap: '0.5rem', justifyContent: 'center' }}>
                <button
                  type="button"
                  onClick={() => fillTestCredentials('admin')}
                  className="btn btn-secondary btn-small"
                >
                  Admin Login
                </button>
                <button
                  type="button"
                  onClick={() => fillTestCredentials('user')}
                  className="btn btn-secondary btn-small"
                >
                  User Login
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

export default LoginPage 