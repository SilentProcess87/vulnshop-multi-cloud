import React, { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { UserPlus, AlertTriangle } from 'lucide-react'
import { useAuth } from '../App'
import { auth } from '../services/api'

const RegisterPage = () => {
  const [formData, setFormData] = useState({
    username: '',
    email: '',
    password: '',
    confirmPassword: '',
    role: 'user' // VULNERABILITY: Allows role selection during registration
  })
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')
  
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
    setSuccess('')

    // Basic validation
    if (formData.password !== formData.confirmPassword) {
      setError('Passwords do not match')
      setLoading(false)
      return
    }

    if (formData.password.length < 6) {
      setError('Password must be at least 6 characters long')
      setLoading(false)
      return
    }

    try {
      const registrationData = {
        username: formData.username,
        email: formData.email,
        password: formData.password,
        role: formData.role // VULNERABILITY: Sending role to backend
      }
      
      const response = await auth.register(registrationData)
      const { user, token } = response.data
      
      setSuccess('Registration successful! Logging you in...')
      
      setTimeout(() => {
        login(user, token)
        navigate('/')
      }, 1500)
    } catch (error) {
      setError(error.response?.data?.error || 'Registration failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="page">
      <div className="container" style={{ maxWidth: '500px' }}>
        <div className="page-header">
          <h1 className="page-title">
            <UserPlus size={32} style={{ marginRight: '1rem' }} />
            Register
          </h1>
          <p className="page-subtitle">Create your account</p>
        </div>

        {/* Vulnerability Warning */}
        <div className="alert alert-warning">
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <AlertTriangle size={16} />
            <strong>Mass Assignment Vulnerability:</strong> Notice how you can select your role during registration!
          </div>
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
                <label htmlFor="email" className="form-label">Email</label>
                <input
                  type="email"
                  id="email"
                  name="email"
                  value={formData.email}
                  onChange={handleChange}
                  className="form-input"
                  required
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
                  minLength="6"
                />
              </div>

              <div className="form-group">
                <label htmlFor="confirmPassword" className="form-label">Confirm Password</label>
                <input
                  type="password"
                  id="confirmPassword"
                  name="confirmPassword"
                  value={formData.confirmPassword}
                  onChange={handleChange}
                  className="form-input"
                  required
                />
              </div>

              {/* VULNERABILITY: Role selection during registration */}
              <div className="form-group">
                <label htmlFor="role" className="form-label">
                  Role 
                  <span style={{ fontSize: '0.8rem', color: '#dc3545', marginLeft: '0.5rem' }}>
                    (⚠️ Vulnerability: Should not be user-selectable)
                  </span>
                </label>
                <select
                  id="role"
                  name="role"
                  value={formData.role}
                  onChange={handleChange}
                  className="form-select"
                >
                  <option value="user">Regular User</option>
                  <option value="admin">Administrator</option>
                </select>
                <small style={{ color: '#666', fontSize: '0.8rem' }}>
                  Try selecting "Administrator" to test the mass assignment vulnerability!
                </small>
              </div>

              <button
                type="submit"
                className="btn btn-primary"
                style={{ width: '100%', marginBottom: '1rem' }}
                disabled={loading}
              >
                {loading ? 'Creating Account...' : 'Create Account'}
              </button>
            </form>

            <div style={{ textAlign: 'center' }}>
              <Link to="/login" className="nav-link">
                Already have an account? Sign in here
              </Link>
            </div>
          </div>
        </div>

        {/* Vulnerability Explanation */}
        <div className="card" style={{ marginTop: '2rem' }}>
          <div className="card-header">
            <h3>🔓 Mass Assignment Vulnerability</h3>
          </div>
          <div className="card-body">
            <p style={{ marginBottom: '1rem' }}>
              This registration form demonstrates a <strong>mass assignment vulnerability</strong> where users can manipulate their role during registration.
            </p>
            <p style={{ marginBottom: '1rem' }}>
              <strong>Why is this dangerous?</strong>
            </p>
            <ul style={{ marginBottom: '1rem', paddingLeft: '1.5rem' }}>
              <li>Users can assign themselves administrative privileges</li>
              <li>The backend accepts any role sent from the frontend</li>
              <li>No server-side validation of role assignment</li>
            </ul>
            <p style={{ fontSize: '0.9rem', color: '#666' }}>
              <strong>How to fix:</strong> The backend should ignore client-provided roles and assign default roles based on business logic.
            </p>
          </div>
        </div>
      </div>
    </div>
  )
}

export default RegisterPage 