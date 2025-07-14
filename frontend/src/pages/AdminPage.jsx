import React, { useState, useEffect } from 'react'
import { Shield, Users, Package, AlertTriangle, Eye } from 'lucide-react'
import { useAuth } from '../App'
import { admin } from '../services/api'

const AdminPage = () => {
  const [users, setUsers] = useState([])
  const [adminOrders, setAdminOrders] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [activeTab, setActiveTab] = useState('users')
  
  const { user } = useAuth()

  useEffect(() => {
    if (user?.role === 'admin') {
      fetchAdminData()
    }
  }, [user])

  const fetchAdminData = async () => {
    try {
      setLoading(true)
      setError('')
      
      const [usersResponse, ordersResponse] = await Promise.all([
        admin.getUsers(),
        admin.getOrders()
      ])
      
      setUsers(usersResponse.data)
      setAdminOrders(ordersResponse.data)
    } catch (error) {
      setError(error.response?.data?.error || 'Failed to fetch admin data')
      console.error('Error fetching admin data:', error)
    } finally {
      setLoading(false)
    }
  }

  const formatDate = (dateString) => {
    return new Date(dateString).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    })
  }

  const getRoleBadgeColor = (role) => {
    return role === 'admin' ? '#dc3545' : '#007bff'
  }

  const getStatusColor = (status) => {
    switch (status) {
      case 'pending': return '#ffc107'
      case 'processing': return '#17a2b8'
      case 'shipped': return '#28a745'
      case 'delivered': return '#007bff'
      default: return '#6c757d'
    }
  }

  if (user?.role !== 'admin') {
    return (
      <div className="page">
        <div className="container">
          <div className="alert alert-error">
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <AlertTriangle size={20} />
              <strong>Access Denied:</strong> Administrator privileges required to access this page.
            </div>
          </div>
          
          <div className="card" style={{ marginTop: '2rem' }}>
            <div className="card-header">
              <h3>🔓 Privilege Escalation Test</h3>
            </div>
            <div className="card-body">
              <p style={{ marginBottom: '1rem' }}>
                You don't have admin privileges, but you can test privilege escalation by:
              </p>
              <ul style={{ marginBottom: '1rem', paddingLeft: '1.5rem' }}>
                <li>Registering a new account and selecting "Administrator" role during registration</li>
                <li>Using browser developer tools to modify your user role in localStorage</li>
                <li>Attempting to access admin API endpoints directly</li>
              </ul>
              <button
                onClick={() => window.location.href = '/register'}
                className="btn btn-primary"
              >
                Try Registration Vulnerability
              </button>
            </div>
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
            <Shield size={32} style={{ marginRight: '1rem' }} />
            Admin Dashboard
          </h1>
          <p className="page-subtitle">Manage users, orders, and system settings</p>
        </div>

        {/* Admin Access Warning */}
        <div className="alert alert-warning">
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <AlertTriangle size={16} />
            <strong>Privilege Escalation Vulnerability:</strong> This admin panel can be accessed through role manipulation during registration!
          </div>
        </div>

        {error && (
          <div className="alert alert-error">
            {error}
          </div>
        )}

        {/* Tab Navigation */}
        <div className="card" style={{ marginBottom: '2rem' }}>
          <div className="card-header">
            <div style={{ display: 'flex', gap: '1rem' }}>
              <button
                onClick={() => setActiveTab('users')}
                className={`btn ${activeTab === 'users' ? 'btn-primary' : 'btn-secondary'}`}
              >
                <Users size={16} style={{ marginRight: '0.5rem' }} />
                Users ({users.length})
              </button>
              <button
                onClick={() => setActiveTab('orders')}
                className={`btn ${activeTab === 'orders' ? 'btn-primary' : 'btn-secondary'}`}
              >
                <Package size={16} style={{ marginRight: '0.5rem' }} />
                Orders ({adminOrders.length})
              </button>
            </div>
          </div>
        </div>

        {loading ? (
          <div style={{ textAlign: 'center', padding: '2rem' }}>
            <div className="spinner"></div>
            <p>Loading admin data...</p>
          </div>
        ) : (
          <>
            {/* Users Tab */}
            {activeTab === 'users' && (
              <div className="card">
                <div className="card-header">
                  <h3>
                    <Users size={20} style={{ marginRight: '0.5rem' }} />
                    User Management
                  </h3>
                </div>
                <div className="card-body" style={{ padding: 0 }}>
                  <div style={{ overflowX: 'auto' }}>
                    <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                      <thead>
                        <tr style={{ background: '#f8f9fa', borderBottom: '2px solid #dee2e6' }}>
                          <th style={{ padding: '1rem', textAlign: 'left' }}>Username</th>
                          <th style={{ padding: '1rem', textAlign: 'left' }}>Email</th>
                          <th style={{ padding: '1rem', textAlign: 'left' }}>Role</th>
                          <th style={{ padding: '1rem', textAlign: 'left' }}>Created</th>
                          <th style={{ padding: '1rem', textAlign: 'left' }}>Actions</th>
                        </tr>
                      </thead>
                      <tbody>
                        {users.map((userItem) => (
                          <tr
                            key={userItem._id}
                            style={{ borderBottom: '1px solid #e9ecef' }}
                          >
                            <td style={{ padding: '1rem', fontWeight: '500' }}>
                              {userItem.username}
                            </td>
                            <td style={{ padding: '1rem', color: '#666' }}>
                              {userItem.email}
                            </td>
                            <td style={{ padding: '1rem' }}>
                              <span
                                style={{
                                  display: 'inline-block',
                                  padding: '0.25rem 0.75rem',
                                  borderRadius: '12px',
                                  fontSize: '0.8rem',
                                  fontWeight: 'bold',
                                  color: 'white',
                                  background: getRoleBadgeColor(userItem.role),
                                  textTransform: 'uppercase'
                                }}
                              >
                                {userItem.role}
                              </span>
                            </td>
                            <td style={{ padding: '1rem', color: '#666', fontSize: '0.9rem' }}>
                              {formatDate(userItem.createdAt)}
                            </td>
                            <td style={{ padding: '1rem' }}>
                              <button
                                className="btn btn-secondary btn-small"
                                title="View user details"
                              >
                                <Eye size={14} />
                              </button>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              </div>
            )}

            {/* Orders Tab */}
            {activeTab === 'orders' && (
              <div className="card">
                <div className="card-header">
                  <h3>
                    <Package size={20} style={{ marginRight: '0.5rem' }} />
                    Order Management
                  </h3>
                </div>
                <div className="card-body" style={{ padding: 0 }}>
                  <div style={{ overflowX: 'auto' }}>
                    <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                      <thead>
                        <tr style={{ background: '#f8f9fa', borderBottom: '2px solid #dee2e6' }}>
                          <th style={{ padding: '1rem', textAlign: 'left' }}>Order ID</th>
                          <th style={{ padding: '1rem', textAlign: 'left' }}>Customer</th>
                          <th style={{ padding: '1rem', textAlign: 'left' }}>Items</th>
                          <th style={{ padding: '1rem', textAlign: 'left' }}>Total</th>
                          <th style={{ padding: '1rem', textAlign: 'left' }}>Status</th>
                          <th style={{ padding: '1rem', textAlign: 'left' }}>Date</th>
                        </tr>
                      </thead>
                      <tbody>
                        {adminOrders.map((order) => (
                          <tr
                            key={order._id}
                            style={{ borderBottom: '1px solid #e9ecef' }}
                          >
                            <td style={{ padding: '1rem', fontFamily: 'monospace', fontSize: '0.9rem' }}>
                              #{order._id.slice(-8)}
                            </td>
                            <td style={{ padding: '1rem', fontWeight: '500' }}>
                              {order.userId?.username || 'Unknown'}
                              <br />
                              <small style={{ color: '#666' }}>
                                {order.userId?.email || 'No email'}
                              </small>
                            </td>
                            <td style={{ padding: '1rem' }}>
                              {order.items?.length || 0} item(s)
                              <br />
                              <small style={{ color: '#666' }}>
                                {order.items?.slice(0, 2).map(item => 
                                  item.productId?.name || 'Unknown'
                                ).join(', ')}
                                {order.items?.length > 2 && '...'}
                              </small>
                            </td>
                            <td style={{ padding: '1rem', fontWeight: 'bold', color: '#007bff' }}>
                              ${order.total?.toFixed(2) || '0.00'}
                            </td>
                            <td style={{ padding: '1rem' }}>
                              <span
                                style={{
                                  display: 'inline-block',
                                  padding: '0.25rem 0.75rem',
                                  borderRadius: '12px',
                                  fontSize: '0.8rem',
                                  fontWeight: 'bold',
                                  color: 'white',
                                  background: getStatusColor(order.status),
                                  textTransform: 'capitalize'
                                }}
                              >
                                {order.status}
                              </span>
                            </td>
                            <td style={{ padding: '1rem', color: '#666', fontSize: '0.9rem' }}>
                              {formatDate(order.createdAt)}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              </div>
            )}
          </>
        )}

        {/* Privilege Escalation Explanation */}
        <div className="card" style={{ marginTop: '3rem' }}>
          <div className="card-header">
            <h3>🔓 Privilege Escalation Vulnerability</h3>
          </div>
          <div className="card-body">
            <p style={{ marginBottom: '1rem' }}>
              This admin panel demonstrates <strong>privilege escalation vulnerabilities</strong> that allow regular users to gain administrative access.
            </p>
            <p style={{ marginBottom: '1rem' }}>
              <strong>How it works:</strong>
            </p>
            <ul style={{ marginBottom: '1rem', paddingLeft: '1.5rem' }}>
              <li><strong>Mass Assignment:</strong> Users can select "Administrator" role during registration</li>
              <li><strong>Client-side Role Check:</strong> Role validation happens only in the frontend</li>
              <li><strong>Weak Authorization:</strong> Backend trusts client-provided role information</li>
              <li><strong>Missing Validation:</strong> No server-side verification of role assignment</li>
            </ul>
            <p style={{ marginBottom: '1rem' }}>
              <strong>Attack vectors:</strong>
            </p>
            <ul style={{ marginBottom: '1rem', paddingLeft: '1.5rem' }}>
              <li>Register with admin role selected</li>
              <li>Modify localStorage user data</li>
              <li>Intercept and modify registration requests</li>
              <li>Directly call admin API endpoints</li>
            </ul>
            <p style={{ fontSize: '0.9rem', color: '#666' }}>
              <strong>How to fix:</strong> Implement proper server-side authorization, never trust client data, use role-based access control (RBAC), and validate permissions on every request.
            </p>
          </div>
        </div>
      </div>
    </div>
  )
}

export default AdminPage 