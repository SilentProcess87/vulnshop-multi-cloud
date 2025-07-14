import React, { useState, useEffect } from 'react'
import { Package, AlertTriangle, ExternalLink } from 'lucide-react'
import { useAuth } from '../App'
import { orders } from '../services/api'

const OrdersPage = () => {
  const [userOrders, setUserOrders] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [idorTest, setIdorTest] = useState('')
  const [idorResult, setIdorResult] = useState('')
  
  const { user } = useAuth()

  useEffect(() => {
    fetchOrders()
  }, [])

  const fetchOrders = async () => {
    try {
      setLoading(true)
      const response = await orders.getAll()
      setUserOrders(response.data)
    } catch (error) {
      setError('Failed to fetch orders')
      console.error('Error fetching orders:', error)
    } finally {
      setLoading(false)
    }
  }

  // VULNERABILITY: IDOR testing function
  const testIDOR = async () => {
    if (!idorTest.trim()) {
      setIdorResult('Please enter an order ID')
      return
    }

    try {
      const response = await orders.getById(idorTest)
      setIdorResult(`SUCCESS: Accessed order ${idorTest} belonging to user: ${response.data.userId?.username || 'Unknown'}`)
    } catch (error) {
      setIdorResult(`FAILED: ${error.response?.data?.error || 'Could not access order'}`)
    }
  }

  const formatDate = (dateString) => {
    return new Date(dateString).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'long',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    })
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

  return (
    <div className="page">
      <div className="container">
        <div className="page-header">
          <h1 className="page-title">
            <Package size={32} style={{ marginRight: '1rem' }} />
            My Orders
          </h1>
          <p className="page-subtitle">Track your order history and status</p>
        </div>

        {/* IDOR Vulnerability Testing */}
        <div className="card" style={{ marginBottom: '2rem' }}>
          <div className="card-header">
            <h3>🔓 IDOR Vulnerability Test</h3>
          </div>
          <div className="card-body">
            <div className="alert alert-warning">
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <AlertTriangle size={16} />
                <strong>Insecure Direct Object Reference:</strong> Test accessing other users' orders!
              </div>
            </div>
            
            <p style={{ marginBottom: '1rem' }}>
              This demonstrates an IDOR vulnerability where you can access any order by knowing its ID, regardless of ownership.
            </p>
            
            <div style={{ display: 'flex', gap: '1rem', alignItems: 'flex-end', marginBottom: '1rem' }}>
              <div className="form-group" style={{ flex: 1, marginBottom: 0 }}>
                <label className="form-label">Test Order ID:</label>
                <input
                  type="text"
                  value={idorTest}
                  onChange={(e) => setIdorTest(e.target.value)}
                  placeholder="Try: 1, 2, 3, or any MongoDB ObjectId"
                  className="form-input"
                />
              </div>
              <button
                onClick={testIDOR}
                className="btn btn-primary"
                style={{ height: 'fit-content' }}
              >
                Test Access
              </button>
            </div>
            
            {idorResult && (
              <div className={`alert ${idorResult.startsWith('SUCCESS') ? 'alert-error' : 'alert-info'}`}>
                {idorResult}
              </div>
            )}
            
            <p style={{ fontSize: '0.9rem', color: '#666' }}>
              <strong>Try accessing:</strong> Different order IDs to see if you can access orders that don't belong to you.
            </p>
          </div>
        </div>

        {error && (
          <div className="alert alert-error">
            {error}
          </div>
        )}

        {/* Orders List */}
        {loading ? (
          <div style={{ textAlign: 'center', padding: '2rem' }}>
            <div className="spinner"></div>
            <p>Loading orders...</p>
          </div>
        ) : userOrders.length === 0 ? (
          <div style={{ textAlign: 'center', padding: '4rem 2rem' }}>
            <Package size={64} style={{ color: '#ccc', marginBottom: '1rem' }} />
            <h2 style={{ color: '#666', marginBottom: '1rem' }}>No orders yet</h2>
            <p style={{ color: '#666', marginBottom: '2rem' }}>
              Start shopping to see your orders here!
            </p>
            <button
              onClick={() => window.location.href = '/products'}
              className="btn btn-primary"
            >
              Browse Products
            </button>
          </div>
        ) : (
          <div className="grid" style={{ gap: '1.5rem' }}>
            {userOrders.map((order) => (
              <div key={order._id} className="card">
                <div className="card-header">
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <div>
                      <h3 style={{ marginBottom: '0.5rem' }}>Order #{order._id.slice(-8)}</h3>
                      <p style={{ color: '#666', fontSize: '0.9rem' }}>
                        Placed on {formatDate(order.createdAt)}
                      </p>
                    </div>
                    <div style={{ textAlign: 'right' }}>
                      <div
                        style={{
                          display: 'inline-block',
                          padding: '0.5rem 1rem',
                          borderRadius: '20px',
                          color: 'white',
                          fontSize: '0.9rem',
                          fontWeight: 'bold',
                          background: getStatusColor(order.status),
                          textTransform: 'capitalize'
                        }}
                      >
                        {order.status}
                      </div>
                    </div>
                  </div>
                </div>
                
                <div className="card-body">
                  <div style={{ marginBottom: '1.5rem' }}>
                    <h4 style={{ marginBottom: '1rem' }}>Items Ordered:</h4>
                    {order.items?.map((item, index) => (
                      <div
                        key={index}
                        style={{
                          display: 'flex',
                          justifyContent: 'space-between',
                          alignItems: 'center',
                          padding: '0.5rem 0',
                          borderBottom: index < order.items.length - 1 ? '1px solid #e9ecef' : 'none'
                        }}
                      >
                        <div>
                          <span style={{ fontWeight: '500' }}>
                            {item.productId?.name || 'Product Not Found'}
                          </span>
                          <span style={{ color: '#666', marginLeft: '0.5rem' }}>
                            x{item.quantity}
                          </span>
                        </div>
                        <div style={{ fontWeight: 'bold', color: '#007bff' }}>
                          ${(item.price * item.quantity).toFixed(2)}
                        </div>
                      </div>
                    ))}
                  </div>
                  
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <div>
                      <strong style={{ fontSize: '1.2rem' }}>
                        Total: ${order.total?.toFixed(2) || '0.00'}
                      </strong>
                    </div>
                    <div style={{ display: 'flex', gap: '0.5rem' }}>
                      <button
                        onClick={() => testIDOR.bind(null, order._id)}
                        className="btn btn-secondary btn-small"
                        title="Test IDOR with this order ID"
                      >
                        <ExternalLink size={14} style={{ marginRight: '0.5rem' }} />
                        Test IDOR
                      </button>
                    </div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}

        {/* IDOR Vulnerability Explanation */}
        <div className="card" style={{ marginTop: '3rem' }}>
          <div className="card-header">
            <h3>🔓 Insecure Direct Object Reference (IDOR)</h3>
          </div>
          <div className="card-body">
            <p style={{ marginBottom: '1rem' }}>
              IDOR vulnerabilities occur when an application provides direct access to objects based on user-supplied input without proper authorization checks.
            </p>
            <p style={{ marginBottom: '1rem' }}>
              <strong>In this application:</strong>
            </p>
            <ul style={{ marginBottom: '1rem', paddingLeft: '1.5rem' }}>
              <li>The API endpoint /api/orders/:id accepts any order ID</li>
              <li>No verification that the order belongs to the requesting user</li>
              <li>Attackers can enumerate order IDs to access sensitive data</li>
              <li>Personal information and purchase history can be exposed</li>
            </ul>
            <p style={{ fontSize: '0.9rem', color: '#666' }}>
              <strong>How to fix:</strong> Implement proper authorization checks, use UUIDs instead of incremental IDs, and validate user ownership before returning data.
            </p>
          </div>
        </div>
      </div>
    </div>
  )
}

export default OrdersPage 