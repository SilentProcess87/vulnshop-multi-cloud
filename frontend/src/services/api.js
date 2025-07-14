import axios from 'axios'

// Get API configuration from environment variables
const API_URL = import.meta.env.VITE_API_URL || '/api'
const API_SUBSCRIPTION_KEY = import.meta.env.VITE_API_SUBSCRIPTION_KEY

// Create axios instance with base configuration
const api = axios.create({
  baseURL: API_URL,
  timeout: 10000,
  headers: {
    'Content-Type': 'application/json',
    // Add subscription key if configured (for APIM)
    ...(API_SUBSCRIPTION_KEY && { 'Ocp-Apim-Subscription-Key': API_SUBSCRIPTION_KEY })
  }
})

// Add auth token to requests if available
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('token')
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

// Handle response errors
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      // Token expired or invalid
      localStorage.removeItem('token')
      localStorage.removeItem('user')
      window.location.href = '/login'
    }
    return Promise.reject(error)
  }
)

// Auth API calls
export const auth = {
  login: (credentials) => api.post('/login', credentials),
  register: (userData) => api.post('/register', userData),
}

// Products API calls
export const products = {
  getAll: () => api.get('/products'),
  search: (query) => api.get(`/products/search?q=${encodeURIComponent(query)}`),
  create: (productData) => api.post('/products', productData),
  getById: (id) => api.get(`/products/${id}`),
}

// Orders API calls
export const orders = {
  getAll: () => api.get('/orders'),
  getById: (id) => api.get(`/orders/${id}`),
  create: (orderData) => api.post('/orders', orderData),
}

// Reviews API calls
export const reviews = {
  create: (productId, reviewData) => api.post(`/products/${productId}/reviews`, reviewData),
}

// Admin API calls
export const admin = {
  getUsers: () => api.get('/admin/users'),
  getOrders: () => api.get('/admin/orders'),
}

// Health check
export const health = {
  check: () => api.get('/health'),
}

// Log configuration for debugging
console.log('API Configuration:', {
  baseURL: API_URL,
  hasSubscriptionKey: !!API_SUBSCRIPTION_KEY
})

export default api 