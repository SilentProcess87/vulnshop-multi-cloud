import axios from 'axios'

// Create axios instance with base configuration
const api = axios.create({
  baseURL: '/api', // Will be proxied to backend by Vite
  timeout: 10000,
  headers: {
    'Content-Type': 'application/json'
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
  login: (credentials) => api.post('/auth/login', credentials),
  register: (userData) => api.post('/auth/register', userData),
}

// Products API calls
export const products = {
  getAll: () => api.get('/products'),
  search: (query) => api.get(`/products/search?q=${encodeURIComponent(query)}`),
  create: (productData) => api.post('/products', productData),
}

// Orders API calls
export const orders = {
  getAll: () => api.get('/orders'),
  getById: (id) => api.get(`/orders/${id}`),
  create: (orderData) => api.post('/orders', orderData),
}

// Reviews API calls
export const reviews = {
  getByProduct: (productId) => api.get(`/reviews/${productId}`),
  create: (reviewData) => api.post('/reviews', reviewData),
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

export default api 