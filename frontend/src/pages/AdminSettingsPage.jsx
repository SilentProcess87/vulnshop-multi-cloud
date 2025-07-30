import React, { useState, useEffect } from 'react'
import { useAuth } from '../App'
import { api } from '../services/api'

const AdminSettingsPage = () => {
  const { user } = useAuth()
  const [settings, setSettings] = useState({})
  const [users, setUsers] = useState([])
  const [logs, setLogs] = useState([])
  const [systemInfo, setSystemInfo] = useState({})
  const [fileContent, setFileContent] = useState('')
  const [loading, setLoading] = useState(false)
  const [message, setMessage] = useState('')
  const [error, setError] = useState('')

  // Form states for various vulnerabilities
  const [userSearch, setUserSearch] = useState('')
  const [fileToRead, setFileToRead] = useState('')
  const [sqlCommand, setSqlCommand] = useState('')
  const [xmlData, setXmlData] = useState('<settings><theme>dark</theme></settings>')
  const [redirectUrl, setRedirectUrl] = useState('')
  const [backupPassword, setBackupPassword] = useState('')
  const [sessionId, setSessionId] = useState('')
  const [newUserData, setNewUserData] = useState({
    username: '',
    email: '',
    role: 'user',
    isActive: true
  })

  useEffect(() => {
    loadInitialData()
  }, [])

  const loadInitialData = async () => {
    try {
      // Load system settings
      const settingsResponse = await api.get('/admin/settings')
      setSettings(settingsResponse.data)

      // Load system info (A09 - Security Logging and Monitoring Failures)
      const systemResponse = await api.get('/admin/system-info')
      setSystemInfo(systemResponse.data)

      // Load users for management
      const usersResponse = await api.get('/admin/users')
      setUsers(usersResponse.data.users || [])

      // Load security logs
      const logsResponse = await api.get('/admin/security-logs')
      setLogs(logsResponse.data.logs || [])
    } catch (err) {
      setError('Failed to load admin data: ' + err.message)
    }
  }

  // A01 - Broken Access Control: Function that should check permissions but doesn't
  const executeAdminCommand = async (command) => {
    try {
      setLoading(true)
      const response = await api.post('/admin/execute-command', { command })
      setMessage(response.data.message)
    } catch (err) {
      setError('Command execution failed: ' + err.message)
    } finally {
      setLoading(false)
    }
  }

  // A02 - Cryptographic Failures: Weak password hashing demo
  const generateWeakHash = async () => {
    try {
      const response = await api.post('/admin/generate-hash', { 
        password: backupPassword,
        method: 'md5' // Weak hashing algorithm
      })
      setMessage(`Weak hash generated: ${response.data.hash}`)
    } catch (err) {
      setError('Hash generation failed: ' + err.message)
    }
  }

  // A03 - Injection: SQL Injection vulnerability
  const searchUsers = async () => {
    try {
      setLoading(true)
      // This will be vulnerable to SQL injection in the backend
      const response = await api.get(`/admin/search-users?query=${encodeURIComponent(userSearch)}`)
      setUsers(response.data.users || [])
      setMessage(`Found ${response.data.users?.length || 0} users`)
    } catch (err) {
      setError('User search failed: ' + err.message)
    } finally {
      setLoading(false)
    }
  }

  // A04 - Insecure Design: Direct SQL execution interface
  const executeSqlCommand = async () => {
    try {
      setLoading(true)
      const response = await api.post('/admin/execute-sql', { sql: sqlCommand })
      setMessage(`SQL executed. Rows affected: ${response.data.changes}`)
      if (response.data.results) {
        console.log('SQL Results:', response.data.results)
      }
    } catch (err) {
      setError('SQL execution failed: ' + err.message)
    } finally {
      setLoading(false)
    }
  }

  // A05 - Security Misconfiguration: File reading with path traversal
  const readServerFile = async () => {
    try {
      setLoading(true)
      const response = await api.get(`/admin/read-file?path=${encodeURIComponent(fileToRead)}`)
      setFileContent(response.data.content)
      setMessage('File read successfully')
    } catch (err) {
      setError('File reading failed: ' + err.message)
    } finally {
      setLoading(false)
    }
  }

  // A06 - Vulnerable and Outdated Components: XML processing with XXE
  const processXmlSettings = async () => {
    try {
      setLoading(true)
      const response = await api.post('/admin/process-xml', { 
        xml: xmlData,
        enableExternalEntities: true // Dangerous option
      })
      setMessage('XML processed successfully')
      setSettings(response.data.settings || settings)
    } catch (err) {
      setError('XML processing failed: ' + err.message)
    } finally {
      setLoading(false)
    }
  }

  // A07 - Identification and Authentication Failures: Session hijacking
  const impersonateUser = async () => {
    try {
      setLoading(true)
      const response = await api.post('/admin/impersonate', { sessionId })
      setMessage(`Now impersonating user: ${response.data.username}`)
    } catch (err) {
      setError('Impersonation failed: ' + err.message)
    } finally {
      setLoading(false)
    }
  }

  // A08 - Software and Data Integrity Failures: Unsafe deserialization
  const loadUserPreferences = async () => {
    try {
      setLoading(true)
      const serializedData = localStorage.getItem('adminPreferences') || '{"theme":"dark","notifications":true}'
      const response = await api.post('/admin/load-preferences', { 
        serializedData,
        unsafe: true // Flag to enable unsafe deserialization
      })
      setMessage('Preferences loaded from serialized data')
    } catch (err) {
      setError('Preference loading failed: ' + err.message)
    } finally {
      setLoading(false)
    }
  }

  // A09 - Security Logging and Monitoring Failures: Clear security logs
  const clearSecurityLogs = async () => {
    try {
      setLoading(true)
      await api.delete('/admin/security-logs')
      setLogs([])
      setMessage('Security logs cleared (this should be logged!)')
    } catch (err) {
      setError('Log clearing failed: ' + err.message)
    } finally {
      setLoading(false)
    }
  }

  // A10 - Server-Side Request Forgery (SSRF): URL redirect
  const processRedirect = async () => {
    try {
      setLoading(true)
      const response = await api.post('/admin/process-redirect', { url: redirectUrl })
      setMessage(`Redirect processed: ${response.data.finalUrl}`)
    } catch (err) {
      setError('Redirect processing failed: ' + err.message)
    } finally {
      setLoading(false)
    }
  }

  // Mass assignment vulnerability
  const createUser = async () => {
    try {
      setLoading(true)
      // Send all form data including potentially dangerous fields
      const response = await api.post('/admin/create-user', newUserData)
      setMessage(`User created with ID: ${response.data.userId}`)
      loadInitialData() // Reload users
    } catch (err) {
      setError('User creation failed: ' + err.message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="admin-settings-page">
      <div className="container mx-auto px-4 py-8">
        <h1 className="text-3xl font-bold mb-8 text-red-600">
          🔧 Admin Settings (Vulnerable)
        </h1>
        
        <div className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded mb-6">
          <strong>⚠️ DANGER ZONE:</strong> This page contains ALL OWASP Top 10 vulnerabilities for educational purposes!
        </div>

        {message && (
          <div className="bg-green-100 border border-green-400 text-green-700 px-4 py-3 rounded mb-4">
            {message}
          </div>
        )}

        {error && (
          <div className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded mb-4">
            {error}
          </div>
        )}

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
          {/* A01 - Broken Access Control */}
          <div className="vulnerability-section bg-white p-6 rounded-lg shadow">
            <h2 className="text-xl font-bold mb-4 text-red-600">A01 - Broken Access Control</h2>
            <p className="text-sm text-gray-600 mb-4">Execute admin commands without proper authorization checks</p>
            <div className="space-y-3">
              <button 
                onClick={() => executeAdminCommand('restart-server')}
                className="w-full bg-red-500 text-white py-2 px-4 rounded hover:bg-red-600"
                disabled={loading}
              >
                Restart Server (No Auth Check)
              </button>
              <button 
                onClick={() => executeAdminCommand('delete-all-logs')}
                className="w-full bg-red-500 text-white py-2 px-4 rounded hover:bg-red-600"
                disabled={loading}
              >
                Delete All Logs
              </button>
            </div>
          </div>

          {/* A02 - Cryptographic Failures */}
          <div className="vulnerability-section bg-white p-6 rounded-lg shadow">
            <h2 className="text-xl font-bold mb-4 text-red-600">A02 - Cryptographic Failures</h2>
            <p className="text-sm text-gray-600 mb-4">Weak password hashing (MD5)</p>
            <div className="space-y-3">
              <input
                type="password"
                placeholder="Enter password to hash"
                value={backupPassword}
                onChange={(e) => setBackupPassword(e.target.value)}
                className="w-full p-2 border rounded"
              />
              <button 
                onClick={generateWeakHash}
                className="w-full bg-orange-500 text-white py-2 px-4 rounded hover:bg-orange-600"
                disabled={loading}
              >
                Generate MD5 Hash (Weak!)
              </button>
            </div>
          </div>

          {/* A03 - Injection */}
          <div className="vulnerability-section bg-white p-6 rounded-lg shadow">
            <h2 className="text-xl font-bold mb-4 text-red-600">A03 - Injection (SQL Injection)</h2>
            <p className="text-sm text-gray-600 mb-4">Search users with SQL injection vulnerability</p>
            <div className="space-y-3">
              <input
                type="text"
                placeholder="Search users (try: ' OR '1'='1)"
                value={userSearch}
                onChange={(e) => setUserSearch(e.target.value)}
                className="w-full p-2 border rounded"
              />
              <button 
                onClick={searchUsers}
                className="w-full bg-purple-500 text-white py-2 px-4 rounded hover:bg-purple-600"
                disabled={loading}
              >
                Search Users (SQL Injectable)
              </button>
            </div>
          </div>

          {/* A04 - Insecure Design */}
          <div className="vulnerability-section bg-white p-6 rounded-lg shadow">
            <h2 className="text-xl font-bold mb-4 text-red-600">A04 - Insecure Design</h2>
            <p className="text-sm text-gray-600 mb-4">Direct SQL execution interface</p>
            <div className="space-y-3">
              <textarea
                placeholder="Enter SQL command (e.g., SELECT * FROM users)"
                value={sqlCommand}
                onChange={(e) => setSqlCommand(e.target.value)}
                className="w-full p-2 border rounded h-20"
              />
              <button 
                onClick={executeSqlCommand}
                className="w-full bg-indigo-500 text-white py-2 px-4 rounded hover:bg-indigo-600"
                disabled={loading}
              >
                Execute Raw SQL
              </button>
            </div>
          </div>

          {/* A05 - Security Misconfiguration */}
          <div className="vulnerability-section bg-white p-6 rounded-lg shadow">
            <h2 className="text-xl font-bold mb-4 text-red-600">A05 - Security Misconfiguration</h2>
            <p className="text-sm text-gray-600 mb-4">Read server files (path traversal)</p>
            <div className="space-y-3">
              <input
                type="text"
                placeholder="File path (try: ../../../../etc/passwd)"
                value={fileToRead}
                onChange={(e) => setFileToRead(e.target.value)}
                className="w-full p-2 border rounded"
              />
              <button 
                onClick={readServerFile}
                className="w-full bg-blue-500 text-white py-2 px-4 rounded hover:bg-blue-600"
                disabled={loading}
              >
                Read Server File
              </button>
              {fileContent && (
                <textarea
                  value={fileContent}
                  readOnly
                  className="w-full p-2 border rounded h-32 bg-gray-100"
                />
              )}
            </div>
          </div>

          {/* A06 - Vulnerable Components */}
          <div className="vulnerability-section bg-white p-6 rounded-lg shadow">
            <h2 className="text-xl font-bold mb-4 text-red-600">A06 - Vulnerable Components (XXE)</h2>
            <p className="text-sm text-gray-600 mb-4">XML processing with external entities enabled</p>
            <div className="space-y-3">
              <textarea
                placeholder="XML settings"
                value={xmlData}
                onChange={(e) => setXmlData(e.target.value)}
                className="w-full p-2 border rounded h-20"
              />
              <button 
                onClick={processXmlSettings}
                className="w-full bg-yellow-500 text-white py-2 px-4 rounded hover:bg-yellow-600"
                disabled={loading}
              >
                Process XML (XXE Vulnerable)
              </button>
            </div>
          </div>

          {/* A07 - Authentication Failures */}
          <div className="vulnerability-section bg-white p-6 rounded-lg shadow">
            <h2 className="text-xl font-bold mb-4 text-red-600">A07 - Authentication Failures</h2>
            <p className="text-sm text-gray-600 mb-4">Session hijacking / impersonation</p>
            <div className="space-y-3">
              <input
                type="text"
                placeholder="Session ID to hijack"
                value={sessionId}
                onChange={(e) => setSessionId(e.target.value)}
                className="w-full p-2 border rounded"
              />
              <button 
                onClick={impersonateUser}
                className="w-full bg-pink-500 text-white py-2 px-4 rounded hover:bg-pink-600"
                disabled={loading}
              >
                Impersonate User
              </button>
            </div>
          </div>

          {/* A08 - Software Integrity Failures */}
          <div className="vulnerability-section bg-white p-6 rounded-lg shadow">
            <h2 className="text-xl font-bold mb-4 text-red-600">A08 - Software Integrity Failures</h2>
            <p className="text-sm text-gray-600 mb-4">Unsafe deserialization of user preferences</p>
            <button 
              onClick={loadUserPreferences}
              className="w-full bg-teal-500 text-white py-2 px-4 rounded hover:bg-teal-600"
              disabled={loading}
            >
              Load Preferences (Unsafe Deserialization)
            </button>
          </div>

          {/* A09 - Logging Failures */}
          <div className="vulnerability-section bg-white p-6 rounded-lg shadow">
            <h2 className="text-xl font-bold mb-4 text-red-600">A09 - Logging and Monitoring Failures</h2>
            <p className="text-sm text-gray-600 mb-4">Clear security logs without proper logging</p>
            <button 
              onClick={clearSecurityLogs}
              className="w-full bg-gray-500 text-white py-2 px-4 rounded hover:bg-gray-600"
              disabled={loading}
            >
              Clear Security Logs (Unlogged!)
            </button>
            <div className="mt-4 max-h-32 overflow-y-auto">
              <h4 className="font-semibold">Recent Security Logs:</h4>
              {logs.length > 0 ? (
                logs.map((log, index) => (
                  <div key={index} className="text-xs text-gray-600 py-1 border-b">
                    {log.timestamp}: {log.event}
                  </div>
                ))
              ) : (
                <p className="text-gray-500 text-sm">No logs available</p>
              )}
            </div>
          </div>

          {/* A10 - SSRF */}
          <div className="vulnerability-section bg-white p-6 rounded-lg shadow">
            <h2 className="text-xl font-bold mb-4 text-red-600">A10 - Server-Side Request Forgery</h2>
            <p className="text-sm text-gray-600 mb-4">Process URL redirects without validation</p>
            <div className="space-y-3">
              <input
                type="text"
                placeholder="Redirect URL (try internal IPs)"
                value={redirectUrl}
                onChange={(e) => setRedirectUrl(e.target.value)}
                className="w-full p-2 border rounded"
              />
              <button 
                onClick={processRedirect}
                className="w-full bg-green-500 text-white py-2 px-4 rounded hover:bg-green-600"
                disabled={loading}
              >
                Process Redirect (SSRF Vulnerable)
              </button>
            </div>
          </div>

          {/* Mass Assignment Vulnerability */}
          <div className="vulnerability-section bg-white p-6 rounded-lg shadow">
            <h2 className="text-xl font-bold mb-4 text-red-600">Mass Assignment Vulnerability</h2>
            <p className="text-sm text-gray-600 mb-4">Create user with potential privilege escalation</p>
            <div className="space-y-3">
              <input
                type="text"
                placeholder="Username"
                value={newUserData.username}
                onChange={(e) => setNewUserData({...newUserData, username: e.target.value})}
                className="w-full p-2 border rounded"
              />
              <input
                type="email"
                placeholder="Email"
                value={newUserData.email}
                onChange={(e) => setNewUserData({...newUserData, email: e.target.value})}
                className="w-full p-2 border rounded"
              />
              <select
                value={newUserData.role}
                onChange={(e) => setNewUserData({...newUserData, role: e.target.value})}
                className="w-full p-2 border rounded"
              >
                <option value="user">User</option>
                <option value="admin">Admin</option>
                <option value="superadmin">Super Admin</option>
              </select>
              <button 
                onClick={createUser}
                className="w-full bg-red-600 text-white py-2 px-4 rounded hover:bg-red-700"
                disabled={loading}
              >
                Create User (Mass Assignment)
              </button>
            </div>
          </div>

          {/* System Information Display */}
          <div className="vulnerability-section bg-white p-6 rounded-lg shadow">
            <h2 className="text-xl font-bold mb-4 text-gray-700">System Information</h2>
            <div className="text-sm space-y-2">
              <p><strong>Server:</strong> {systemInfo.hostname}</p>
              <p><strong>Platform:</strong> {systemInfo.platform}</p>
              <p><strong>Memory:</strong> {systemInfo.memory}</p>
              <p><strong>Users Count:</strong> {users.length}</p>
              <p><strong>Database:</strong> {systemInfo.database}</p>
            </div>
          </div>
        </div>

        <div className="mt-8 bg-yellow-100 border border-yellow-400 text-yellow-700 px-4 py-3 rounded">
          <h3 className="font-bold">Educational Purpose:</h3>
          <p className="text-sm">
            This page demonstrates all OWASP Top 10 vulnerabilities in a controlled environment. 
            Each section shows how these vulnerabilities can be exploited and should be fixed in production applications.
          </p>
        </div>
      </div>
    </div>
  )
}

export default AdminSettingsPage
