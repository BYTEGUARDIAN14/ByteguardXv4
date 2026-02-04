import React, { createContext, useContext } from 'react'
import axios from 'axios'

// Create auth context
const AuthContext = createContext()

// Custom hook to use auth context
export const useAuth = () => {
  const context = useContext(AuthContext)
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider')
  }
  return context
}

// Simplified Auth provider for offline-first app
// No actual authentication - always "authenticated" as local user
export const AuthProvider = ({ children }) => {
  // Mock user for offline-first app
  const user = {
    id: 'local-user',
    username: 'Local User',
    email: 'local@byteguardx.app',
    role: 'admin' // Full access in offline mode
  }

  const API_BASE_URL = import.meta.env.VITE_API_URL ||
    (import.meta.env.PROD ? 'https://your-flask-backend.herokuapp.com' : 'http://localhost:5000')

  // Create axios instance for API calls
  const api = axios.create({
    baseURL: API_BASE_URL,
    withCredentials: true,
    timeout: 30000,
    headers: {
      'Content-Type': 'application/json',
      'X-Requested-With': 'XMLHttpRequest',
    },
  })

  // No-op functions for compatibility
  const login = async () => ({ success: true })
  const signup = async () => ({ success: true })
  const logout = async () => { }
  const refreshToken = async () => true
  const updateProfile = async () => ({ success: true })
  const checkAuthStatus = async () => { }

  const value = {
    user,
    isAuthenticated: true, // Always authenticated in offline mode
    isLoading: false,
    login,
    signup,
    logout,
    refreshToken,
    updateProfile,
    checkAuthStatus,
    api
  }

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  )
}

export default AuthContext
