import React from 'react'

// Simplified ProtectedRoute for offline-first app
// Always renders children - no authentication required
const ProtectedRoute = ({ children }) => {
  return children
}

export default ProtectedRoute
