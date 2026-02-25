import React from 'react'
import { Link } from 'react-router-dom'
import { Home, ArrowLeft, Search, Shield } from 'lucide-react'

const NotFound = () => {
  return (
    <div className="flex items-center justify-center h-full">
      <div className="text-center max-w-sm">
        <div className="text-6xl font-bold text-desktop-border mb-2">404</div>
        <h1 className="text-base font-semibold text-text-primary mb-1">Page Not Found</h1>
        <p className="text-xs text-text-muted mb-6">
          The page you're looking for doesn't exist or has been moved.
        </p>

        <div className="flex gap-3 justify-center mb-6">
          <Link to="/" className="btn-primary text-xs px-4 py-2 inline-flex items-center gap-1.5">
            <Home className="h-3.5 w-3.5" />
            Dashboard
          </Link>
          <Link to="/scan" className="btn-secondary text-xs px-4 py-2 inline-flex items-center gap-1.5">
            <Search className="h-3.5 w-3.5" />
            Start Scan
          </Link>
        </div>

        <button
          onClick={() => window.history.back()}
          className="btn-ghost text-xs px-3 py-1.5 inline-flex items-center gap-1.5"
        >
          <ArrowLeft className="h-3.5 w-3.5" />
          Go Back
        </button>
      </div>
    </div>
  )
}

export default NotFound
