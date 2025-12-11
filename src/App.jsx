import React, { Suspense, startTransition } from 'react'
import { Routes, Route, Navigate } from 'react-router-dom'
import { motion, AnimatePresence } from 'framer-motion'
import { Toaster } from 'react-hot-toast'
import { HelmetProvider } from 'react-helmet-async'
import ErrorBoundary from './components/ErrorBoundary'
import Navbar from './components/Navbar'
import ProtectedRoute from './components/ProtectedRoute'
import { AuthProvider } from './contexts/AuthContext'
import { NotificationProvider } from './components/ui/NotificationSystem'
import { AccessibilityProvider } from './components/accessibility/UniversalAccessibility'
import LoadingSpinner from './components/LoadingSpinner'
import ForceBlackTheme from './components/ForceBlackTheme'
import DarkVeil from './components/ui/DarkVeil'

// Enhanced Components (commented out to prevent import errors)
// import EnhancedSecurityDashboard from './components/dashboard/EnhancedSecurityDashboard'

// Lazy load pages for better performance
const Home = React.lazy(() => import('./pages/Home'))
const Scan = React.lazy(() => import('./pages/Scan'))
const Report = React.lazy(() => import('./pages/Report'))
const Login = React.lazy(() => import('./pages/Login'))
const Signup = React.lazy(() => import('./pages/Signup'))
const Dashboard = React.lazy(() => import('./pages/Dashboard'))
const AdminDashboard = React.lazy(() => import('./pages/AdminDashboard'))
const PluginMarketplace = React.lazy(() => import('./pages/PluginMarketplace'))
const Settings = React.lazy(() => import('./pages/Settings'))
const NotFound = React.lazy(() => import('./pages/NotFound'))

import { pageVariants } from './utils/animations'

function App() {
  return (
    <HelmetProvider>
      <ErrorBoundary>
        <AuthProvider>
          <NotificationProvider>
            <AccessibilityProvider>
              <div className="min-h-screen text-white relative" style={{backgroundColor: 'transparent', background: 'transparent'}}>
          {/* Global Dark Veil Background - Rendered Behind Everything */}
          <div className="fixed inset-0 z-[-1] w-screen h-screen">
            <DarkVeil />
          </div>

          {/* Force Pure Black Theme - TEMPORARILY DISABLED FOR DEBUGGING */}
          {/* <ForceBlackTheme /> */}

          {/* Toast Notifications - Centralized */}
          <Toaster
            position="top-right"
            containerClassName="z-50"
            toastOptions={{
              duration: 4000,
              style: {
                background: '#000000',
                color: '#ffffff',
                border: '1px solid rgba(255, 255, 255, 0.2)',
                borderRadius: '8px',
                fontSize: '14px',
                maxWidth: '400px',
              },
              success: {
                iconTheme: {
                  primary: '#00bcd4',
                  secondary: '#ffffff',
                },
                style: {
                  background: '#000000',
                  color: '#ffffff',
                  border: '1px solid #00bcd4',
                },
              },
              error: {
                iconTheme: {
                  primary: '#ff4444',
                  secondary: '#ffffff',
                },
                style: {
                  background: '#000000',
                  color: '#ffffff',
                  border: '1px solid #ff4444',
                },
              },
              loading: {
                iconTheme: {
                  primary: '#00bcd4',
                  secondary: '#ffffff',
                },
                style: {
                  background: '#000000',
                  color: '#ffffff',
                  border: '1px solid #00bcd4',
                },
              },
            }}
          />

          <div className="relative">
            <AnimatePresence mode="wait">
              <Routes>
                {/* Public Routes */}
                <Route
                  path="/"
                  element={
                    <Suspense fallback={
                      <div className="min-h-screen flex items-center justify-center bg-black">
                        <LoadingSpinner size="lg" text="Loading Home..." />
                      </div>
                    }>
                      <Home />
                    </Suspense>
                  }
                />
                <Route
                  path="/login"
                  element={
                    <Suspense fallback={
                      <div className="min-h-screen flex items-center justify-center bg-black">
                        <LoadingSpinner size="lg" text="Loading Login..." />
                      </div>
                    }>
                      <Login />
                    </Suspense>
                  }
                />
                <Route
                  path="/signup"
                  element={
                    <Suspense fallback={
                      <div className="min-h-screen flex items-center justify-center bg-black">
                        <LoadingSpinner size="lg" text="Loading Signup..." />
                      </div>
                    }>
                      <Signup />
                    </Suspense>
                  }
                />

                {/* Protected Routes */}
                <Route
                  path="/dashboard"
                  element={
                    <ProtectedRoute>
                      <Suspense fallback={
                        <div className="min-h-screen flex items-center justify-center bg-black">
                          <LoadingSpinner size="lg" text="Loading Dashboard..." />
                        </div>
                      }>
                        <Dashboard />
                      </Suspense>
                    </ProtectedRoute>
                  }
                />

                {/* Enhanced Dashboard Route */}
                <Route
                  path="/dashboard/enhanced"
                  element={
                    <ProtectedRoute>
                      <Suspense fallback={
                        <div className="min-h-screen flex items-center justify-center bg-black">
                          <LoadingSpinner size="lg" text="Loading Dashboard..." />
                        </div>
                      }>
                        <Dashboard />
                      </Suspense>
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/scan"
                  element={
                    <ProtectedRoute>
                      <motion.div
                        initial={{ opacity: 0, y: 20 }}
                        animate={{ opacity: 1, y: 0 }}
                        exit={{ opacity: 0, y: -20 }}
                        transition={{ duration: 0.3 }}
                      >
                        <Navbar />
                        <Scan />
                      </motion.div>
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/reports"
                  element={
                    <ProtectedRoute>
                      <motion.div
                        initial={{ opacity: 0, y: 20 }}
                        animate={{ opacity: 1, y: 0 }}
                        exit={{ opacity: 0, y: -20 }}
                        transition={{ duration: 0.3 }}
                      >
                        <Navbar />
                        <Report />
                      </motion.div>
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/report/:scanId"
                  element={
                    <ProtectedRoute>
                      <motion.div
                        initial={{ opacity: 0, y: 20 }}
                        animate={{ opacity: 1, y: 0 }}
                        exit={{ opacity: 0, y: -20 }}
                        transition={{ duration: 0.3 }}
                      >
                        <Navbar />
                        <Report />
                      </motion.div>
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/settings"
                  element={
                    <ProtectedRoute>
                      <motion.div
                        initial={{ opacity: 0, y: 20 }}
                        animate={{ opacity: 1, y: 0 }}
                        exit={{ opacity: 0, y: -20 }}
                        transition={{ duration: 0.3 }}
                      >
                        <Settings />
                      </motion.div>
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/admin"
                  element={
                    <ProtectedRoute requireAdmin={true}>
                      <motion.div
                        initial={{ opacity: 0, y: 20 }}
                        animate={{ opacity: 1, y: 0 }}
                        exit={{ opacity: 0, y: -20 }}
                        transition={{ duration: 0.3 }}
                      >
                        <AdminDashboard />
                      </motion.div>
                    </ProtectedRoute>
                  }
                />
                <Route
                  path="/plugins"
                  element={
                    <ProtectedRoute>
                      <motion.div
                        initial={{ opacity: 0, y: 20 }}
                        animate={{ opacity: 1, y: 0 }}
                        exit={{ opacity: 0, y: -20 }}
                        transition={{ duration: 0.3 }}
                      >
                        <Navbar />
                        <PluginMarketplace />
                      </motion.div>
                    </ProtectedRoute>
                  }
                />

                {/* 404 */}
                <Route
                  path="*"
                  element={
                    <motion.div
                      initial={{ opacity: 0, y: 20 }}
                      animate={{ opacity: 1, y: 0 }}
                      exit={{ opacity: 0, y: -20 }}
                      transition={{ duration: 0.3 }}
                    >
                      <NotFound />
                    </motion.div>
                  }
                />
              </Routes>
            </AnimatePresence>
          </div>
        </div>
          </AccessibilityProvider>
        </NotificationProvider>
      </AuthProvider>
    </ErrorBoundary>
  </HelmetProvider>
)
}

export default App
