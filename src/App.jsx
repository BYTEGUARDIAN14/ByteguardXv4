import React, { Suspense } from 'react'
import { Routes, Route, Navigate } from 'react-router-dom'
import { motion, AnimatePresence } from 'framer-motion'
import { Toaster } from 'react-hot-toast'
import { HelmetProvider } from 'react-helmet-async'
import ErrorBoundary from './components/ErrorBoundary'
import Navbar from './components/Navbar'
import { AuthProvider } from './contexts/AuthContext'
import { NotificationProvider } from './components/ui/NotificationSystem'
import { AccessibilityProvider } from './components/accessibility/UniversalAccessibility'
import LoadingSpinner from './components/LoadingSpinner'

// Lazy load pages for better performance
const Scan = React.lazy(() => import('./pages/Scan'))
const Report = React.lazy(() => import('./pages/Report'))
const Dashboard = React.lazy(() => import('./pages/Dashboard'))
const AdminDashboard = React.lazy(() => import('./pages/AdminDashboard'))
const PluginMarketplace = React.lazy(() => import('./pages/PluginMarketplace'))
const Settings = React.lazy(() => import('./pages/Settings'))
const NotFound = React.lazy(() => import('./pages/NotFound'))

function App() {
  return (
    <HelmetProvider>
      <ErrorBoundary>
        <AuthProvider>
          <NotificationProvider>
            <AccessibilityProvider>
              <div className="min-h-screen bg-neutral-950 text-white">
                {/* Toast Notifications */}
                <Toaster
                  position="top-right"
                  containerClassName="z-50"
                  toastOptions={{
                    duration: 4000,
                    style: {
                      background: '#171717',
                      color: '#ffffff',
                      border: '1px solid rgba(255, 255, 255, 0.1)',
                      borderRadius: '8px',
                      fontSize: '14px',
                      maxWidth: '400px',
                    },
                    success: {
                      iconTheme: {
                        primary: '#22c55e',
                        secondary: '#ffffff',
                      },
                      style: {
                        background: '#171717',
                        color: '#ffffff',
                        border: '1px solid #22c55e',
                      },
                    },
                    error: {
                      iconTheme: {
                        primary: '#ef4444',
                        secondary: '#ffffff',
                      },
                      style: {
                        background: '#171717',
                        color: '#ffffff',
                        border: '1px solid #ef4444',
                      },
                    },
                    loading: {
                      iconTheme: {
                        primary: '#3b82f6',
                        secondary: '#ffffff',
                      },
                      style: {
                        background: '#171717',
                        color: '#ffffff',
                        border: '1px solid #3b82f6',
                      },
                    },
                  }}
                />

                <div className="relative">
                  <AnimatePresence mode="wait">
                    <Routes>
                      {/* Default route - Dashboard (main workspace) */}
                      <Route
                        path="/"
                        element={
                          <Suspense fallback={
                            <div className="min-h-screen flex items-center justify-center bg-neutral-950">
                              <LoadingSpinner size="lg" text="Loading..." />
                            </div>
                          }>
                            <Dashboard />
                          </Suspense>
                        }
                      />

                      {/* Core App Routes */}
                      <Route
                        path="/dashboard"
                        element={
                          <Suspense fallback={
                            <div className="min-h-screen flex items-center justify-center bg-neutral-950">
                              <LoadingSpinner size="lg" text="Loading Dashboard..." />
                            </div>
                          }>
                            <Dashboard />
                          </Suspense>
                        }
                      />

                      <Route
                        path="/scan"
                        element={
                          <Suspense fallback={
                            <div className="min-h-screen flex items-center justify-center bg-neutral-950">
                              <LoadingSpinner size="lg" text="Loading Scanner..." />
                            </div>
                          }>
                            <motion.div
                              initial={{ opacity: 0 }}
                              animate={{ opacity: 1 }}
                              exit={{ opacity: 0 }}
                              transition={{ duration: 0.2 }}
                            >
                              <Navbar />
                              <Scan />
                            </motion.div>
                          </Suspense>
                        }
                      />

                      <Route
                        path="/reports"
                        element={
                          <Suspense fallback={
                            <div className="min-h-screen flex items-center justify-center bg-neutral-950">
                              <LoadingSpinner size="lg" text="Loading Reports..." />
                            </div>
                          }>
                            <motion.div
                              initial={{ opacity: 0 }}
                              animate={{ opacity: 1 }}
                              exit={{ opacity: 0 }}
                              transition={{ duration: 0.2 }}
                            >
                              <Navbar />
                              <Report />
                            </motion.div>
                          </Suspense>
                        }
                      />

                      <Route
                        path="/report/:scanId"
                        element={
                          <Suspense fallback={
                            <div className="min-h-screen flex items-center justify-center bg-neutral-950">
                              <LoadingSpinner size="lg" text="Loading Report..." />
                            </div>
                          }>
                            <motion.div
                              initial={{ opacity: 0 }}
                              animate={{ opacity: 1 }}
                              exit={{ opacity: 0 }}
                              transition={{ duration: 0.2 }}
                            >
                              <Navbar />
                              <Report />
                            </motion.div>
                          </Suspense>
                        }
                      />

                      <Route
                        path="/settings"
                        element={
                          <Suspense fallback={
                            <div className="min-h-screen flex items-center justify-center bg-neutral-950">
                              <LoadingSpinner size="lg" text="Loading Settings..." />
                            </div>
                          }>
                            <motion.div
                              initial={{ opacity: 0 }}
                              animate={{ opacity: 1 }}
                              exit={{ opacity: 0 }}
                              transition={{ duration: 0.2 }}
                            >
                              <Settings />
                            </motion.div>
                          </Suspense>
                        }
                      />

                      <Route
                        path="/admin"
                        element={
                          <Suspense fallback={
                            <div className="min-h-screen flex items-center justify-center bg-neutral-950">
                              <LoadingSpinner size="lg" text="Loading Admin..." />
                            </div>
                          }>
                            <motion.div
                              initial={{ opacity: 0 }}
                              animate={{ opacity: 1 }}
                              exit={{ opacity: 0 }}
                              transition={{ duration: 0.2 }}
                            >
                              <AdminDashboard />
                            </motion.div>
                          </Suspense>
                        }
                      />

                      <Route
                        path="/plugins"
                        element={
                          <Suspense fallback={
                            <div className="min-h-screen flex items-center justify-center bg-neutral-950">
                              <LoadingSpinner size="lg" text="Loading Plugins..." />
                            </div>
                          }>
                            <motion.div
                              initial={{ opacity: 0 }}
                              animate={{ opacity: 1 }}
                              exit={{ opacity: 0 }}
                              transition={{ duration: 0.2 }}
                            >
                              <Navbar />
                              <PluginMarketplace />
                            </motion.div>
                          </Suspense>
                        }
                      />

                      {/* Redirect old auth routes to dashboard */}
                      <Route path="/login" element={<Navigate to="/" replace />} />
                      <Route path="/signup" element={<Navigate to="/" replace />} />

                      {/* 404 */}
                      <Route
                        path="*"
                        element={
                          <Suspense fallback={
                            <div className="min-h-screen flex items-center justify-center bg-neutral-950">
                              <LoadingSpinner size="lg" />
                            </div>
                          }>
                            <NotFound />
                          </Suspense>
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
