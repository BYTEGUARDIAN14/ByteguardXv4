import React, { Suspense, useState } from 'react'
import { Routes, Route, Navigate } from 'react-router-dom'
import { Toaster } from 'react-hot-toast'
import { HelmetProvider } from 'react-helmet-async'
import ErrorBoundary from './components/ErrorBoundary'
import Sidebar from './components/layout/Sidebar'
import Header from './components/layout/Header'
import { AuthProvider } from './contexts/AuthContext'
import { NotificationProvider } from './components/ui/NotificationSystem'
import { AccessibilityProvider } from './components/accessibility/UniversalAccessibility'

// Lazy load pages for better performance
const Scan = React.lazy(() => import('./pages/Scan'))
const Report = React.lazy(() => import('./pages/Report'))
const Dashboard = React.lazy(() => import('./pages/Dashboard'))
const AdminDashboard = React.lazy(() => import('./pages/AdminDashboard'))
const PluginMarketplace = React.lazy(() => import('./pages/PluginMarketplace'))
const Settings = React.lazy(() => import('./pages/Settings'))
const NotFound = React.lazy(() => import('./pages/NotFound'))

// Simple loading fallback for desktop
const PageLoader = ({ text = 'Loading...' }) => (
  <div className="flex items-center justify-center h-full">
    <div className="flex items-center gap-3">
      <div className="w-4 h-4 border-2 border-primary-600 border-t-transparent rounded-full animate-spin" />
      <span className="text-sm text-text-muted">{text}</span>
    </div>
  </div>
)

function App() {
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false)

  return (
    <HelmetProvider>
      <ErrorBoundary>
        <AuthProvider>
          <NotificationProvider>
            <AccessibilityProvider>
              {/* Toast Notifications */}
              <Toaster
                position="top-right"
                containerClassName="z-50"
                toastOptions={{
                  duration: 4000,
                  style: {
                    background: '#1e1e1e',
                    color: '#e4e4e7',
                    border: '1px solid #222',
                    borderRadius: '6px',
                    fontSize: '13px',
                    maxWidth: '360px',
                    padding: '10px 14px',
                  },
                  success: {
                    iconTheme: { primary: '#10b981', secondary: '#fff' },
                    style: { borderColor: '#10b981' },
                  },
                  error: {
                    iconTheme: { primary: '#ef4444', secondary: '#fff' },
                    style: { borderColor: '#ef4444' },
                  },
                  loading: {
                    iconTheme: { primary: '#06b6d4', secondary: '#fff' },
                    style: { borderColor: '#06b6d4' },
                  },
                }}
              />

              {/* Desktop App Shell */}
              <div className="h-screen flex overflow-hidden bg-desktop-bg text-text-primary">
                {/* Sidebar */}
                <Sidebar
                  isCollapsed={sidebarCollapsed}
                  onToggle={() => setSidebarCollapsed(!sidebarCollapsed)}
                />

                {/* Main Area */}
                <div
                  className={`
                    flex-1 flex flex-col min-w-0 transition-all duration-200 ease-in-out
                    ${sidebarCollapsed ? 'ml-[56px]' : 'ml-[240px]'}
                  `}
                >
                  {/* Header / Toolbar */}
                  <Header sidebarCollapsed={sidebarCollapsed} />

                  {/* Content Area */}
                  <main className="flex-1 overflow-y-auto mt-[44px]">
                    <Routes>
                      {/* Default route - Dashboard */}
                      <Route
                        path="/"
                        element={
                          <Suspense fallback={<PageLoader text="Loading Dashboard..." />}>
                            <Dashboard />
                          </Suspense>
                        }
                      />

                      <Route
                        path="/dashboard"
                        element={
                          <Suspense fallback={<PageLoader text="Loading Dashboard..." />}>
                            <Dashboard />
                          </Suspense>
                        }
                      />

                      <Route
                        path="/scan"
                        element={
                          <Suspense fallback={<PageLoader text="Loading Scanner..." />}>
                            <Scan />
                          </Suspense>
                        }
                      />

                      <Route
                        path="/reports"
                        element={
                          <Suspense fallback={<PageLoader text="Loading Reports..." />}>
                            <Report />
                          </Suspense>
                        }
                      />

                      <Route
                        path="/report/:scanId"
                        element={
                          <Suspense fallback={<PageLoader text="Loading Report..." />}>
                            <Report />
                          </Suspense>
                        }
                      />

                      <Route
                        path="/settings"
                        element={
                          <Suspense fallback={<PageLoader text="Loading Settings..." />}>
                            <Settings />
                          </Suspense>
                        }
                      />

                      <Route
                        path="/admin"
                        element={
                          <Suspense fallback={<PageLoader text="Loading Admin..." />}>
                            <AdminDashboard />
                          </Suspense>
                        }
                      />

                      <Route
                        path="/plugins"
                        element={
                          <Suspense fallback={<PageLoader text="Loading Plugins..." />}>
                            <PluginMarketplace />
                          </Suspense>
                        }
                      />

                      {/* Redirect old auth routes */}
                      <Route path="/login" element={<Navigate to="/" replace />} />
                      <Route path="/signup" element={<Navigate to="/" replace />} />

                      {/* 404 */}
                      <Route
                        path="*"
                        element={
                          <Suspense fallback={<PageLoader />}>
                            <NotFound />
                          </Suspense>
                        }
                      />
                    </Routes>
                  </main>
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
