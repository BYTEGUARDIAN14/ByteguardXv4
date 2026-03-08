import React, { Suspense, useState } from 'react'
import { Routes, Route, Navigate } from 'react-router-dom'
import { Toaster } from 'react-hot-toast'
import { HelmetProvider } from 'react-helmet-async'
import ErrorBoundary from './components/ErrorBoundary'

import { AuthProvider } from './contexts/AuthContext'
import { NotificationProvider } from './components/ui/NotificationSystem'
import Navbar from './components/Navbar'

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
  return (
    <HelmetProvider>
      <ErrorBoundary>
        <AuthProvider>
          <NotificationProvider>
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

            {/* Desktop Layout */}
            <div className="flex flex-col h-screen bg-desktop-bg text-text-primary overflow-hidden">
              <Navbar />
              <main className="flex-1 overflow-y-auto">
                <Suspense fallback={<PageLoader text="Loading..." />}>
                  <Routes>
                    {/* Default route - Dashboard */}
                    <Route path="/" element={<Dashboard />} />
                    <Route path="/dashboard" element={<Dashboard />} />
                    <Route path="/scan" element={<Scan />} />
                    <Route path="/reports" element={<Report />} />
                    <Route path="/report/:scanId" element={<Report />} />
                    <Route path="/settings" element={<Settings />} />
                    <Route path="/admin" element={<AdminDashboard />} />
                    <Route path="/plugins" element={<PluginMarketplace />} />

                    {/* Redirect old auth routes */}
                    <Route path="/login" element={<Navigate to="/" replace />} />
                    <Route path="/signup" element={<Navigate to="/" replace />} />

                    {/* 404 */}
                    <Route path="*" element={<NotFound />} />
                  </Routes>
                </Suspense>
              </main>
            </div>
          </NotificationProvider>
        </AuthProvider>
      </ErrorBoundary>
    </HelmetProvider>
  )
}

export default App
