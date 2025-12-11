/**
 * ByteGuardX Enhanced - Complete Integration of Advanced UI/UX Features
 * Combines all next-generation components into a unified experience
 */

import React, { useState, useEffect, Suspense } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import { Helmet } from 'react-helmet-async';

// Core Components
import Navbar from './Navbar';
import Footer from './Footer';
import LoadingSpinner from './LoadingSpinner';
import ErrorBoundary from './ErrorBoundary';

// Enhanced Components
import { AccessibilityProvider } from './accessibility/UniversalAccessibility';
import EnhancedSecurityDashboard from './dashboard/EnhancedSecurityDashboard';
import { QuantumGlassCard } from './advanced/QuantumGlassmorphism';

// Lazy load pages for performance
const Dashboard = React.lazy(() => import('../pages/Dashboard'));
const Scan = React.lazy(() => import('../pages/Scan'));
const Reports = React.lazy(() => import('../pages/ReportsPage'));
const Settings = React.lazy(() => import('../pages/SettingsPage'));
const PluginMarketplace = React.lazy(() => import('../pages/PluginMarketplace'));
const AdminDashboard = React.lazy(() => import('../pages/AdminDashboard'));

// Performance monitoring
const PerformanceMonitor = React.lazy(() => import('./performance/PerformanceMonitor'));

const ByteGuardXEnhanced = () => {
  const [isLoading, setIsLoading] = useState(true);
  const [user, setUser] = useState(null);
  const [systemHealth, setSystemHealth] = useState('healthy');
  const [notifications, setNotifications] = useState([]);

  // Initialize application
  useEffect(() => {
    initializeApp();
  }, []);

  const initializeApp = async () => {
    try {
      // Check authentication
      const token = localStorage.getItem('token');
      if (token) {
        const userData = await validateToken(token);
        setUser(userData);
      }

      // Check system health
      const health = await checkSystemHealth();
      setSystemHealth(health.status);

      // Load user preferences
      await loadUserPreferences();

      // Initialize performance monitoring
      if ('performance' in window) {
        initializePerformanceMonitoring();
      }

    } catch (error) {
      console.error('App initialization error:', error);
    } finally {
      setIsLoading(false);
    }
  };

  const validateToken = async (token) => {
    try {
      const response = await fetch('/api/auth/validate', {
        headers: { Authorization: `Bearer ${token}` }
      });
      if (response.ok) {
        return await response.json();
      }
    } catch (error) {
      console.error('Token validation error:', error);
    }
    return null;
  };

  const checkSystemHealth = async () => {
    try {
      const response = await fetch('/api/health');
      return await response.json();
    } catch (error) {
      return { status: 'degraded' };
    }
  };

  const loadUserPreferences = async () => {
    try {
      const preferences = localStorage.getItem('byteguardx-preferences');
      if (preferences) {
        const parsed = JSON.parse(preferences);
        // Apply theme, language, etc.
        applyUserPreferences(parsed);
      }
    } catch (error) {
      console.error('Error loading preferences:', error);
    }
  };

  const applyUserPreferences = (preferences) => {
    // Apply theme
    if (preferences.theme) {
      document.documentElement.setAttribute('data-theme', preferences.theme);
    }

    // Apply language
    if (preferences.language) {
      document.documentElement.setAttribute('lang', preferences.language);
    }

    // Apply accessibility settings
    if (preferences.accessibility) {
      Object.entries(preferences.accessibility).forEach(([key, value]) => {
        if (value) {
          document.documentElement.classList.add(`accessibility-${key}`);
        }
      });
    }
  };

  const initializePerformanceMonitoring = () => {
    // Monitor Core Web Vitals
    import('web-vitals').then(({ getCLS, getFID, getFCP, getLCP, getTTFB }) => {
      getCLS(console.log);
      getFID(console.log);
      getFCP(console.log);
      getLCP(console.log);
      getTTFB(console.log);
    });
  };

  // Loading screen with quantum effects
  if (isLoading) {
    return (
      <div className="min-h-screen bg-black flex items-center justify-center">
        <motion.div
          initial={{ opacity: 0, scale: 0.8 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ duration: 0.5 }}
        >
          <QuantumGlassCard variant="quantum" className="p-12 text-center">
            <motion.div
              animate={{ rotate: 360 }}
              transition={{ duration: 2, repeat: Infinity, ease: 'linear' }}
              className="w-16 h-16 mx-auto mb-6"
            >
              <div className="w-full h-full border-4 border-cyan-400 border-t-transparent rounded-full"></div>
            </motion.div>
            
            <h2 className="text-2xl font-bold text-white mb-2">ByteGuardX Enhanced</h2>
            <p className="text-gray-400 mb-4">Initializing next-generation security platform...</p>
            
            <div className="flex items-center justify-center space-x-2">
              {[0, 1, 2].map((i) => (
                <motion.div
                  key={i}
                  className="w-2 h-2 bg-cyan-400 rounded-full"
                  animate={{ scale: [1, 1.5, 1] }}
                  transition={{ duration: 1, repeat: Infinity, delay: i * 0.2 }}
                />
              ))}
            </div>
          </QuantumGlassCard>
        </motion.div>
      </div>
    );
  }

  return (
    <AccessibilityProvider>
      <Router>
        <div className="min-h-screen bg-black text-white cyber-gradient">
          <Helmet>
            <title>ByteGuardX Enhanced - Next-Generation Security Platform</title>
            <meta name="description" content="AI-powered vulnerability scanning with immersive 3D visualization, spatial design, and advanced accessibility features." />
            <meta name="viewport" content="width=device-width, initial-scale=1.0" />
            <meta name="theme-color" content="#06B6D4" />
          </Helmet>

          <ErrorBoundary>
            {/* System Health Indicator */}
            {systemHealth !== 'healthy' && (
              <motion.div
                initial={{ opacity: 0, y: -50 }}
                animate={{ opacity: 1, y: 0 }}
                className="bg-yellow-500/20 border-b border-yellow-400/30 p-3 text-center"
              >
                <p className="text-yellow-400 text-sm">
                  System Status: {systemHealth} - Some features may be limited
                </p>
              </motion.div>
            )}

            {/* Navigation */}
            <Navbar user={user} />

            {/* Main Content */}
            <main className="flex-1">
              <Suspense fallback={
                <div className="flex items-center justify-center min-h-[400px]">
                  <LoadingSpinner size="lg" text="Loading..." />
                </div>
              }>
                <Routes>
                  {/* Enhanced Dashboard Route */}
                  <Route 
                    path="/dashboard" 
                    element={
                      user ? (
                        <EnhancedSecurityDashboard />
                      ) : (
                        <Navigate to="/login" replace />
                      )
                    } 
                  />
                  
                  {/* Standard Routes */}
                  <Route path="/scan" element={<Scan />} />
                  <Route path="/reports" element={<Reports />} />
                  <Route path="/settings" element={<Settings />} />
                  <Route path="/plugins" element={<PluginMarketplace />} />
                  <Route 
                    path="/admin" 
                    element={
                      user?.role === 'admin' ? (
                        <AdminDashboard />
                      ) : (
                        <Navigate to="/dashboard" replace />
                      )
                    } 
                  />
                  
                  {/* Default redirect */}
                  <Route path="/" element={<Navigate to="/dashboard" replace />} />
                  
                  {/* 404 fallback */}
                  <Route path="*" element={
                    <div className="min-h-screen flex items-center justify-center">
                      <QuantumGlassCard className="p-8 text-center">
                        <h1 className="text-4xl font-bold text-white mb-4">404</h1>
                        <p className="text-gray-400 mb-6">Page not found</p>
                        <button
                          onClick={() => window.history.back()}
                          className="px-6 py-3 bg-gradient-to-r from-cyan-500 to-blue-500 text-white rounded-2xl hover:from-cyan-600 hover:to-blue-600 transition-all"
                        >
                          Go Back
                        </button>
                      </QuantumGlassCard>
                    </div>
                  } />
                </Routes>
              </Suspense>
            </main>

            {/* Footer */}
            <Footer />

            {/* Performance Monitor (Development only) */}
            {process.env.NODE_ENV === 'development' && (
              <Suspense fallback={null}>
                <PerformanceMonitor />
              </Suspense>
            )}

            {/* Global Notifications */}
            <AnimatePresence>
              {notifications.map((notification) => (
                <motion.div
                  key={notification.id}
                  initial={{ opacity: 0, x: 300 }}
                  animate={{ opacity: 1, x: 0 }}
                  exit={{ opacity: 0, x: 300 }}
                  className="fixed top-4 right-4 z-50"
                >
                  <QuantumGlassCard 
                    variant="elevated" 
                    className={`p-4 max-w-sm ${
                      notification.type === 'error' ? 'border-red-400/30' :
                      notification.type === 'warning' ? 'border-yellow-400/30' :
                      notification.type === 'success' ? 'border-green-400/30' :
                      'border-cyan-400/30'
                    }`}
                  >
                    <div className="flex items-start space-x-3">
                      <div className={`w-2 h-2 rounded-full mt-2 ${
                        notification.type === 'error' ? 'bg-red-400' :
                        notification.type === 'warning' ? 'bg-yellow-400' :
                        notification.type === 'success' ? 'bg-green-400' :
                        'bg-cyan-400'
                      }`} />
                      <div className="flex-1">
                        <h4 className="text-white font-medium">{notification.title}</h4>
                        <p className="text-gray-400 text-sm">{notification.message}</p>
                      </div>
                      <button
                        onClick={() => setNotifications(prev => 
                          prev.filter(n => n.id !== notification.id)
                        )}
                        className="text-gray-400 hover:text-white"
                      >
                        ✕
                      </button>
                    </div>
                  </QuantumGlassCard>
                </motion.div>
              ))}
            </AnimatePresence>
          </ErrorBoundary>
        </div>
      </Router>
    </AccessibilityProvider>
  );
};

export default ByteGuardXEnhanced;
