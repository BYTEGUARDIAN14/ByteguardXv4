import { create } from 'zustand';
import { subscribeWithSelector, devtools, persist } from 'zustand/middleware';
import { immer } from 'zustand/middleware/immer';

/**
 * Advanced State Management with Zustand
 * Features: Persistence, DevTools, Immer, Subscriptions, Performance Monitoring
 */

// Performance monitoring middleware
const performanceMiddleware = (config) => (set, get, api) =>
  config(
    (...args) => {
      const start = performance.now();
      const result = set(...args);
      const end = performance.now();
      
      if (end - start > 16) { // Slower than 60fps
        console.warn(`Slow state update: ${end - start}ms`);
      }
      
      return result;
    },
    get,
    api
  );

// Main application store
export const useAppStore = create(
  devtools(
    persist(
      subscribeWithSelector(
        immer(
          performanceMiddleware((set, get) => ({
            // UI State
            ui: {
              theme: 'dark',
              sidebarCollapsed: false,
              loading: false,
              notifications: [],
              modals: {},
              activeTab: 'dashboard',
              layout: 'default'
            },

            // User State
            user: {
              profile: null,
              preferences: {
                language: 'en',
                timezone: 'UTC',
                notifications: true,
                autoRefresh: true,
                refreshInterval: 30000
              },
              permissions: [],
              isAuthenticated: false
            },

            // Security State
            security: {
              threats: [],
              alerts: [],
              incidents: [],
              scanResults: [],
              plugins: [],
              policies: []
            },

            // Performance State
            performance: {
              metrics: {},
              alerts: [],
              history: [],
              realTimeData: {}
            },

            // Actions
            setTheme: (theme) => set((state) => {
              state.ui.theme = theme;
            }),

            toggleSidebar: () => set((state) => {
              state.ui.sidebarCollapsed = !state.ui.sidebarCollapsed;
            }),

            setLoading: (loading) => set((state) => {
              state.ui.loading = loading;
            }),

            addNotification: (notification) => set((state) => {
              state.ui.notifications.push({
                id: Date.now(),
                timestamp: new Date().toISOString(),
                ...notification
              });
            }),

            removeNotification: (id) => set((state) => {
              state.ui.notifications = state.ui.notifications.filter(n => n.id !== id);
            }),

            setUser: (user) => set((state) => {
              state.user.profile = user;
              state.user.isAuthenticated = !!user;
            }),

            updateUserPreferences: (preferences) => set((state) => {
              Object.assign(state.user.preferences, preferences);
            }),

            setSecurityData: (type, data) => set((state) => {
              state.security[type] = data;
            }),

            addSecurityAlert: (alert) => set((state) => {
              state.security.alerts.unshift({
                id: Date.now(),
                timestamp: new Date().toISOString(),
                ...alert
              });
              
              // Keep only last 100 alerts
              if (state.security.alerts.length > 100) {
                state.security.alerts = state.security.alerts.slice(0, 100);
              }
            }),

            updatePerformanceMetrics: (metrics) => set((state) => {
              state.performance.metrics = { ...state.performance.metrics, ...metrics };
              
              // Add to history
              state.performance.history.push({
                timestamp: Date.now(),
                metrics: { ...metrics }
              });
              
              // Keep only last 1000 entries
              if (state.performance.history.length > 1000) {
                state.performance.history = state.performance.history.slice(-1000);
              }
            }),

            // Computed values
            get unreadNotifications() {
              return get().ui.notifications.filter(n => !n.read).length;
            },

            get criticalAlerts() {
              return get().security.alerts.filter(a => a.severity === 'CRITICAL');
            },

            get systemHealth() {
              const metrics = get().performance.metrics;
              const alerts = get().security.alerts;
              
              const criticalAlerts = alerts.filter(a => a.severity === 'CRITICAL').length;
              const highCpuUsage = metrics.cpu_usage > 80;
              const highMemoryUsage = metrics.memory_usage > 85;
              
              if (criticalAlerts > 0 || highCpuUsage || highMemoryUsage) {
                return 'critical';
              }
              
              const warningAlerts = alerts.filter(a => a.severity === 'HIGH').length;
              if (warningAlerts > 0 || metrics.cpu_usage > 60 || metrics.memory_usage > 70) {
                return 'warning';
              }
              
              return 'healthy';
            }
          }))
        )
      ),
      {
        name: 'byteguardx-store',
        partialize: (state) => ({
          ui: {
            theme: state.ui.theme,
            sidebarCollapsed: state.ui.sidebarCollapsed
          },
          user: {
            preferences: state.user.preferences
          }
        })
      }
    ),
    { name: 'ByteGuardX Store' }
  )
);

// Specialized stores for better performance
export const useSecurityStore = create(
  devtools(
    subscribeWithSelector((set, get) => ({
      threats: [],
      alerts: [],
      incidents: [],
      scanResults: [],
      realTimeData: {},
      
      addThreat: (threat) => set((state) => ({
        threats: [threat, ...state.threats.slice(0, 999)]
      })),
      
      updateRealTimeData: (data) => set((state) => ({
        realTimeData: { ...state.realTimeData, ...data }
      })),
      
      clearOldData: () => set((state) => {
        const cutoff = Date.now() - 24 * 60 * 60 * 1000; // 24 hours
        return {
          threats: state.threats.filter(t => t.timestamp > cutoff),
          alerts: state.alerts.filter(a => a.timestamp > cutoff)
        };
      })
    })),
    { name: 'Security Store' }
  )
);

export const usePerformanceStore = create(
  devtools(
    subscribeWithSelector((set, get) => ({
      metrics: {},
      history: [],
      alerts: [],
      
      updateMetrics: (metrics) => set((state) => {
        const newHistory = [...state.history, {
          timestamp: Date.now(),
          ...metrics
        }].slice(-1000); // Keep last 1000 entries
        
        return {
          metrics: { ...state.metrics, ...metrics },
          history: newHistory
        };
      }),
      
      addAlert: (alert) => set((state) => ({
        alerts: [alert, ...state.alerts.slice(0, 99)]
      })),
      
      getMetricHistory: (metric, timeRange = 3600000) => {
        const cutoff = Date.now() - timeRange;
        return get().history
          .filter(entry => entry.timestamp > cutoff)
          .map(entry => ({
            timestamp: entry.timestamp,
            value: entry[metric]
          }));
      }
    })),
    { name: 'Performance Store' }
  )
);

// Store subscriptions for side effects
useAppStore.subscribe(
  (state) => state.ui.theme,
  (theme) => {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('theme', theme);
  }
);

useAppStore.subscribe(
  (state) => state.user.preferences.autoRefresh,
  (autoRefresh) => {
    if (autoRefresh) {
      // Start auto-refresh
      console.log('Auto-refresh enabled');
    } else {
      // Stop auto-refresh
      console.log('Auto-refresh disabled');
    }
  }
);

// Performance monitoring
if (process.env.NODE_ENV === 'development') {
  useAppStore.subscribe(
    (state) => state,
    (state, prevState) => {
      const stateSize = JSON.stringify(state).length;
      if (stateSize > 1024 * 1024) { // 1MB
        console.warn('Large state detected:', stateSize / 1024, 'KB');
      }
    }
  );
}

export default useAppStore;
