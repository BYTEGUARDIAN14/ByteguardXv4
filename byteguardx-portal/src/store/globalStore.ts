import { create } from 'zustand';
import { persist, createJSONStorage } from 'zustand/middleware';
import { secureStorage } from '../utils/security';

// Theme state
interface ThemeState {
  theme: 'dark' | 'light' | 'auto';
  setTheme: (theme: 'dark' | 'light' | 'auto') => void;
}

// User preferences state
interface UserPreferencesState {
  language: string;
  region: string;
  notifications: boolean;
  analytics: boolean;
  setLanguage: (language: string) => void;
  setRegion: (region: string) => void;
  toggleNotifications: () => void;
  toggleAnalytics: () => void;
}

// UI state
interface UIState {
  sidebarOpen: boolean;
  mobileMenuOpen: boolean;
  searchOpen: boolean;
  loading: boolean;
  setSidebarOpen: (open: boolean) => void;
  setMobileMenuOpen: (open: boolean) => void;
  setSearchOpen: (open: boolean) => void;
  setLoading: (loading: boolean) => void;
}

// Combined store
interface GlobalStore extends ThemeState, UserPreferencesState, UIState {}

// Create the store with persistence
export const useGlobalStore = create<GlobalStore>()(
  persist(
    (set, get) => ({
      // Theme state
      theme: 'dark',
      setTheme: (theme) => {
        set({ theme });
        document.documentElement.classList.toggle('dark', theme === 'dark');
      },

      // User preferences
      language: 'en',
      region: 'US',
      notifications: true,
      analytics: false,
      setLanguage: (language) => set({ language }),
      setRegion: (region) => set({ region }),
      toggleNotifications: () => set((state) => ({ notifications: !state.notifications })),
      toggleAnalytics: () => set((state) => ({ analytics: !state.analytics })),

      // UI state (not persisted)
      sidebarOpen: false,
      mobileMenuOpen: false,
      searchOpen: false,
      loading: false,
      setSidebarOpen: (sidebarOpen) => set({ sidebarOpen }),
      setMobileMenuOpen: (mobileMenuOpen) => set({ mobileMenuOpen }),
      setSearchOpen: (searchOpen) => set({ searchOpen }),
      setLoading: (loading) => set({ loading }),
    }),
    {
      name: 'byteguardx-preferences',
      storage: createJSONStorage(() => ({
        getItem: (name) => secureStorage.get(name),
        setItem: (name, value) => secureStorage.set(name, value),
        removeItem: (name) => secureStorage.remove(name),
      })),
      // Only persist certain keys
      partialize: (state) => ({
        theme: state.theme,
        language: state.language,
        region: state.region,
        notifications: state.notifications,
        analytics: state.analytics,
      }),
    }
  )
);

// Selectors for better performance
export const useTheme = () => useGlobalStore((state) => ({
  theme: state.theme,
  setTheme: state.setTheme,
}));

export const useUserPreferences = () => useGlobalStore((state) => ({
  language: state.language,
  region: state.region,
  notifications: state.notifications,
  analytics: state.analytics,
  setLanguage: state.setLanguage,
  setRegion: state.setRegion,
  toggleNotifications: state.toggleNotifications,
  toggleAnalytics: state.toggleAnalytics,
}));

export const useUI = () => useGlobalStore((state) => ({
  sidebarOpen: state.sidebarOpen,
  mobileMenuOpen: state.mobileMenuOpen,
  searchOpen: state.searchOpen,
  loading: state.loading,
  setSidebarOpen: state.setSidebarOpen,
  setMobileMenuOpen: state.setMobileMenuOpen,
  setSearchOpen: state.setSearchOpen,
  setLoading: state.setLoading,
}));
