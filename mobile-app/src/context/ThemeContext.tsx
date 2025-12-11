import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import { Appearance, ColorSchemeName } from 'react-native';
import * as SecureStore from 'expo-secure-store';

export interface ThemeColors {
  primary: string;
  primaryContainer: string;
  secondary: string;
  background: string;
  surface: string;
  surfaceVariant: string;
  text: string;
  textSecondary: string;
  border: string;
  error: string;
  warning: string;
  success: string;
  info: string;
}

export interface Theme {
  colors: ThemeColors;
  isDark: boolean;
  spacing: {
    xs: number;
    sm: number;
    md: number;
    lg: number;
    xl: number;
  };
  borderRadius: {
    sm: number;
    md: number;
    lg: number;
  };
  typography: {
    h1: { fontSize: number; fontWeight: string };
    h2: { fontSize: number; fontWeight: string };
    h3: { fontSize: number; fontWeight: string };
    body: { fontSize: number; fontWeight: string };
    caption: { fontSize: number; fontWeight: string };
  };
}

const lightTheme: Theme = {
  colors: {
    primary: '#0ea5e9',
    primaryContainer: '#0284c7',
    secondary: '#64748b',
    background: '#ffffff',
    surface: '#f8fafc',
    surfaceVariant: '#f1f5f9',
    text: '#0f172a',
    textSecondary: '#64748b',
    border: '#e2e8f0',
    error: '#ef4444',
    warning: '#f59e0b',
    success: '#10b981',
    info: '#3b82f6',
  },
  isDark: false,
  spacing: {
    xs: 4,
    sm: 8,
    md: 16,
    lg: 24,
    xl: 32,
  },
  borderRadius: {
    sm: 4,
    md: 8,
    lg: 12,
  },
  typography: {
    h1: { fontSize: 32, fontWeight: 'bold' },
    h2: { fontSize: 24, fontWeight: 'bold' },
    h3: { fontSize: 20, fontWeight: '600' },
    body: { fontSize: 16, fontWeight: 'normal' },
    caption: { fontSize: 14, fontWeight: 'normal' },
  },
};

const darkTheme: Theme = {
  colors: {
    primary: '#0ea5e9',
    primaryContainer: '#0284c7',
    secondary: '#64748b',
    background: '#000000',
    surface: '#18181b',
    surfaceVariant: '#27272a',
    text: '#fafafa',
    textSecondary: '#a1a1aa',
    border: '#3f3f46',
    error: '#f87171',
    warning: '#fbbf24',
    success: '#34d399',
    info: '#60a5fa',
  },
  isDark: true,
  spacing: {
    xs: 4,
    sm: 8,
    md: 16,
    lg: 24,
    xl: 32,
  },
  borderRadius: {
    sm: 4,
    md: 8,
    lg: 12,
  },
  typography: {
    h1: { fontSize: 32, fontWeight: 'bold' },
    h2: { fontSize: 24, fontWeight: 'bold' },
    h3: { fontSize: 20, fontWeight: '600' },
    body: { fontSize: 16, fontWeight: 'normal' },
    caption: { fontSize: 14, fontWeight: 'normal' },
  },
};

export interface ThemeContextType {
  theme: Theme;
  isDark: boolean;
  toggleTheme: () => void;
  setTheme: (themeName: 'light' | 'dark' | 'auto') => void;
  themeMode: 'light' | 'dark' | 'auto';
}

const ThemeContext = createContext<ThemeContextType | undefined>(undefined);

export const useTheme = (): ThemeContextType => {
  const context = useContext(ThemeContext);
  if (!context) {
    throw new Error('useTheme must be used within a ThemeProvider');
  }
  return context;
};

interface ThemeProviderProps {
  children: ReactNode;
}

export const ThemeProvider: React.FC<ThemeProviderProps> = ({ children }) => {
  const [themeMode, setThemeMode] = useState<'light' | 'dark' | 'auto'>('auto');
  const [systemColorScheme, setSystemColorScheme] = useState<ColorSchemeName>(
    Appearance.getColorScheme()
  );

  // Determine current theme based on mode and system preference
  const getCurrentTheme = (): Theme => {
    if (themeMode === 'auto') {
      return systemColorScheme === 'dark' ? darkTheme : lightTheme;
    }
    return themeMode === 'dark' ? darkTheme : lightTheme;
  };

  const [theme, setCurrentTheme] = useState<Theme>(getCurrentTheme());

  useEffect(() => {
    loadThemePreference();
    
    // Listen for system theme changes
    const subscription = Appearance.addChangeListener(({ colorScheme }) => {
      setSystemColorScheme(colorScheme);
    });

    return () => subscription?.remove();
  }, []);

  useEffect(() => {
    // Update theme when mode or system preference changes
    setCurrentTheme(getCurrentTheme());
  }, [themeMode, systemColorScheme]);

  const loadThemePreference = async () => {
    try {
      const savedTheme = await SecureStore.getItemAsync('theme_preference');
      if (savedTheme && ['light', 'dark', 'auto'].includes(savedTheme)) {
        setThemeMode(savedTheme as 'light' | 'dark' | 'auto');
      }
    } catch (error) {
      console.error('Failed to load theme preference:', error);
    }
  };

  const saveThemePreference = async (newTheme: 'light' | 'dark' | 'auto') => {
    try {
      await SecureStore.setItemAsync('theme_preference', newTheme);
    } catch (error) {
      console.error('Failed to save theme preference:', error);
    }
  };

  const setTheme = (themeName: 'light' | 'dark' | 'auto') => {
    setThemeMode(themeName);
    saveThemePreference(themeName);
  };

  const toggleTheme = () => {
    const newTheme = theme.isDark ? 'light' : 'dark';
    setTheme(newTheme);
  };

  const contextValue: ThemeContextType = {
    theme,
    isDark: theme.isDark,
    toggleTheme,
    setTheme,
    themeMode,
  };

  return (
    <ThemeContext.Provider value={contextValue}>
      {children}
    </ThemeContext.Provider>
  );
};

// Utility functions for theme-aware styling
export const createThemedStyles = (theme: Theme) => ({
  container: {
    backgroundColor: theme.colors.background,
    flex: 1,
  },
  surface: {
    backgroundColor: theme.colors.surface,
    borderRadius: theme.borderRadius.md,
  },
  card: {
    backgroundColor: theme.colors.surface,
    borderRadius: theme.borderRadius.lg,
    padding: theme.spacing.md,
    marginBottom: theme.spacing.md,
    shadowColor: theme.isDark ? '#000' : '#000',
    shadowOffset: { width: 0, height: 2 },
    shadowOpacity: theme.isDark ? 0.3 : 0.1,
    shadowRadius: 4,
    elevation: 4,
  },
  text: {
    color: theme.colors.text,
    fontSize: theme.typography.body.fontSize,
    fontWeight: theme.typography.body.fontWeight,
  },
  textSecondary: {
    color: theme.colors.textSecondary,
    fontSize: theme.typography.caption.fontSize,
  },
  heading: {
    color: theme.colors.text,
    fontSize: theme.typography.h2.fontSize,
    fontWeight: theme.typography.h2.fontWeight,
    marginBottom: theme.spacing.md,
  },
  button: {
    backgroundColor: theme.colors.primary,
    borderRadius: theme.borderRadius.md,
    padding: theme.spacing.md,
    alignItems: 'center' as const,
  },
  buttonText: {
    color: '#ffffff',
    fontSize: theme.typography.body.fontSize,
    fontWeight: '600',
  },
  input: {
    backgroundColor: theme.colors.surface,
    borderColor: theme.colors.border,
    borderWidth: 1,
    borderRadius: theme.borderRadius.md,
    padding: theme.spacing.md,
    color: theme.colors.text,
    fontSize: theme.typography.body.fontSize,
  },
  divider: {
    height: 1,
    backgroundColor: theme.colors.border,
    marginVertical: theme.spacing.md,
  },
});

// Severity color helpers
export const getSeverityColor = (severity: string, theme: Theme): string => {
  switch (severity.toLowerCase()) {
    case 'critical':
      return theme.colors.error;
    case 'high':
      return '#ff5722';
    case 'medium':
      return theme.colors.warning;
    case 'low':
      return theme.colors.success;
    default:
      return theme.colors.textSecondary;
  }
};

// Status color helpers
export const getStatusColor = (status: string, theme: Theme): string => {
  switch (status.toLowerCase()) {
    case 'completed':
    case 'success':
      return theme.colors.success;
    case 'running':
    case 'in_progress':
      return theme.colors.warning;
    case 'failed':
    case 'error':
      return theme.colors.error;
    case 'pending':
      return theme.colors.info;
    default:
      return theme.colors.textSecondary;
  }
};
