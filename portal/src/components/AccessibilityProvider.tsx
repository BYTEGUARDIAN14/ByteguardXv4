/**
 * Accessibility Provider for ByteGuardX Portal
 * WCAG 2.1 AA compliance with keyboard navigation and screen reader support
 */

import React, { createContext, useContext, useEffect, useState } from 'react';

interface AccessibilityContextType {
  isHighContrast: boolean;
  fontSize: 'normal' | 'large' | 'extra-large';
  reducedMotion: boolean;
  screenReaderMode: boolean;
  keyboardNavigation: boolean;
  toggleHighContrast: () => void;
  setFontSize: (size: 'normal' | 'large' | 'extra-large') => void;
  toggleReducedMotion: () => void;
  announceToScreenReader: (message: string) => void;
}

const AccessibilityContext = createContext<AccessibilityContextType | undefined>(undefined);

export const useAccessibility = () => {
  const context = useContext(AccessibilityContext);
  if (!context) {
    throw new Error('useAccessibility must be used within AccessibilityProvider');
  }
  return context;
};

interface AccessibilityProviderProps {
  children: React.ReactNode;
}

export const AccessibilityProvider: React.FC<AccessibilityProviderProps> = ({ children }) => {
  const [isHighContrast, setIsHighContrast] = useState(false);
  const [fontSize, setFontSize] = useState<'normal' | 'large' | 'extra-large'>('normal');
  const [reducedMotion, setReducedMotion] = useState(false);
  const [screenReaderMode, setScreenReaderMode] = useState(false);
  const [keyboardNavigation, setKeyboardNavigation] = useState(false);

  // Detect user preferences
  useEffect(() => {
    // Check for reduced motion preference
    const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    setReducedMotion(prefersReducedMotion);

    // Check for high contrast preference
    const prefersHighContrast = window.matchMedia('(prefers-contrast: high)').matches;
    setIsHighContrast(prefersHighContrast);

    // Detect screen reader usage
    const hasScreenReader = window.navigator.userAgent.includes('NVDA') || 
                           window.navigator.userAgent.includes('JAWS') ||
                           window.speechSynthesis;
    setScreenReaderMode(hasScreenReader);

    // Load saved preferences
    const savedPreferences = localStorage.getItem('byteguardx-accessibility');
    if (savedPreferences) {
      try {
        const prefs = JSON.parse(savedPreferences);
        setIsHighContrast(prefs.isHighContrast ?? isHighContrast);
        setFontSize(prefs.fontSize ?? 'normal');
        setReducedMotion(prefs.reducedMotion ?? reducedMotion);
      } catch (error) {
        console.warn('Failed to load accessibility preferences:', error);
      }
    }
  }, []);

  // Keyboard navigation detection
  useEffect(() => {
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Tab') {
        setKeyboardNavigation(true);
      }
    };

    const handleMouseDown = () => {
      setKeyboardNavigation(false);
    };

    document.addEventListener('keydown', handleKeyDown);
    document.addEventListener('mousedown', handleMouseDown);

    return () => {
      document.removeEventListener('keydown', handleKeyDown);
      document.removeEventListener('mousedown', handleMouseDown);
    };
  }, []);

  // Apply accessibility styles
  useEffect(() => {
    const root = document.documentElement;
    
    // High contrast mode
    if (isHighContrast) {
      root.classList.add('high-contrast');
    } else {
      root.classList.remove('high-contrast');
    }

    // Font size
    root.classList.remove('font-large', 'font-extra-large');
    if (fontSize === 'large') {
      root.classList.add('font-large');
    } else if (fontSize === 'extra-large') {
      root.classList.add('font-extra-large');
    }

    // Reduced motion
    if (reducedMotion) {
      root.classList.add('reduced-motion');
    } else {
      root.classList.remove('reduced-motion');
    }

    // Keyboard navigation
    if (keyboardNavigation) {
      root.classList.add('keyboard-navigation');
    } else {
      root.classList.remove('keyboard-navigation');
    }

    // Save preferences
    const preferences = {
      isHighContrast,
      fontSize,
      reducedMotion
    };
    localStorage.setItem('byteguardx-accessibility', JSON.stringify(preferences));
  }, [isHighContrast, fontSize, reducedMotion, keyboardNavigation]);

  const toggleHighContrast = () => {
    setIsHighContrast(!isHighContrast);
  };

  const handleSetFontSize = (size: 'normal' | 'large' | 'extra-large') => {
    setFontSize(size);
  };

  const toggleReducedMotion = () => {
    setReducedMotion(!reducedMotion);
  };

  const announceToScreenReader = (message: string) => {
    const announcement = document.createElement('div');
    announcement.setAttribute('aria-live', 'polite');
    announcement.setAttribute('aria-atomic', 'true');
    announcement.className = 'sr-only';
    announcement.textContent = message;
    
    document.body.appendChild(announcement);
    
    setTimeout(() => {
      document.body.removeChild(announcement);
    }, 1000);
  };

  const value: AccessibilityContextType = {
    isHighContrast,
    fontSize,
    reducedMotion,
    screenReaderMode,
    keyboardNavigation,
    toggleHighContrast,
    setFontSize: handleSetFontSize,
    toggleReducedMotion,
    announceToScreenReader
  };

  return (
    <AccessibilityContext.Provider value={value}>
      {children}
    </AccessibilityContext.Provider>
  );
};

// Accessibility CSS classes to be added to global styles
export const accessibilityStyles = `
/* Screen reader only content */
.sr-only {
  position: absolute;
  width: 1px;
  height: 1px;
  padding: 0;
  margin: -1px;
  overflow: hidden;
  clip: rect(0, 0, 0, 0);
  white-space: nowrap;
  border: 0;
}

/* High contrast mode */
.high-contrast {
  --bg-primary: #000000;
  --bg-secondary: #1a1a1a;
  --text-primary: #ffffff;
  --text-secondary: #e0e0e0;
  --border-color: #ffffff;
  --accent-color: #00ffff;
  --focus-color: #ffff00;
}

.high-contrast .glassmorphism {
  background: rgba(255, 255, 255, 0.1) !important;
  border: 2px solid #ffffff !important;
}

/* Font size adjustments */
.font-large {
  font-size: 1.125rem;
}

.font-extra-large {
  font-size: 1.25rem;
}

/* Reduced motion */
.reduced-motion * {
  animation-duration: 0.01ms !important;
  animation-iteration-count: 1 !important;
  transition-duration: 0.01ms !important;
}

/* Keyboard navigation focus styles */
.keyboard-navigation *:focus {
  outline: 3px solid var(--focus-color, #00ffff) !important;
  outline-offset: 2px !important;
}

.keyboard-navigation button:focus,
.keyboard-navigation a:focus,
.keyboard-navigation input:focus,
.keyboard-navigation select:focus,
.keyboard-navigation textarea:focus {
  box-shadow: 0 0 0 3px var(--focus-color, #00ffff) !important;
}

/* Skip to content link */
.skip-to-content {
  position: absolute;
  top: -40px;
  left: 6px;
  background: var(--accent-color, #00ffff);
  color: var(--bg-primary, #000000);
  padding: 8px;
  text-decoration: none;
  border-radius: 4px;
  z-index: 1000;
  font-weight: bold;
}

.skip-to-content:focus {
  top: 6px;
}

/* Ensure sufficient color contrast for cyan accents */
.text-cyan-400 {
  color: #22d3ee;
}

.high-contrast .text-cyan-400 {
  color: #00ffff;
}

/* Focus indicators for interactive elements */
button, a, input, select, textarea, [tabindex]:not([tabindex="-1"]) {
  position: relative;
}

button:focus-visible,
a:focus-visible,
input:focus-visible,
select:focus-visible,
textarea:focus-visible,
[tabindex]:not([tabindex="-1"]):focus-visible {
  outline: 2px solid var(--focus-color, #00ffff);
  outline-offset: 2px;
}

/* Ensure interactive elements have minimum touch target size */
button, a, input[type="button"], input[type="submit"] {
  min-height: 44px;
  min-width: 44px;
}

/* Loading states with accessibility */
.loading-spinner[aria-label] {
  position: relative;
}

.loading-spinner[aria-label]::after {
  content: attr(aria-label);
  position: absolute;
  left: -9999px;
}
`;
