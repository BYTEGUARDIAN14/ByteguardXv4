import { useState, useEffect, useCallback, useRef } from 'react';

/**
 * Advanced Accessibility Hooks
 * Features: Keyboard navigation, screen reader support, focus management, ARIA
 */

// Main accessibility hook
export const useAccessibility = () => {
  const [isKeyboardUser, setIsKeyboardUser] = useState(false);
  const [reducedMotion, setReducedMotion] = useState(false);
  const [highContrast, setHighContrast] = useState(false);
  const [fontSize, setFontSize] = useState('normal');

  useEffect(() => {
    // Detect keyboard usage
    const handleKeyDown = (e) => {
      if (e.key === 'Tab') {
        setIsKeyboardUser(true);
        document.body.classList.add('keyboard-user');
      }
    };

    const handleMouseDown = () => {
      setIsKeyboardUser(false);
      document.body.classList.remove('keyboard-user');
    };

    // Check for reduced motion preference
    const mediaQuery = window.matchMedia('(prefers-reduced-motion: reduce)');
    setReducedMotion(mediaQuery.matches);
    
    const handleMotionChange = (e) => setReducedMotion(e.matches);
    mediaQuery.addEventListener('change', handleMotionChange);

    // Check for high contrast preference
    const contrastQuery = window.matchMedia('(prefers-contrast: high)');
    setHighContrast(contrastQuery.matches);
    
    const handleContrastChange = (e) => setHighContrast(e.matches);
    contrastQuery.addEventListener('change', handleContrastChange);

    // Load saved preferences
    const savedFontSize = localStorage.getItem('byteguardx-font-size');
    if (savedFontSize) {
      setFontSize(savedFontSize);
      document.documentElement.style.fontSize = getFontSizeValue(savedFontSize);
    }

    document.addEventListener('keydown', handleKeyDown);
    document.addEventListener('mousedown', handleMouseDown);

    return () => {
      document.removeEventListener('keydown', handleKeyDown);
      document.removeEventListener('mousedown', handleMouseDown);
      mediaQuery.removeEventListener('change', handleMotionChange);
      contrastQuery.removeEventListener('change', handleContrastChange);
    };
  }, []);

  const changeFontSize = useCallback((size) => {
    setFontSize(size);
    document.documentElement.style.fontSize = getFontSizeValue(size);
    localStorage.setItem('byteguardx-font-size', size);
  }, []);

  const getFontSizeValue = (size) => {
    const sizes = {
      small: '14px',
      normal: '16px',
      large: '18px',
      xlarge: '20px'
    };
    return sizes[size] || sizes.normal;
  };

  return {
    isKeyboardUser,
    reducedMotion,
    highContrast,
    fontSize,
    changeFontSize
  };
};

// Keyboard navigation hook
export const useKeyboardNavigation = (items = [], options = {}) => {
  const {
    loop = true,
    orientation = 'vertical', // 'vertical' | 'horizontal' | 'both'
    onSelect,
    disabled = false
  } = options;

  const [activeIndex, setActiveIndex] = useState(-1);
  const itemRefs = useRef([]);

  const handleKeyDown = useCallback((event) => {
    if (disabled || items.length === 0) return;

    const { key } = event;
    let newIndex = activeIndex;

    switch (key) {
      case 'ArrowDown':
        if (orientation === 'vertical' || orientation === 'both') {
          event.preventDefault();
          newIndex = activeIndex + 1;
          if (newIndex >= items.length) {
            newIndex = loop ? 0 : items.length - 1;
          }
        }
        break;

      case 'ArrowUp':
        if (orientation === 'vertical' || orientation === 'both') {
          event.preventDefault();
          newIndex = activeIndex - 1;
          if (newIndex < 0) {
            newIndex = loop ? items.length - 1 : 0;
          }
        }
        break;

      case 'ArrowRight':
        if (orientation === 'horizontal' || orientation === 'both') {
          event.preventDefault();
          newIndex = activeIndex + 1;
          if (newIndex >= items.length) {
            newIndex = loop ? 0 : items.length - 1;
          }
        }
        break;

      case 'ArrowLeft':
        if (orientation === 'horizontal' || orientation === 'both') {
          event.preventDefault();
          newIndex = activeIndex - 1;
          if (newIndex < 0) {
            newIndex = loop ? items.length - 1 : 0;
          }
        }
        break;

      case 'Home':
        event.preventDefault();
        newIndex = 0;
        break;

      case 'End':
        event.preventDefault();
        newIndex = items.length - 1;
        break;

      case 'Enter':
      case ' ':
        if (activeIndex >= 0 && onSelect) {
          event.preventDefault();
          onSelect(items[activeIndex], activeIndex);
        }
        break;

      case 'Escape':
        event.preventDefault();
        setActiveIndex(-1);
        break;

      default:
        return;
    }

    if (newIndex !== activeIndex) {
      setActiveIndex(newIndex);
      
      // Focus the new active item
      if (itemRefs.current[newIndex]) {
        itemRefs.current[newIndex].focus();
      }
    }
  }, [activeIndex, items, loop, orientation, onSelect, disabled]);

  const getItemProps = useCallback((index) => ({
    ref: (el) => {
      itemRefs.current[index] = el;
    },
    tabIndex: activeIndex === index ? 0 : -1,
    'aria-selected': activeIndex === index,
    onKeyDown: handleKeyDown,
    onFocus: () => setActiveIndex(index),
    role: 'option'
  }), [activeIndex, handleKeyDown]);

  const getContainerProps = useCallback(() => ({
    role: 'listbox',
    'aria-activedescendant': activeIndex >= 0 ? `item-${activeIndex}` : undefined,
    onKeyDown: handleKeyDown
  }), [activeIndex, handleKeyDown]);

  return {
    activeIndex,
    setActiveIndex,
    getItemProps,
    getContainerProps
  };
};

// Focus management hook
export const useFocusManagement = () => {
  const focusHistoryRef = useRef([]);
  const trapRef = useRef(null);

  const saveFocus = useCallback(() => {
    const activeElement = document.activeElement;
    if (activeElement && activeElement !== document.body) {
      focusHistoryRef.current.push(activeElement);
    }
  }, []);

  const restoreFocus = useCallback(() => {
    const lastFocused = focusHistoryRef.current.pop();
    if (lastFocused && typeof lastFocused.focus === 'function') {
      lastFocused.focus();
    }
  }, []);

  const trapFocus = useCallback((container) => {
    if (!container) return;

    trapRef.current = container;
    
    const focusableElements = container.querySelectorAll(
      'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
    );
    
    const firstElement = focusableElements[0];
    const lastElement = focusableElements[focusableElements.length - 1];

    const handleKeyDown = (e) => {
      if (e.key === 'Tab') {
        if (e.shiftKey) {
          if (document.activeElement === firstElement) {
            e.preventDefault();
            lastElement.focus();
          }
        } else {
          if (document.activeElement === lastElement) {
            e.preventDefault();
            firstElement.focus();
          }
        }
      }
    };

    container.addEventListener('keydown', handleKeyDown);
    
    // Focus first element
    if (firstElement) {
      firstElement.focus();
    }

    return () => {
      container.removeEventListener('keydown', handleKeyDown);
    };
  }, []);

  const releaseFocusTrap = useCallback(() => {
    trapRef.current = null;
  }, []);

  return {
    saveFocus,
    restoreFocus,
    trapFocus,
    releaseFocusTrap
  };
};

// Screen reader announcements hook
export const useScreenReader = () => {
  const announcementRef = useRef(null);

  useEffect(() => {
    // Create live region for announcements
    const liveRegion = document.createElement('div');
    liveRegion.setAttribute('aria-live', 'polite');
    liveRegion.setAttribute('aria-atomic', 'true');
    liveRegion.style.position = 'absolute';
    liveRegion.style.left = '-10000px';
    liveRegion.style.width = '1px';
    liveRegion.style.height = '1px';
    liveRegion.style.overflow = 'hidden';
    
    document.body.appendChild(liveRegion);
    announcementRef.current = liveRegion;

    return () => {
      if (announcementRef.current) {
        document.body.removeChild(announcementRef.current);
      }
    };
  }, []);

  const announce = useCallback((message, priority = 'polite') => {
    if (announcementRef.current) {
      announcementRef.current.setAttribute('aria-live', priority);
      announcementRef.current.textContent = message;
      
      // Clear after announcement
      setTimeout(() => {
        if (announcementRef.current) {
          announcementRef.current.textContent = '';
        }
      }, 1000);
    }
  }, []);

  return { announce };
};

// ARIA attributes hook
export const useARIA = () => {
  const generateId = useCallback((prefix = 'aria') => {
    return `${prefix}-${Math.random().toString(36).substr(2, 9)}`;
  }, []);

  const getDescribedByProps = useCallback((description) => {
    const id = generateId('desc');
    return {
      'aria-describedby': id,
      descriptionProps: {
        id,
        children: description,
        className: 'sr-only'
      }
    };
  }, [generateId]);

  const getLabelledByProps = useCallback((label) => {
    const id = generateId('label');
    return {
      'aria-labelledby': id,
      labelProps: {
        id,
        children: label
      }
    };
  }, [generateId]);

  const getExpandedProps = useCallback((isExpanded) => ({
    'aria-expanded': isExpanded,
    'aria-haspopup': true
  }), []);

  return {
    generateId,
    getDescribedByProps,
    getLabelledByProps,
    getExpandedProps
  };
};

// Skip links hook
export const useSkipLinks = () => {
  const skipLinksRef = useRef([]);

  const addSkipLink = useCallback((target, label) => {
    const link = {
      target,
      label,
      id: `skip-${Math.random().toString(36).substr(2, 9)}`
    };
    
    skipLinksRef.current.push(link);
    return link.id;
  }, []);

  const SkipLinks = useCallback(() => (
    <div className="skip-links">
      {skipLinksRef.current.map((link) => (
        <a
          key={link.id}
          href={`#${link.target}`}
          className="skip-link sr-only focus:not-sr-only focus:absolute focus:top-0 focus:left-0 focus:z-50 focus:p-4 focus:bg-primary focus:text-primary-content"
        >
          {link.label}
        </a>
      ))}
    </div>
  ), []);

  return { addSkipLink, SkipLinks };
};

// Accessibility testing hook (development only)
export const useA11yTesting = () => {
  const [violations, setViolations] = useState([]);

  useEffect(() => {
    if (process.env.NODE_ENV === 'development') {
      // Load axe-core for accessibility testing
      import('axe-core').then((axe) => {
        const runTests = () => {
          axe.run().then((results) => {
            setViolations(results.violations);
            
            if (results.violations.length > 0) {
              console.group('🚨 Accessibility Violations');
              results.violations.forEach((violation) => {
                console.error(violation.description);
                console.log('Help:', violation.helpUrl);
                console.log('Elements:', violation.nodes);
              });
              console.groupEnd();
            }
          });
        };

        // Run tests on mount and when DOM changes
        runTests();
        
        const observer = new MutationObserver(() => {
          setTimeout(runTests, 1000); // Debounce
        });
        
        observer.observe(document.body, {
          childList: true,
          subtree: true
        });

        return () => observer.disconnect();
      });
    }
  }, []);

  return { violations };
};

export default useAccessibility;
