import { useState, useEffect } from 'react';

// Breakpoint definitions
const breakpoints = {
  xs: 0,
  sm: 640,
  md: 768,
  lg: 1024,
  xl: 1280,
  '2xl': 1536,
} as const;

type Breakpoint = keyof typeof breakpoints;

// Hook for responsive design
export const useResponsive = () => {
  const [windowSize, setWindowSize] = useState({
    width: typeof window !== 'undefined' ? window.innerWidth : 1024,
    height: typeof window !== 'undefined' ? window.innerHeight : 768,
  });

  useEffect(() => {
    const handleResize = () => {
      setWindowSize({
        width: window.innerWidth,
        height: window.innerHeight,
      });
    };

    window.addEventListener('resize', handleResize);
    return () => window.removeEventListener('resize', handleResize);
  }, []);

  const isBreakpoint = (breakpoint: Breakpoint) => {
    return windowSize.width >= breakpoints[breakpoint];
  };

  const isMobile = windowSize.width < breakpoints.md;
  const isTablet = windowSize.width >= breakpoints.md && windowSize.width < breakpoints.lg;
  const isDesktop = windowSize.width >= breakpoints.lg;

  return {
    windowSize,
    isBreakpoint,
    isMobile,
    isTablet,
    isDesktop,
    breakpoints: {
      xs: isBreakpoint('xs'),
      sm: isBreakpoint('sm'),
      md: isBreakpoint('md'),
      lg: isBreakpoint('lg'),
      xl: isBreakpoint('xl'),
      '2xl': isBreakpoint('2xl'),
    },
  };
};

// Hook for media queries
export const useMediaQuery = (query: string) => {
  const [matches, setMatches] = useState(false);

  useEffect(() => {
    const media = window.matchMedia(query);
    if (media.matches !== matches) {
      setMatches(media.matches);
    }

    const listener = () => setMatches(media.matches);
    media.addEventListener('change', listener);
    return () => media.removeEventListener('change', listener);
  }, [matches, query]);

  return matches;
};

// Responsive container component
import React from 'react';

export const ResponsiveContainer: React.FC<{
  children: React.ReactNode;
  className?: string;
}> = ({ children, className = '' }) => {
  const { isMobile, isTablet } = useResponsive();

  const containerClasses = `
    w-full mx-auto px-4
    ${isMobile ? 'max-w-full' : ''}
    ${isTablet ? 'max-w-4xl px-6' : ''}
    ${!isMobile && !isTablet ? 'max-w-7xl px-8' : ''}
    ${className}
  `;

  return React.createElement('div', { className: containerClasses }, children);
};
