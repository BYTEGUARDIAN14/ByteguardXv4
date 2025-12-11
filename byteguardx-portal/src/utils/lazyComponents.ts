import { lazy } from 'react';

// Lazy load heavy components for better performance
export const LazyComponents = {
  // Main sections
  HeroSection: lazy(() => import('../components/sections/HeroSection')),
  FeaturesSection: lazy(() => import('../components/sections/FeaturesSection')),
  ComparisonSection: lazy(() => import('../components/sections/ComparisonSection')),
  PricingSection: lazy(() => import('../components/sections/PricingSection')),
  GallerySection: lazy(() => import('../components/sections/GallerySection')),
  
  // Pages
  Compare: lazy(() => import('../pages/Compare')),
  Docs: lazy(() => import('../pages/Docs')),
  Download: lazy(() => import('../pages/Download')),
  Extensions: lazy(() => import('../pages/Extensions')),
  Support: lazy(() => import('../pages/Support')),
  
  // Heavy components
  CodeEditor: lazy(() => import('../components/CodeEditor')),
  Dashboard: lazy(() => import('../components/Dashboard')),
  Analytics: lazy(() => import('../components/Analytics'))
};

// Loading fallback component
export const LoadingFallback = () => (
  <div className="flex items-center justify-center min-h-[200px]">
    <div className="flex flex-col items-center space-y-4">
      <div className="animate-spin rounded-full h-8 w-8 border-2 border-cyan-400 border-t-transparent"></div>
      <p className="text-gray-400 text-sm">Loading...</p>
    </div>
  </div>
);

// Preload critical components
export const preloadCriticalComponents = () => {
  // Preload components that are likely to be needed soon
  LazyComponents.HeroSection();
  LazyComponents.FeaturesSection();
};

// Progressive loading utility
export const useProgressiveLoading = (componentName: keyof typeof LazyComponents) => {
  const Component = LazyComponents[componentName];
  
  // Preload on hover/focus for better UX
  const preload = () => {
    Component();
  };
  
  return { Component, preload };
};
