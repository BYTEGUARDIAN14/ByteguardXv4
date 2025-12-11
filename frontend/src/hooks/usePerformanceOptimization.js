import { useState, useEffect, useCallback, useMemo, useRef } from 'react';
import { debounce, throttle } from 'lodash';

/**
 * Advanced Performance Optimization Hook
 * Provides comprehensive performance monitoring and optimization utilities
 */
export const usePerformanceOptimization = () => {
  const [performanceMetrics, setPerformanceMetrics] = useState({
    renderTime: 0,
    memoryUsage: 0,
    componentCount: 0,
    reRenderCount: 0,
    lastUpdate: Date.now()
  });

  const renderStartTime = useRef(Date.now());
  const reRenderCount = useRef(0);
  const performanceObserver = useRef(null);

  // Performance monitoring
  useEffect(() => {
    const startTime = performance.now();
    renderStartTime.current = startTime;

    // Increment re-render count
    reRenderCount.current += 1;

    // Measure render time
    const measureRenderTime = () => {
      const endTime = performance.now();
      const renderTime = endTime - startTime;

      setPerformanceMetrics(prev => ({
        ...prev,
        renderTime,
        reRenderCount: reRenderCount.current,
        lastUpdate: Date.now()
      }));
    };

    // Use requestAnimationFrame for accurate timing
    const rafId = requestAnimationFrame(measureRenderTime);

    // Memory usage monitoring (if available)
    if ('memory' in performance) {
      const memoryInfo = performance.memory;
      setPerformanceMetrics(prev => ({
        ...prev,
        memoryUsage: memoryInfo.usedJSHeapSize / 1024 / 1024 // MB
      }));
    }

    return () => {
      cancelAnimationFrame(rafId);
    };
  });

  // Performance observer for detailed metrics
  useEffect(() => {
    if ('PerformanceObserver' in window) {
      performanceObserver.current = new PerformanceObserver((list) => {
        const entries = list.getEntries();
        
        entries.forEach(entry => {
          if (entry.entryType === 'measure') {
            console.log(`Performance measure: ${entry.name} - ${entry.duration}ms`);
          }
        });
      });

      performanceObserver.current.observe({ entryTypes: ['measure', 'navigation'] });
    }

    return () => {
      if (performanceObserver.current) {
        performanceObserver.current.disconnect();
      }
    };
  }, []);

  // Optimized debounced function creator
  const createDebouncedCallback = useCallback((callback, delay = 300) => {
    return debounce(callback, delay, {
      leading: false,
      trailing: true,
      maxWait: delay * 2
    });
  }, []);

  // Optimized throttled function creator
  const createThrottledCallback = useCallback((callback, delay = 100) => {
    return throttle(callback, delay, {
      leading: true,
      trailing: false
    });
  }, []);

  // Memoized value creator with dependency tracking
  const createMemoizedValue = useCallback((factory, deps) => {
    return useMemo(factory, deps);
  }, []);

  // Virtual scrolling helper
  const useVirtualScrolling = useCallback((items, itemHeight, containerHeight) => {
    const [scrollTop, setScrollTop] = useState(0);
    
    const visibleItems = useMemo(() => {
      const startIndex = Math.floor(scrollTop / itemHeight);
      const endIndex = Math.min(
        startIndex + Math.ceil(containerHeight / itemHeight) + 1,
        items.length
      );
      
      return {
        startIndex,
        endIndex,
        items: items.slice(startIndex, endIndex),
        totalHeight: items.length * itemHeight,
        offsetY: startIndex * itemHeight
      };
    }, [items, itemHeight, containerHeight, scrollTop]);

    const handleScroll = createThrottledCallback((e) => {
      setScrollTop(e.target.scrollTop);
    }, 16); // 60fps

    return {
      visibleItems,
      handleScroll,
      scrollTop
    };
  }, [createThrottledCallback]);

  // Image lazy loading optimization
  const useLazyLoading = useCallback(() => {
    const [loadedImages, setLoadedImages] = useState(new Set());
    const observerRef = useRef(null);

    useEffect(() => {
      if ('IntersectionObserver' in window) {
        observerRef.current = new IntersectionObserver(
          (entries) => {
            entries.forEach(entry => {
              if (entry.isIntersecting) {
                const img = entry.target;
                const src = img.dataset.src;
                
                if (src && !loadedImages.has(src)) {
                  img.src = src;
                  img.classList.remove('lazy');
                  img.classList.add('loaded');
                  
                  setLoadedImages(prev => new Set([...prev, src]));
                  observerRef.current.unobserve(img);
                }
              }
            });
          },
          {
            rootMargin: '50px 0px',
            threshold: 0.1
          }
        );
      }

      return () => {
        if (observerRef.current) {
          observerRef.current.disconnect();
        }
      };
    }, [loadedImages]);

    const observeImage = useCallback((imgElement) => {
      if (observerRef.current && imgElement) {
        observerRef.current.observe(imgElement);
      }
    }, []);

    return { observeImage, loadedImages };
  }, []);

  // Component performance profiler
  const useComponentProfiler = useCallback((componentName) => {
    const renderCount = useRef(0);
    const totalRenderTime = useRef(0);
    const lastRenderTime = useRef(0);

    useEffect(() => {
      const startTime = performance.now();
      
      return () => {
        const endTime = performance.now();
        const renderTime = endTime - startTime;
        
        renderCount.current += 1;
        totalRenderTime.current += renderTime;
        lastRenderTime.current = renderTime;

        // Log performance data
        if (renderTime > 16) { // Slower than 60fps
          console.warn(`Slow render detected in ${componentName}: ${renderTime.toFixed(2)}ms`);
        }

        // Performance mark for DevTools
        if ('performance' in window && 'mark' in performance) {
          performance.mark(`${componentName}-render-${renderCount.current}`);
        }
      };
    });

    return {
      renderCount: renderCount.current,
      averageRenderTime: renderCount.current > 0 ? totalRenderTime.current / renderCount.current : 0,
      lastRenderTime: lastRenderTime.current
    };
  }, []);

  // Bundle size analyzer
  const analyzeBundleSize = useCallback(() => {
    if ('performance' in window && 'getEntriesByType' in performance) {
      const resources = performance.getEntriesByType('resource');
      const jsResources = resources.filter(resource => 
        resource.name.includes('.js') || resource.name.includes('.jsx')
      );

      const totalSize = jsResources.reduce((total, resource) => {
        return total + (resource.transferSize || 0);
      }, 0);

      return {
        totalJSSize: totalSize,
        resourceCount: jsResources.length,
        resources: jsResources.map(resource => ({
          name: resource.name,
          size: resource.transferSize,
          loadTime: resource.duration
        }))
      };
    }

    return null;
  }, []);

  // Memory leak detector
  const useMemoryLeakDetector = useCallback(() => {
    const [memoryLeaks, setMemoryLeaks] = useState([]);
    const initialMemory = useRef(null);

    useEffect(() => {
      if ('memory' in performance) {
        initialMemory.current = performance.memory.usedJSHeapSize;

        const checkMemoryLeaks = setInterval(() => {
          const currentMemory = performance.memory.usedJSHeapSize;
          const memoryIncrease = currentMemory - initialMemory.current;
          
          // If memory increased by more than 10MB
          if (memoryIncrease > 10 * 1024 * 1024) {
            const leak = {
              timestamp: Date.now(),
              memoryIncrease: memoryIncrease / 1024 / 1024, // MB
              totalMemory: currentMemory / 1024 / 1024 // MB
            };

            setMemoryLeaks(prev => [...prev.slice(-9), leak]); // Keep last 10
            console.warn('Potential memory leak detected:', leak);
          }
        }, 5000); // Check every 5 seconds

        return () => clearInterval(checkMemoryLeaks);
      }
    }, []);

    return memoryLeaks;
  }, []);

  // Performance recommendations
  const getPerformanceRecommendations = useCallback(() => {
    const recommendations = [];

    if (performanceMetrics.renderTime > 16) {
      recommendations.push({
        type: 'RENDER_PERFORMANCE',
        severity: 'HIGH',
        message: 'Component render time exceeds 16ms (60fps threshold)',
        suggestion: 'Consider using React.memo, useMemo, or useCallback'
      });
    }

    if (performanceMetrics.reRenderCount > 10) {
      recommendations.push({
        type: 'EXCESSIVE_RERENDERS',
        severity: 'MEDIUM',
        message: 'Component is re-rendering frequently',
        suggestion: 'Check dependencies in useEffect and useMemo hooks'
      });
    }

    if (performanceMetrics.memoryUsage > 50) {
      recommendations.push({
        type: 'MEMORY_USAGE',
        severity: 'HIGH',
        message: 'High memory usage detected',
        suggestion: 'Check for memory leaks and optimize data structures'
      });
    }

    return recommendations;
  }, [performanceMetrics]);

  return {
    performanceMetrics,
    createDebouncedCallback,
    createThrottledCallback,
    createMemoizedValue,
    useVirtualScrolling,
    useLazyLoading,
    useComponentProfiler,
    useMemoryLeakDetector,
    analyzeBundleSize,
    getPerformanceRecommendations
  };
};

export default usePerformanceOptimization;
