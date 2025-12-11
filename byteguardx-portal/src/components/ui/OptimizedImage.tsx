import React, { useState, useRef, useEffect } from 'react';
import { motion } from 'framer-motion';

interface OptimizedImageProps {
  src: string;
  alt: string;
  width?: number;
  height?: number;
  className?: string;
  lazy?: boolean;
  placeholder?: string;
  quality?: number;
  priority?: boolean;
}

const OptimizedImage: React.FC<OptimizedImageProps> = ({
  src,
  alt,
  width,
  height,
  className = '',
  lazy = true,
  placeholder,
  quality = 85,
  priority = false
}) => {
  const [isLoaded, setIsLoaded] = useState(false);
  const [isInView, setIsInView] = useState(!lazy || priority);
  const [error, setError] = useState(false);
  const imgRef = useRef<HTMLImageElement>(null);

  // Intersection Observer for lazy loading
  useEffect(() => {
    if (!lazy || priority) return;

    const observer = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting) {
          setIsInView(true);
          observer.disconnect();
        }
      },
      { threshold: 0.1, rootMargin: '50px' }
    );

    if (imgRef.current) {
      observer.observe(imgRef.current);
    }

    return () => observer.disconnect();
  }, [lazy, priority]);

  // Generate optimized src with query parameters
  const getOptimizedSrc = (originalSrc: string) => {
    const url = new URL(originalSrc, window.location.origin);
    
    if (width) url.searchParams.set('w', width.toString());
    if (height) url.searchParams.set('h', height.toString());
    if (quality !== 85) url.searchParams.set('q', quality.toString());
    
    return url.toString();
  };

  // Generate WebP version if supported
  const getWebPSrc = (originalSrc: string) => {
    if (originalSrc.includes('.svg')) return null;
    return originalSrc.replace(/\.(jpg|jpeg|png)$/i, '.webp');
  };

  const optimizedSrc = getOptimizedSrc(src);
  const webpSrc = getWebPSrc(src);

  const handleLoad = () => {
    setIsLoaded(true);
  };

  const handleError = () => {
    setError(true);
    setIsLoaded(true);
  };

  if (error) {
    return (
      <div 
        className={`bg-gray-800 border border-gray-700 rounded-lg flex items-center justify-center ${className}`}
        style={{ width, height }}
      >
        <span className="text-gray-500 text-sm">Failed to load image</span>
      </div>
    );
  }

  return (
    <div className={`relative overflow-hidden ${className}`} ref={imgRef}>
      {/* Placeholder */}
      {!isLoaded && (
        <div 
          className="absolute inset-0 bg-gray-800 animate-pulse flex items-center justify-center"
          style={{ width, height }}
        >
          {placeholder ? (
            <img src={placeholder} alt="" className="opacity-50" />
          ) : (
            <div className="w-8 h-8 bg-gray-700 rounded animate-pulse" />
          )}
        </div>
      )}

      {/* Actual image */}
      {isInView && (
        <picture>
          {webpSrc && (
            <source srcSet={webpSrc} type="image/webp" />
          )}
          <motion.img
            src={optimizedSrc}
            alt={alt}
            width={width}
            height={height}
            onLoad={handleLoad}
            onError={handleError}
            className={`transition-opacity duration-300 ${
              isLoaded ? 'opacity-100' : 'opacity-0'
            }`}
            loading={lazy && !priority ? 'lazy' : 'eager'}
            initial={{ opacity: 0 }}
            animate={{ opacity: isLoaded ? 1 : 0 }}
            transition={{ duration: 0.3 }}
          />
        </picture>
      )}
    </div>
  );
};

export default OptimizedImage;
