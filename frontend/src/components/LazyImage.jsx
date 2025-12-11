import React, { useState, useEffect, useRef, useCallback, useMemo } from 'react';
import { debounce } from 'lodash';

/**
 * Advanced lazy loading image component with progressive enhancement
 * Features: Intersection Observer, progressive loading, error handling, performance monitoring
 */
const LazyImage = ({
  src,
  alt = '',
  placeholder = null,
  className = '',
  style = {},
  onLoad,
  onError,
  threshold = 0.1,
  rootMargin = '50px',
  progressive = false,
  lowQualitySrc = null,
  webpSrc = null,
  avifSrc = null,
  sizes = '',
  loading = 'lazy',
  decoding = 'async',
  fetchPriority = 'auto',
  ...props
}) => {
  const [isLoaded, setIsLoaded] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [hasError, setHasError] = useState(false);
  const [currentSrc, setCurrentSrc] = useState(placeholder || lowQualitySrc);
  const [loadProgress, setLoadProgress] = useState(0);
  
  const imgRef = useRef(null);
  const observerRef = useRef(null);
  const loadStartTime = useRef(null);

  // Determine the best image format to use
  const optimizedSrc = useMemo(() => {
    // Check for modern format support
    if (avifSrc && supportsFormat('image/avif')) {
      return avifSrc;
    }
    if (webpSrc && supportsFormat('image/webp')) {
      return webpSrc;
    }
    return src;
  }, [src, webpSrc, avifSrc]);

  // Check if browser supports image format
  const supportsFormat = useCallback((format) => {
    const canvas = document.createElement('canvas');
    canvas.width = 1;
    canvas.height = 1;
    return canvas.toDataURL(format).indexOf(format) === 5;
  }, []);

  // Progressive image loading
  const loadImage = useCallback(async (imageSrc, isProgressive = false) => {
    if (!imageSrc) return;

    setIsLoading(true);
    setHasError(false);
    loadStartTime.current = performance.now();

    try {
      const img = new Image();
      
      // Set up progress tracking for progressive loading
      if (isProgressive && 'fetch' in window) {
        const response = await fetch(imageSrc);
        const reader = response.body.getReader();
        const contentLength = +response.headers.get('Content-Length');
        
        let receivedLength = 0;
        const chunks = [];
        
        while (true) {
          const { done, value } = await reader.read();
          
          if (done) break;
          
          chunks.push(value);
          receivedLength += value.length;
          
          const progress = (receivedLength / contentLength) * 100;
          setLoadProgress(progress);
        }
        
        const blob = new Blob(chunks);
        const imageUrl = URL.createObjectURL(blob);
        
        return new Promise((resolve, reject) => {
          img.onload = () => {
            URL.revokeObjectURL(imageUrl);
            resolve(img);
          };
          img.onerror = reject;
          img.src = imageUrl;
        });
      } else {
        return new Promise((resolve, reject) => {
          img.onload = () => resolve(img);
          img.onerror = reject;
          img.src = imageSrc;
        });
      }
    } catch (error) {
      throw error;
    }
  }, []);

  // Handle image load success
  const handleImageLoad = useCallback(async () => {
    try {
      // Load low quality first if progressive loading is enabled
      if (progressive && lowQualitySrc && !isLoaded) {
        await loadImage(lowQualitySrc);
        setCurrentSrc(lowQualitySrc);
        
        // Then load high quality
        await loadImage(optimizedSrc, true);
        setCurrentSrc(optimizedSrc);
      } else {
        await loadImage(optimizedSrc);
        setCurrentSrc(optimizedSrc);
      }

      const loadTime = performance.now() - loadStartTime.current;
      
      setIsLoaded(true);
      setIsLoading(false);
      setLoadProgress(100);
      
      // Performance logging
      if (loadTime > 1000) {
        console.warn(`Slow image load: ${optimizedSrc} took ${loadTime.toFixed(2)}ms`);
      }
      
      if (onLoad) {
        onLoad({
          src: optimizedSrc,
          loadTime,
          progressive: progressive && lowQualitySrc
        });
      }
    } catch (error) {
      handleImageError(error);
    }
  }, [optimizedSrc, lowQualitySrc, progressive, isLoaded, loadImage, onLoad]);

  // Handle image load error
  const handleImageError = useCallback((error) => {
    setHasError(true);
    setIsLoading(false);
    setLoadProgress(0);
    
    console.error('Image load error:', error);
    
    if (onError) {
      onError(error);
    }
  }, [onError]);

  // Intersection Observer setup
  useEffect(() => {
    if (!imgRef.current || isLoaded || isLoading) return;

    const options = {
      threshold,
      rootMargin
    };

    observerRef.current = new IntersectionObserver((entries) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting) {
          handleImageLoad();
          observerRef.current.unobserve(entry.target);
        }
      });
    }, options);

    observerRef.current.observe(imgRef.current);

    return () => {
      if (observerRef.current) {
        observerRef.current.disconnect();
      }
    };
  }, [isLoaded, isLoading, threshold, rootMargin, handleImageLoad]);

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      if (observerRef.current) {
        observerRef.current.disconnect();
      }
    };
  }, []);

  // Generate srcSet for responsive images
  const generateSrcSet = useCallback(() => {
    if (!sizes) return undefined;
    
    const srcSet = [];
    if (webpSrc) srcSet.push(`${webpSrc} 1x`);
    if (avifSrc) srcSet.push(`${avifSrc} 1x`);
    srcSet.push(`${src} 1x`);
    
    return srcSet.join(', ');
  }, [src, webpSrc, avifSrc, sizes]);

  // Render loading placeholder
  const renderPlaceholder = () => {
    if (placeholder) {
      return placeholder;
    }
    
    return (
      <div 
        className="animate-pulse bg-gray-300 flex items-center justify-center"
        style={{ width: '100%', height: '100%', minHeight: '200px' }}
      >
        <svg 
          className="w-12 h-12 text-gray-400" 
          fill="currentColor" 
          viewBox="0 0 20 20"
        >
          <path 
            fillRule="evenodd" 
            d="M4 3a2 2 0 00-2 2v10a2 2 0 002 2h12a2 2 0 002-2V5a2 2 0 00-2-2H4zm12 12H4l4-8 3 6 2-4 3 6z" 
            clipRule="evenodd" 
          />
        </svg>
      </div>
    );
  };

  // Render error state
  const renderError = () => (
    <div 
      className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded flex items-center justify-center"
      style={{ minHeight: '200px' }}
    >
      <div className="text-center">
        <svg className="w-12 h-12 mx-auto mb-2" fill="currentColor" viewBox="0 0 20 20">
          <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7 4a1 1 0 11-2 0 1 1 0 012 0zm-1-9a1 1 0 00-1 1v4a1 1 0 102 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
        </svg>
        <p>Failed to load image</p>
      </div>
    </div>
  );

  // Render progress bar for progressive loading
  const renderProgressBar = () => {
    if (!progressive || !isLoading || loadProgress === 0) return null;
    
    return (
      <div className="absolute bottom-0 left-0 right-0 bg-gray-200 h-1">
        <div 
          className="bg-blue-500 h-full transition-all duration-300 ease-out"
          style={{ width: `${loadProgress}%` }}
        />
      </div>
    );
  };

  const imageClasses = `
    ${className}
    ${isLoading ? 'opacity-75' : ''}
    ${isLoaded ? 'opacity-100' : 'opacity-0'}
    transition-opacity duration-300 ease-in-out
  `.trim();

  return (
    <div 
      ref={imgRef}
      className="relative overflow-hidden"
      style={style}
      {...props}
    >
      {/* Show placeholder while loading or if no src */}
      {(!isLoaded && !hasError) && renderPlaceholder()}
      
      {/* Show error state */}
      {hasError && renderError()}
      
      {/* Actual image */}
      {currentSrc && !hasError && (
        <img
          src={currentSrc}
          alt={alt}
          className={imageClasses}
          srcSet={generateSrcSet()}
          sizes={sizes}
          loading={loading}
          decoding={decoding}
          fetchpriority={fetchPriority}
          onLoad={() => {
            if (currentSrc === optimizedSrc) {
              setIsLoaded(true);
              setIsLoading(false);
            }
          }}
          onError={handleImageError}
        />
      )}
      
      {/* Progress bar for progressive loading */}
      {renderProgressBar()}
      
      {/* Loading indicator */}
      {isLoading && (
        <div className="absolute inset-0 flex items-center justify-center bg-black bg-opacity-20">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-white"></div>
        </div>
      )}
    </div>
  );
};

export default React.memo(LazyImage);

// Hook for managing multiple lazy images
export const useLazyImageBatch = (images = []) => {
  const [loadedImages, setLoadedImages] = useState(new Set());
  const [failedImages, setFailedImages] = useState(new Set());
  const [loadingImages, setLoadingImages] = useState(new Set());

  const handleImageLoad = useCallback((src) => {
    setLoadedImages(prev => new Set([...prev, src]));
    setLoadingImages(prev => {
      const next = new Set(prev);
      next.delete(src);
      return next;
    });
  }, []);

  const handleImageError = useCallback((src) => {
    setFailedImages(prev => new Set([...prev, src]));
    setLoadingImages(prev => {
      const next = new Set(prev);
      next.delete(src);
      return next;
    });
  }, []);

  const handleImageStart = useCallback((src) => {
    setLoadingImages(prev => new Set([...prev, src]));
  }, []);

  const getImageStatus = useCallback((src) => {
    if (loadedImages.has(src)) return 'loaded';
    if (failedImages.has(src)) return 'failed';
    if (loadingImages.has(src)) return 'loading';
    return 'pending';
  }, [loadedImages, failedImages, loadingImages]);

  const resetImage = useCallback((src) => {
    setLoadedImages(prev => {
      const next = new Set(prev);
      next.delete(src);
      return next;
    });
    setFailedImages(prev => {
      const next = new Set(prev);
      next.delete(src);
      return next;
    });
    setLoadingImages(prev => {
      const next = new Set(prev);
      next.delete(src);
      return next;
    });
  }, []);

  return {
    loadedImages,
    failedImages,
    loadingImages,
    handleImageLoad,
    handleImageError,
    handleImageStart,
    getImageStatus,
    resetImage,
    stats: {
      total: images.length,
      loaded: loadedImages.size,
      failed: failedImages.size,
      loading: loadingImages.size,
      pending: images.length - loadedImages.size - failedImages.size - loadingImages.size
    }
  };
};
