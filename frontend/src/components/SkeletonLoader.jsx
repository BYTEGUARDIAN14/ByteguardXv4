import React, { useMemo } from 'react';

/**
 * Advanced skeleton loader system with customizable shapes and animations
 * Provides smooth loading states with realistic content placeholders
 */
const SkeletonLoader = ({
  variant = 'text',
  width = '100%',
  height = '1rem',
  className = '',
  animation = 'pulse',
  count = 1,
  spacing = '0.5rem',
  borderRadius = '0.25rem',
  baseColor = '#e2e8f0',
  highlightColor = '#f1f5f9',
  duration = '1.5s',
  direction = 'ltr',
  ...props
}) => {
  // Generate skeleton items based on count
  const skeletonItems = useMemo(() => {
    return Array.from({ length: count }, (_, index) => (
      <SkeletonItem
        key={index}
        variant={variant}
        width={width}
        height={height}
        animation={animation}
        borderRadius={borderRadius}
        baseColor={baseColor}
        highlightColor={highlightColor}
        duration={duration}
        direction={direction}
        style={{
          marginBottom: index < count - 1 ? spacing : 0
        }}
      />
    ));
  }, [count, variant, width, height, animation, borderRadius, baseColor, highlightColor, duration, direction, spacing]);

  return (
    <div className={`skeleton-container ${className}`} {...props}>
      {skeletonItems}
    </div>
  );
};

// Individual skeleton item component
const SkeletonItem = ({
  variant,
  width,
  height,
  animation,
  borderRadius,
  baseColor,
  highlightColor,
  duration,
  direction,
  style = {}
}) => {
  const skeletonStyle = useMemo(() => {
    const baseStyles = {
      width,
      height,
      backgroundColor: baseColor,
      borderRadius,
      position: 'relative',
      overflow: 'hidden',
      ...style
    };

    // Add animation styles
    if (animation === 'wave') {
      return {
        ...baseStyles,
        background: `linear-gradient(90deg, ${baseColor} 25%, ${highlightColor} 50%, ${baseColor} 75%)`,
        backgroundSize: '200% 100%',
        animation: `skeletonWave ${duration} ease-in-out infinite`
      };
    } else if (animation === 'pulse') {
      return {
        ...baseStyles,
        animation: `skeletonPulse ${duration} ease-in-out infinite`
      };
    } else if (animation === 'shimmer') {
      return {
        ...baseStyles,
        background: `linear-gradient(45deg, ${baseColor} 25%, transparent 25%, transparent 75%, ${baseColor} 75%, ${baseColor}), linear-gradient(45deg, ${baseColor} 25%, transparent 25%, transparent 75%, ${baseColor} 75%, ${baseColor})`,
        backgroundSize: '20px 20px',
        backgroundPosition: '0 0, 10px 10px',
        animation: `skeletonShimmer ${duration} linear infinite`
      };
    }

    return baseStyles;
  }, [variant, width, height, animation, borderRadius, baseColor, highlightColor, duration, style]);

  // Variant-specific adjustments
  const getVariantStyles = () => {
    switch (variant) {
      case 'circle':
        return { borderRadius: '50%' };
      case 'rectangular':
        return { borderRadius: '0' };
      case 'rounded':
        return { borderRadius: '0.5rem' };
      default:
        return {};
    }
  };

  return (
    <div
      className="skeleton-item"
      style={{
        ...skeletonStyle,
        ...getVariantStyles()
      }}
    />
  );
};

// Predefined skeleton templates for common UI patterns
export const SkeletonCard = ({ 
  showAvatar = true, 
  showTitle = true, 
  showDescription = true,
  showActions = true,
  className = ''
}) => (
  <div className={`p-4 border rounded-lg ${className}`}>
    {showAvatar && (
      <div className="flex items-center space-x-3 mb-4">
        <SkeletonLoader variant="circle" width="3rem" height="3rem" />
        <div className="flex-1">
          <SkeletonLoader width="40%" height="1rem" className="mb-2" />
          <SkeletonLoader width="60%" height="0.875rem" />
        </div>
      </div>
    )}
    
    {showTitle && (
      <SkeletonLoader width="80%" height="1.25rem" className="mb-3" />
    )}
    
    {showDescription && (
      <div className="space-y-2 mb-4">
        <SkeletonLoader width="100%" height="0.875rem" />
        <SkeletonLoader width="90%" height="0.875rem" />
        <SkeletonLoader width="75%" height="0.875rem" />
      </div>
    )}
    
    {showActions && (
      <div className="flex space-x-2">
        <SkeletonLoader width="5rem" height="2rem" borderRadius="0.375rem" />
        <SkeletonLoader width="5rem" height="2rem" borderRadius="0.375rem" />
      </div>
    )}
  </div>
);

export const SkeletonTable = ({ 
  rows = 5, 
  columns = 4,
  showHeader = true,
  className = ''
}) => (
  <div className={`w-full ${className}`}>
    {showHeader && (
      <div className="flex space-x-4 p-4 border-b">
        {Array.from({ length: columns }, (_, index) => (
          <SkeletonLoader
            key={index}
            width="25%"
            height="1rem"
            className="flex-1"
          />
        ))}
      </div>
    )}
    
    {Array.from({ length: rows }, (_, rowIndex) => (
      <div key={rowIndex} className="flex space-x-4 p-4 border-b last:border-b-0">
        {Array.from({ length: columns }, (_, colIndex) => (
          <SkeletonLoader
            key={colIndex}
            width="25%"
            height="0.875rem"
            className="flex-1"
          />
        ))}
      </div>
    ))}
  </div>
);

export const SkeletonList = ({ 
  items = 5,
  showAvatar = true,
  showSecondaryText = true,
  className = ''
}) => (
  <div className={`space-y-3 ${className}`}>
    {Array.from({ length: items }, (_, index) => (
      <div key={index} className="flex items-center space-x-3 p-3">
        {showAvatar && (
          <SkeletonLoader variant="circle" width="2.5rem" height="2.5rem" />
        )}
        <div className="flex-1">
          <SkeletonLoader width="60%" height="1rem" className="mb-1" />
          {showSecondaryText && (
            <SkeletonLoader width="40%" height="0.875rem" />
          )}
        </div>
      </div>
    ))}
  </div>
);

export const SkeletonChart = ({ 
  type = 'bar',
  className = ''
}) => {
  if (type === 'line') {
    return (
      <div className={`relative h-64 ${className}`}>
        <div className="absolute inset-0 flex items-end justify-between px-4 pb-4">
          {Array.from({ length: 7 }, (_, index) => (
            <div key={index} className="flex flex-col items-center space-y-2">
              <SkeletonLoader
                width="2px"
                height={`${Math.random() * 60 + 20}%`}
                borderRadius="1px"
              />
              <SkeletonLoader width="2rem" height="0.75rem" />
            </div>
          ))}
        </div>
      </div>
    );
  }

  return (
    <div className={`relative h-64 ${className}`}>
      <div className="absolute inset-0 flex items-end justify-between px-4 pb-4">
        {Array.from({ length: 6 }, (_, index) => (
          <SkeletonLoader
            key={index}
            width="3rem"
            height={`${Math.random() * 60 + 20}%`}
            borderRadius="0.25rem"
          />
        ))}
      </div>
    </div>
  );
};

export const SkeletonDashboard = ({ className = '' }) => (
  <div className={`space-y-6 ${className}`}>
    {/* Header */}
    <div className="flex justify-between items-center">
      <SkeletonLoader width="12rem" height="2rem" />
      <SkeletonLoader width="8rem" height="2.5rem" borderRadius="0.375rem" />
    </div>
    
    {/* Stats Cards */}
    <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
      {Array.from({ length: 4 }, (_, index) => (
        <div key={index} className="p-4 border rounded-lg">
          <SkeletonLoader width="60%" height="0.875rem" className="mb-2" />
          <SkeletonLoader width="40%" height="1.5rem" className="mb-1" />
          <SkeletonLoader width="30%" height="0.75rem" />
        </div>
      ))}
    </div>
    
    {/* Chart */}
    <div className="border rounded-lg p-4">
      <SkeletonLoader width="8rem" height="1.25rem" className="mb-4" />
      <SkeletonChart />
    </div>
    
    {/* Table */}
    <div className="border rounded-lg">
      <SkeletonTable rows={8} columns={5} />
    </div>
  </div>
);

// CSS animations (to be included in your global styles)
export const skeletonAnimations = `
  @keyframes skeletonPulse {
    0%, 100% {
      opacity: 1;
    }
    50% {
      opacity: 0.5;
    }
  }

  @keyframes skeletonWave {
    0% {
      background-position: -200% 0;
    }
    100% {
      background-position: 200% 0;
    }
  }

  @keyframes skeletonShimmer {
    0% {
      background-position: 0 0, 10px 10px;
    }
    100% {
      background-position: 20px 20px, 30px 30px;
    }
  }
`;

export default SkeletonLoader;
