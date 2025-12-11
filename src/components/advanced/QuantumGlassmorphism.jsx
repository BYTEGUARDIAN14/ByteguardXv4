/**
 * Quantum Glassmorphism Component Library
 * Next-generation transparency effects with advanced blur transitions
 */

import React, { useState, useEffect, useRef } from 'react';
import { motion, useMotionValue, useTransform, useSpring } from 'framer-motion';

// Quantum Glass Card with Dynamic Blur
export const QuantumGlassCard = ({ 
  children, 
  className = '', 
  variant = 'default',
  quantumEffect = true,
  blurIntensity = 'medium',
  glowColor = 'cyan',
  ...props 
}) => {
  const [isHovered, setIsHovered] = useState(false);
  const [mousePosition, setMousePosition] = useState({ x: 0, y: 0 });
  const cardRef = useRef(null);

  const blurLevels = {
    light: 'backdrop-blur-sm',
    medium: 'backdrop-blur-md',
    heavy: 'backdrop-blur-xl',
    quantum: 'backdrop-blur-2xl'
  };

  const glowColors = {
    cyan: 'shadow-cyan-500/20 hover:shadow-cyan-400/30',
    blue: 'shadow-blue-500/20 hover:shadow-blue-400/30',
    purple: 'shadow-purple-500/20 hover:shadow-purple-400/30',
    green: 'shadow-green-500/20 hover:shadow-green-400/30',
    red: 'shadow-red-500/20 hover:shadow-red-400/30'
  };

  const variants = {
    default: `
      bg-gradient-to-br from-white/10 via-white/5 to-transparent
      border border-white/20 hover:border-white/30
      ${blurLevels[blurIntensity]}
      ${glowColors[glowColor]}
    `,
    elevated: `
      bg-gradient-to-br from-white/15 via-white/8 to-white/2
      border border-white/25 hover:border-white/40
      ${blurLevels.heavy}
      shadow-2xl ${glowColors[glowColor]}
    `,
    minimal: `
      bg-white/5 hover:bg-white/10
      border border-white/10 hover:border-white/20
      ${blurLevels.light}
    `,
    quantum: `
      bg-gradient-to-br from-white/12 via-transparent to-white/8
      border-2 border-transparent
      ${blurLevels.quantum}
      relative overflow-hidden
    `
  };

  const handleMouseMove = (e) => {
    if (!cardRef.current) return;
    
    const rect = cardRef.current.getBoundingClientRect();
    const x = (e.clientX - rect.left) / rect.width;
    const y = (e.clientY - rect.top) / rect.height;
    
    setMousePosition({ x, y });
  };

  const quantumBorderStyle = quantumEffect && variant === 'quantum' ? {
    background: `linear-gradient(135deg, 
      rgba(6, 182, 212, ${isHovered ? 0.6 : 0.3}) 0%, 
      rgba(59, 130, 246, ${isHovered ? 0.4 : 0.2}) 50%, 
      rgba(147, 51, 234, ${isHovered ? 0.6 : 0.3}) 100%)`,
    padding: '2px',
    borderRadius: '1rem'
  } : {};

  return (
    <motion.div
      ref={cardRef}
      className={`
        relative rounded-2xl transition-all duration-500 ease-out
        ${variants[variant]}
        ${className}
      `}
      style={quantumBorderStyle}
      onMouseEnter={() => setIsHovered(true)}
      onMouseLeave={() => setIsHovered(false)}
      onMouseMove={handleMouseMove}
      whileHover={{ 
        scale: 1.02,
        y: -4,
        transition: { duration: 0.3, ease: 'easeOut' }
      }}
      {...props}
    >
      {/* Quantum Effect Overlay */}
      {quantumEffect && variant === 'quantum' && (
        <motion.div
          className="absolute inset-0 rounded-2xl opacity-0 hover:opacity-100 transition-opacity duration-500"
          style={{
            background: `radial-gradient(circle at ${mousePosition.x * 100}% ${mousePosition.y * 100}%, 
              rgba(6, 182, 212, 0.1) 0%, 
              transparent 50%)`
          }}
        />
      )}
      
      {/* Content Container */}
      <div className={variant === 'quantum' ? 'relative z-10 bg-black/20 rounded-2xl p-6' : 'p-6'}>
        {children}
      </div>
      
      {/* Animated Border Glow */}
      {quantumEffect && (
        <motion.div
          className="absolute inset-0 rounded-2xl opacity-0 hover:opacity-100 transition-opacity duration-500"
          style={{
            background: `conic-gradient(from ${mousePosition.x * 360}deg, 
              transparent, 
              rgba(6, 182, 212, 0.2), 
              transparent)`,
            filter: 'blur(2px)',
            zIndex: -1
          }}
        />
      )}
    </motion.div>
  );
};

// Adaptive Color Scheme Hook
export const useAdaptiveColorScheme = (threatLevel = 'low') => {
  const [colorScheme, setColorScheme] = useState('default');

  useEffect(() => {
    const schemes = {
      low: {
        primary: 'from-green-400 to-emerald-500',
        glass: 'from-green-500/10 to-emerald-500/5',
        border: 'border-green-400/30',
        glow: 'shadow-green-500/20'
      },
      medium: {
        primary: 'from-yellow-400 to-orange-500',
        glass: 'from-yellow-500/10 to-orange-500/5',
        border: 'border-yellow-400/30',
        glow: 'shadow-yellow-500/20'
      },
      high: {
        primary: 'from-red-400 to-rose-500',
        glass: 'from-red-500/10 to-rose-500/5',
        border: 'border-red-400/30',
        glow: 'shadow-red-500/20'
      },
      critical: {
        primary: 'from-purple-400 to-pink-500',
        glass: 'from-purple-500/10 to-pink-500/5',
        border: 'border-purple-400/30',
        glow: 'shadow-purple-500/20'
      },
      default: {
        primary: 'from-cyan-400 to-blue-500',
        glass: 'from-cyan-500/10 to-blue-500/5',
        border: 'border-cyan-400/30',
        glow: 'shadow-cyan-500/20'
      }
    };

    setColorScheme(schemes[threatLevel] || schemes.default);
  }, [threatLevel]);

  return colorScheme;
};

// Micro-Animation Components
export const MicroAnimationWrapper = ({ children, type = 'pulse', ...props }) => {
  const animations = {
    pulse: {
      scale: [1, 1.05, 1],
      transition: { duration: 2, repeat: Infinity, ease: 'easeInOut' }
    },
    glow: {
      boxShadow: [
        '0 0 20px rgba(6, 182, 212, 0.3)',
        '0 0 40px rgba(6, 182, 212, 0.6)',
        '0 0 20px rgba(6, 182, 212, 0.3)'
      ],
      transition: { duration: 3, repeat: Infinity, ease: 'easeInOut' }
    },
    float: {
      y: [0, -10, 0],
      transition: { duration: 4, repeat: Infinity, ease: 'easeInOut' }
    },
    shimmer: {
      backgroundPosition: ['0% 50%', '100% 50%', '0% 50%'],
      transition: { duration: 3, repeat: Infinity, ease: 'linear' }
    }
  };

  return (
    <motion.div
      animate={animations[type]}
      {...props}
    >
      {children}
    </motion.div>
  );
};

// Progressive Disclosure Component
export const ProgressiveDisclosure = ({ 
  title, 
  children, 
  defaultOpen = false,
  complexity = 'simple' 
}) => {
  const [isOpen, setIsOpen] = useState(defaultOpen);
  
  const complexityLevels = {
    simple: 'Basic Information',
    intermediate: 'Detailed Analysis',
    advanced: 'Expert Configuration',
    expert: 'Advanced Technical Details'
  };

  return (
    <QuantumGlassCard variant="minimal" className="mb-4">
      <motion.button
        className="w-full text-left flex items-center justify-between p-2"
        onClick={() => setIsOpen(!isOpen)}
        whileHover={{ scale: 1.01 }}
        whileTap={{ scale: 0.99 }}
      >
        <div>
          <h3 className="text-lg font-semibold text-white">{title}</h3>
          <span className="text-sm text-gray-400">{complexityLevels[complexity]}</span>
        </div>
        <motion.div
          animate={{ rotate: isOpen ? 180 : 0 }}
          transition={{ duration: 0.3 }}
          className="text-cyan-400"
        >
          ▼
        </motion.div>
      </motion.button>
      
      <motion.div
        initial={false}
        animate={{ 
          height: isOpen ? 'auto' : 0,
          opacity: isOpen ? 1 : 0
        }}
        transition={{ duration: 0.3, ease: 'easeInOut' }}
        className="overflow-hidden"
      >
        <div className="pt-4 border-t border-white/10">
          {children}
        </div>
      </motion.div>
    </QuantumGlassCard>
  );
};

// This is a component library file - use named exports
// Example: import { QuantumGlassCard, MicroAnimationWrapper } from './QuantumGlassmorphism'
