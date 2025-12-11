import React from 'react'
import { motion } from 'framer-motion'

const GlassCard = ({ 
  children, 
  className = '', 
  variant = 'default',
  hover = true,
  glow = false,
  onClick,
  ...props 
}) => {
  const variants = {
    default: 'glass-card',
    elevated: 'glass-card shadow-2xl',
    minimal: 'glass-panel',
    interactive: 'glass-card cursor-pointer hover:shadow-cyan-500/20',
    danger: 'glass-card border-red-500/30 hover:border-red-400/50',
    success: 'glass-card border-green-500/30 hover:border-green-400/50',
    warning: 'glass-card border-yellow-500/30 hover:border-yellow-400/50'
  }

  const hoverEffects = hover ? {
    whileHover: { 
      scale: 1.02,
      y: -4,
      transition: { duration: 0.2, ease: 'easeOut' }
    },
    whileTap: { scale: 0.98 }
  } : {}

  const glowClass = glow ? 'hover-glow' : ''

  return (
    <motion.div
      className={`${variants[variant]} ${glowClass} ${className}`}
      onClick={onClick}
      {...hoverEffects}
      {...props}
    >
      {children}
    </motion.div>
  )
}

export default GlassCard
