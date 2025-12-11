import React from 'react'
import { motion } from 'framer-motion'
import { Loader2 } from 'lucide-react'

const Button = ({
  children,
  variant = 'primary',
  size = 'md',
  loading = false,
  disabled = false,
  icon: Icon,
  iconPosition = 'left',
  fullWidth = false,
  glow = true,
  className = '',
  onClick,
  as: Component = 'button',
  ...props
}) => {
  // Base classes with glassmorphism foundation
  const baseClasses = `
    inline-flex items-center justify-center font-medium rounded-xl
    transition-all duration-300 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-offset-black
    disabled:opacity-50 disabled:cursor-not-allowed backdrop-blur-md relative overflow-hidden
    ${fullWidth ? 'w-full' : ''}
  `

  const variants = {
    primary: `
      bg-gradient-to-r from-cyan-600 via-cyan-500 to-blue-600 text-white 
      border border-cyan-400/20
      shadow-[0_0_20px_rgba(6,182,212,0.3)]
      hover:shadow-[0_0_30px_rgba(6,182,212,0.5)]
      hover:border-cyan-400/50
    `,
    secondary: `
      bg-white/5 border border-white/10 text-white
      hover:bg-white/10 hover:border-cyan-400/30 hover:text-cyan-400
      hover:shadow-[0_0_20px_rgba(6,182,212,0.15)]
    `,
    ghost: `
      text-gray-400 hover:text-cyan-400 hover:bg-white/5 
      border border-transparent hover:border-cyan-400/10
    `,
    danger: `
      bg-gradient-to-r from-red-600 to-red-500 text-white border border-red-500/30
      shadow-[0_0_20px_rgba(239,68,68,0.3)]
      hover:shadow-[0_0_30px_rgba(239,68,68,0.5)]
    `,
    success: `
      bg-gradient-to-r from-emerald-600 to-emerald-500 text-white border border-emerald-500/30
      shadow-[0_0_20px_rgba(16,185,129,0.3)]
      hover:shadow-[0_0_30px_rgba(16,185,129,0.5)]
    `
  }

  const sizes = {
    sm: 'px-4 py-2 text-sm gap-2',
    md: 'px-6 py-3 text-base gap-2.5',
    lg: 'px-8 py-4 text-lg gap-3',
    xl: 'px-10 py-5 text-xl gap-4 font-semibold'
  }

  const isDisabled = disabled || loading

  // Dynamic motion component
  const MotionComponent = motion(Component)

  return (
    <MotionComponent
      className={`${baseClasses} ${variants[variant]} ${sizes[size]} ${className}`}
      onClick={onClick}
      disabled={isDisabled}
      whileHover={!isDisabled ? { scale: 1.02, y: -1 } : {}}
      whileTap={!isDisabled ? { scale: 0.98 } : {}}
      initial={false}
      {...props}
    >
      {/* Loading State */}
      {loading ? (
        <Loader2 className="h-5 w-5 animate-spin" />
      ) : (
        <>
          {/* Left Icon */}
          {Icon && iconPosition === 'left' && (
            <Icon className="h-5 w-5" />
          )}

          {/* Content */}
          <span className="relative z-10">{children}</span>

          {/* Right Icon */}
          {Icon && iconPosition === 'right' && (
            <Icon className="h-5 w-5" />
          )}

          {/* Shine Effect Overlay for Primary */}
          {variant === 'primary' && !isDisabled && (
            <div className="absolute inset-0 -translate-x-full group-hover:animate-shine bg-gradient-to-r from-transparent via-white/10 to-transparent z-0" />
          )}
        </>
      )}
    </MotionComponent>
  )
}

export default Button
