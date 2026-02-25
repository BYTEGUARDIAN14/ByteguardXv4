import React from 'react'

const GlassCard = ({
  children,
  className = '',
  variant = 'default',
  hover = true,
  onClick,
  ...props
}) => {
  const baseClass = hover ? 'desktop-card' : 'desktop-panel'

  return (
    <div
      className={`${baseClass} ${className}`}
      onClick={onClick}
      style={onClick ? { cursor: 'pointer' } : undefined}
      {...props}
    >
      {children}
    </div>
  )
}

export default GlassCard
