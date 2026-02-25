import React from 'react'
import { TrendingUp, TrendingDown } from 'lucide-react'

const StatsCard = ({
  title,
  value,
  change,
  changeType = 'neutral',
  icon: Icon,
  color = 'cyan',
  loading = false,
  onClick
}) => {
  const iconColors = {
    cyan: 'text-primary-400',
    green: 'text-emerald-400',
    red: 'text-red-400',
    yellow: 'text-amber-400',
    blue: 'text-blue-400'
  }

  const changeColors = {
    positive: 'text-emerald-400',
    negative: 'text-red-400',
    neutral: 'text-text-muted'
  }

  const TrendIcon = changeType === 'positive' ? TrendingUp : TrendingDown

  if (loading) {
    return (
      <div className="desktop-panel p-4">
        <div className="animate-pulse">
          <div className="flex items-center justify-between mb-3">
            <div className="h-3 bg-desktop-border rounded w-16"></div>
            <div className="h-7 w-7 bg-desktop-border rounded"></div>
          </div>
          <div className="h-6 bg-desktop-border rounded w-12 mb-2"></div>
          <div className="h-3 bg-desktop-border rounded w-20"></div>
        </div>
      </div>
    )
  }

  return (
    <div
      className={`desktop-card p-4 ${onClick ? 'cursor-pointer' : ''}`}
      onClick={onClick}
    >
      <div className="flex items-center justify-between mb-3">
        <span className="text-xs font-medium text-text-muted uppercase tracking-wider">
          {title}
        </span>
        {Icon && (
          <div className={`p-1.5 rounded-desktop bg-white/[0.04] ${iconColors[color]}`}>
            <Icon className="h-3.5 w-3.5" />
          </div>
        )}
      </div>

      <div className="text-xl font-semibold text-text-primary mb-1">
        {value}
      </div>

      {change && (
        <div className={`flex items-center gap-1 text-xs ${changeColors[changeType]}`}>
          <TrendIcon className="h-3 w-3" />
          <span>{change}</span>
        </div>
      )}
    </div>
  )
}

export default StatsCard
