import React from 'react'
import { motion } from 'framer-motion'
import { TrendingUp, TrendingDown } from 'lucide-react'
import GlassCard from '../ui/GlassCard'

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
  const colors = {
    cyan: 'text-cyan-400 border-cyan-400/30',
    green: 'text-green-400 border-green-400/30',
    red: 'text-red-400 border-red-400/30',
    yellow: 'text-yellow-400 border-yellow-400/30',
    blue: 'text-blue-400 border-blue-400/30'
  }

  const changeColors = {
    positive: 'text-green-400',
    negative: 'text-red-400',
    neutral: 'text-gray-400'
  }

  const TrendIcon = changeType === 'positive' ? TrendingUp : TrendingDown

  if (loading) {
    return (
      <GlassCard className="p-6">
        <div className="animate-pulse">
          <div className="flex items-center justify-between mb-4">
            <div className="h-4 bg-white/10 rounded w-20"></div>
            <div className="h-8 w-8 bg-white/10 rounded-lg"></div>
          </div>
          <div className="h-8 bg-white/10 rounded w-16 mb-2"></div>
          <div className="h-3 bg-white/10 rounded w-24"></div>
        </div>
      </GlassCard>
    )
  }

  return (
    <GlassCard 
      className="p-6 cursor-pointer group"
      onClick={onClick}
      hover={true}
      glow={true}
    >
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-sm font-medium text-gray-300 group-hover:text-white transition-colors">
          {title}
        </h3>
        {Icon && (
          <motion.div
            className={`p-2 rounded-lg border ${colors[color]} bg-white/5`}
            whileHover={{ scale: 1.1, rotate: 5 }}
            transition={{ duration: 0.2 }}
          >
            <Icon className="h-4 w-4" />
          </motion.div>
        )}
      </div>

      <div className="flex items-end justify-between">
        <div>
          <motion.div
            className="text-2xl font-bold text-white mb-1"
            initial={{ scale: 0.8, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            transition={{ duration: 0.5, delay: 0.1 }}
          >
            {value}
          </motion.div>
          
          {change && (
            <motion.div
              className={`flex items-center text-xs ${changeColors[changeType]}`}
              initial={{ opacity: 0, x: -10 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ duration: 0.3, delay: 0.2 }}
            >
              <TrendIcon className="h-3 w-3 mr-1" />
              {change}
            </motion.div>
          )}
        </div>
      </div>
    </GlassCard>
  )
}

export default StatsCard
