import React, { useState, forwardRef } from 'react'
import { motion } from 'framer-motion'
import { Eye, EyeOff, AlertCircle, CheckCircle } from 'lucide-react'

const Input = forwardRef(({ 
  type = 'text',
  label,
  placeholder,
  value,
  onChange,
  onFocus,
  onBlur,
  error,
  success,
  disabled = false,
  required = false,
  icon: Icon,
  iconPosition = 'left',
  className = '',
  ...props 
}, ref) => {
  const [focused, setFocused] = useState(false)
  const [showPassword, setShowPassword] = useState(false)

  const handleFocus = (e) => {
    setFocused(true)
    onFocus?.(e)
  }

  const handleBlur = (e) => {
    setFocused(false)
    onBlur?.(e)
  }

  const inputType = type === 'password' && showPassword ? 'text' : type

  const getStatusIcon = () => {
    if (error) return <AlertCircle className="h-4 w-4 text-red-400" />
    if (success) return <CheckCircle className="h-4 w-4 text-green-400" />
    return null
  }

  const getStatusColor = () => {
    if (error) return 'border-red-400/50 focus:border-red-400'
    if (success) return 'border-green-400/50 focus:border-green-400'
    if (focused) return 'border-cyan-400/50 focus:border-cyan-400'
    return 'border-white/20 focus:border-cyan-400/50'
  }

  return (
    <div className={`space-y-2 ${className}`}>
      {label && (
        <motion.label
          className={`block text-sm font-medium transition-colors duration-200 ${
            focused ? 'text-cyan-400' : 'text-gray-300'
          }`}
          initial={{ opacity: 0, y: -10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.2 }}
        >
          {label}
          {required && <span className="text-red-400 ml-1">*</span>}
        </motion.label>
      )}

      <div className="relative">
        {/* Left Icon */}
        {Icon && iconPosition === 'left' && (
          <div className="absolute left-3 top-1/2 transform -translate-y-1/2 z-10">
            <Icon className={`h-4 w-4 transition-colors duration-200 ${
              focused ? 'text-cyan-400' : 'text-gray-400'
            }`} />
          </div>
        )}

        <motion.input
          ref={ref}
          type={inputType}
          value={value}
          onChange={onChange}
          onFocus={handleFocus}
          onBlur={handleBlur}
          placeholder={placeholder}
          disabled={disabled}
          className={`
            w-full px-4 py-3 text-white placeholder-gray-400 
            bg-white/5 backdrop-blur-sm rounded-2xl border transition-all duration-300
            focus:outline-none focus:ring-2 focus:ring-cyan-400/20 focus:bg-white/10
            disabled:opacity-50 disabled:cursor-not-allowed
            ${Icon && iconPosition === 'left' ? 'pl-10' : ''}
            ${type === 'password' || getStatusIcon() ? 'pr-10' : ''}
            ${getStatusColor()}
          `}
          whileFocus={{ scale: 1.01 }}
          {...props}
        />

        {/* Right Icons */}
        <div className="absolute right-3 top-1/2 transform -translate-y-1/2 flex items-center space-x-2">
          {type === 'password' && (
            <motion.button
              type="button"
              onClick={() => setShowPassword(!showPassword)}
              className="text-gray-400 hover:text-cyan-400 transition-colors"
              whileHover={{ scale: 1.1 }}
              whileTap={{ scale: 0.9 }}
            >
              {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
            </motion.button>
          )}
          
          {getStatusIcon()}
          
          {Icon && iconPosition === 'right' && (
            <Icon className={`h-4 w-4 transition-colors duration-200 ${
              focused ? 'text-cyan-400' : 'text-gray-400'
            }`} />
          )}
        </div>

        {/* Focus Ring Animation */}
        <motion.div
          className="absolute inset-0 rounded-2xl pointer-events-none"
          initial={false}
          animate={focused ? {
            boxShadow: '0 0 0 2px rgba(6, 182, 212, 0.2), 0 0 20px rgba(6, 182, 212, 0.1)'
          } : {
            boxShadow: '0 0 0 0px rgba(6, 182, 212, 0)'
          }}
          transition={{ duration: 0.2 }}
        />
      </div>

      {/* Error/Success Message */}
      <motion.div
        initial={{ opacity: 0, height: 0 }}
        animate={{ 
          opacity: error || success ? 1 : 0, 
          height: error || success ? 'auto' : 0 
        }}
        transition={{ duration: 0.2 }}
        className="overflow-hidden"
      >
        {error && (
          <p className="text-red-400 text-sm flex items-center space-x-1">
            <AlertCircle className="h-3 w-3" />
            <span>{error}</span>
          </p>
        )}
        {success && (
          <p className="text-green-400 text-sm flex items-center space-x-1">
            <CheckCircle className="h-3 w-3" />
            <span>{success}</span>
          </p>
        )}
      </motion.div>
    </div>
  )
})

Input.displayName = 'Input'

export default Input
