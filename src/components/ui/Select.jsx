import React, { useState, useRef, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { ChevronDown, Check, Search } from 'lucide-react'

const Select = ({ 
  options = [], 
  value, 
  onChange, 
  placeholder = 'Select option...',
  label,
  error,
  disabled = false,
  searchable = false,
  multiple = false,
  className = ''
}) => {
  const [isOpen, setIsOpen] = useState(false)
  const [searchTerm, setSearchTerm] = useState('')
  const [focusedIndex, setFocusedIndex] = useState(-1)
  const selectRef = useRef(null)
  const searchRef = useRef(null)

  const filteredOptions = searchable 
    ? options.filter(option => 
        option.label.toLowerCase().includes(searchTerm.toLowerCase())
      )
    : options

  useEffect(() => {
    const handleClickOutside = (event) => {
      if (selectRef.current && !selectRef.current.contains(event.target)) {
        setIsOpen(false)
        setSearchTerm('')
        setFocusedIndex(-1)
      }
    }

    document.addEventListener('mousedown', handleClickOutside)
    return () => document.removeEventListener('mousedown', handleClickOutside)
  }, [])

  useEffect(() => {
    if (isOpen && searchable && searchRef.current) {
      searchRef.current.focus()
    }
  }, [isOpen, searchable])

  const handleKeyDown = (e) => {
    if (!isOpen) {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault()
        setIsOpen(true)
      }
      return
    }

    switch (e.key) {
      case 'Escape':
        setIsOpen(false)
        setFocusedIndex(-1)
        break
      case 'ArrowDown':
        e.preventDefault()
        setFocusedIndex(prev => 
          prev < filteredOptions.length - 1 ? prev + 1 : 0
        )
        break
      case 'ArrowUp':
        e.preventDefault()
        setFocusedIndex(prev => 
          prev > 0 ? prev - 1 : filteredOptions.length - 1
        )
        break
      case 'Enter':
        e.preventDefault()
        if (focusedIndex >= 0) {
          handleSelect(filteredOptions[focusedIndex])
        }
        break
    }
  }

  const handleSelect = (option) => {
    if (multiple) {
      const newValue = Array.isArray(value) ? [...value] : []
      const index = newValue.findIndex(v => v.value === option.value)
      
      if (index >= 0) {
        newValue.splice(index, 1)
      } else {
        newValue.push(option)
      }
      
      onChange(newValue)
    } else {
      onChange(option)
      setIsOpen(false)
    }
    
    setFocusedIndex(-1)
  }

  const isSelected = (option) => {
    if (multiple) {
      return Array.isArray(value) && value.some(v => v.value === option.value)
    }
    return value?.value === option.value
  }

  const getDisplayValue = () => {
    if (multiple && Array.isArray(value) && value.length > 0) {
      return value.length === 1 
        ? value[0].label 
        : `${value.length} selected`
    }
    return value?.label || placeholder
  }

  return (
    <div className={`relative ${className}`} ref={selectRef}>
      {label && (
        <label className="block text-sm font-medium text-gray-300 mb-2">
          {label}
        </label>
      )}

      <motion.button
        type="button"
        onClick={() => !disabled && setIsOpen(!isOpen)}
        onKeyDown={handleKeyDown}
        disabled={disabled}
        className={`
          w-full px-4 py-3 text-left bg-white/5 backdrop-blur-sm rounded-2xl border
          transition-all duration-300 focus:outline-none focus:ring-2 focus:ring-cyan-400/20
          disabled:opacity-50 disabled:cursor-not-allowed
          ${isOpen ? 'border-cyan-400/50' : 'border-white/20 hover:border-cyan-400/30'}
          ${error ? 'border-red-400/50' : ''}
        `}
        whileHover={!disabled ? { scale: 1.01 } : {}}
        whileTap={!disabled ? { scale: 0.99 } : {}}
      >
        <div className="flex items-center justify-between">
          <span className={`truncate ${
            value ? 'text-white' : 'text-gray-400'
          }`}>
            {getDisplayValue()}
          </span>
          
          <motion.div
            animate={{ rotate: isOpen ? 180 : 0 }}
            transition={{ duration: 0.2 }}
          >
            <ChevronDown className="h-4 w-4 text-gray-400" />
          </motion.div>
        </div>
      </motion.button>

      <AnimatePresence>
        {isOpen && (
          <motion.div
            initial={{ opacity: 0, y: -10, scale: 0.95 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: -10, scale: 0.95 }}
            transition={{ duration: 0.2 }}
            className="absolute z-50 w-full mt-2 glass-card border border-white/20 rounded-2xl shadow-2xl max-h-60 overflow-hidden"
          >
            {searchable && (
              <div className="p-3 border-b border-white/10">
                <div className="relative">
                  <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
                  <input
                    ref={searchRef}
                    type="text"
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                    placeholder="Search options..."
                    className="w-full pl-10 pr-4 py-2 bg-white/5 border border-white/10 rounded-xl text-white placeholder-gray-400 focus:outline-none focus:border-cyan-400/50"
                  />
                </div>
              </div>
            )}

            <div className="max-h-48 overflow-y-auto">
              {filteredOptions.length === 0 ? (
                <div className="px-4 py-3 text-gray-400 text-center">
                  No options found
                </div>
              ) : (
                filteredOptions.map((option, index) => (
                  <motion.button
                    key={option.value}
                    type="button"
                    onClick={() => handleSelect(option)}
                    className={`
                      w-full px-4 py-3 text-left flex items-center justify-between
                      transition-colors duration-150 hover:bg-white/10
                      ${focusedIndex === index ? 'bg-white/10' : ''}
                      ${isSelected(option) ? 'text-cyan-400' : 'text-white'}
                    `}
                    whileHover={{ x: 4 }}
                    transition={{ duration: 0.1 }}
                  >
                    <span>{option.label}</span>
                    {isSelected(option) && (
                      <Check className="h-4 w-4 text-cyan-400" />
                    )}
                  </motion.button>
                ))
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {error && (
        <motion.p
          initial={{ opacity: 0, height: 0 }}
          animate={{ opacity: 1, height: 'auto' }}
          className="mt-2 text-sm text-red-400"
        >
          {error}
        </motion.p>
      )}
    </div>
  )
}

export default Select
