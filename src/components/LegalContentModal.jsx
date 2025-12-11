import React, { useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { X, FileText } from 'lucide-react'
import { legalContent } from '../legal/legalContent'

const LegalContentModal = ({ isOpen, onClose, contentType }) => {
  // Handle ESC key press
  useEffect(() => {
    const handleEscKey = (event) => {
      if (event.key === 'Escape') {
        onClose()
      }
    }

    if (isOpen) {
      document.addEventListener('keydown', handleEscKey)
      // Prevent body scroll when modal is open
      document.body.style.overflow = 'hidden'
    }

    return () => {
      document.removeEventListener('keydown', handleEscKey)
      document.body.style.overflow = 'unset'
    }
  }, [isOpen, onClose])

  if (!isOpen || !contentType || !legalContent[contentType]) {
    return null
  }

  const content = legalContent[contentType]

  // Convert markdown-style content to JSX
  const formatContent = (text) => {
    return text.split('\n').map((line, index) => {
      // Handle headers
      if (line.startsWith('# ')) {
        return (
          <h1 key={index} className="text-2xl font-bold text-white mb-4 mt-6">
            {line.substring(2)}
          </h1>
        )
      }
      if (line.startsWith('## ')) {
        return (
          <h2 key={index} className="text-xl font-semibold text-white mb-3 mt-5">
            {line.substring(3)}
          </h2>
        )
      }
      if (line.startsWith('### ')) {
        return (
          <h3 key={index} className="text-lg font-medium text-white mb-2 mt-4">
            {line.substring(4)}
          </h3>
        )
      }

      // Handle bold text
      if (line.startsWith('**') && line.endsWith('**')) {
        return (
          <p key={index} className="text-gray-300 mb-2 font-semibold">
            {line.substring(2, line.length - 2)}
          </p>
        )
      }

      // Handle list items
      if (line.startsWith('- ')) {
        return (
          <li key={index} className="text-gray-300 mb-1 ml-4">
            {line.substring(2)}
          </li>
        )
      }

      // Handle numbered lists
      if (/^\d+\./.test(line)) {
        return (
          <li key={index} className="text-gray-300 mb-1 ml-4 list-decimal">
            {line.substring(line.indexOf('.') + 2)}
          </li>
        )
      }

      // Handle empty lines
      if (line.trim() === '') {
        return <div key={index} className="mb-2"></div>
      }

      // Handle horizontal rules
      if (line.trim() === '---') {
        return <hr key={index} className="border-gray-700 my-6" />
      }

      // Regular paragraphs
      return (
        <p key={index} className="text-gray-300 mb-3 leading-relaxed">
          {line}
        </p>
      )
    })
  }

  return (
    <AnimatePresence>
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        className="fixed inset-0 bg-black/50 backdrop-blur-sm z-50 flex items-center justify-center p-4"
        onClick={onClose}
      >
        <motion.div
          initial={{ opacity: 0, scale: 0.95, y: 20 }}
          animate={{ opacity: 1, scale: 1, y: 0 }}
          exit={{ opacity: 0, scale: 0.95, y: 20 }}
          transition={{ duration: 0.2, ease: "easeOut" }}
          className="glass-card w-full max-w-4xl max-h-[90vh] overflow-hidden"
          onClick={(e) => e.stopPropagation()}
        >
          {/* Header */}
          <div 
            className="flex items-center justify-between p-6 border-b border-white/10 bg-black/20"
          >
            <div className="flex items-center space-x-3">
              <FileText className="h-6 w-6 text-cyan-400" />
              <h2 className="text-xl font-semibold text-white">{content.title}</h2>
            </div>
            <button
              onClick={onClose}
              className="p-2 text-gray-400 hover:text-white transition-colors rounded-lg hover:bg-white/10"
              aria-label="Close modal"
            >
              <X className="h-5 w-5" />
            </button>
          </div>

          {/* Content */}
          <div className="p-6 overflow-y-auto max-h-[calc(90vh-120px)]">
            <div className="prose prose-invert max-w-none">
              {formatContent(content.content)}
            </div>
          </div>

          {/* Footer */}
          <div className="flex items-center justify-end p-6 border-t border-white/10 bg-black/20">
            <button
              onClick={onClose}
              className="btn-secondary"
            >
              Close
            </button>
          </div>
        </motion.div>
      </motion.div>
    </AnimatePresence>
  )
}

export default LegalContentModal
