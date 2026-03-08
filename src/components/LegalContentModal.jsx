import React, { useEffect } from 'react'
import { X, FileText } from 'lucide-react'
import { legalContent } from '../legal/legalContent'

const LegalContentModal = ({ isOpen, onClose, contentType }) => {
  useEffect(() => {
    const handleEscKey = (e) => { if (e.key === 'Escape') onClose() }
    if (isOpen) { document.addEventListener('keydown', handleEscKey); document.body.style.overflow = 'hidden' }
    return () => { document.removeEventListener('keydown', handleEscKey); document.body.style.overflow = 'unset' }
  }, [isOpen, onClose])

  if (!isOpen || !contentType || !legalContent[contentType]) return null
  const content = legalContent[contentType]

  const formatContent = (text) => {
    return text.split('\n').map((line, i) => {
      if (line.startsWith('# ')) return <h1 key={i} className="text-sm font-bold text-text-primary mb-2 mt-4">{line.substring(2)}</h1>
      if (line.startsWith('## ')) return <h2 key={i} className="text-xs font-semibold text-text-primary mb-1.5 mt-3">{line.substring(3)}</h2>
      if (line.startsWith('### ')) return <h3 key={i} className="text-xs font-medium text-text-primary mb-1 mt-2">{line.substring(4)}</h3>
      if (line.startsWith('**') && line.endsWith('**')) return <p key={i} className="text-[11px] text-text-secondary mb-1 font-semibold">{line.slice(2, -2)}</p>
      if (line.startsWith('- ')) return <li key={i} className="text-[11px] text-text-muted mb-0.5 ml-3">{line.substring(2)}</li>
      if (/^\d+\./.test(line)) return <li key={i} className="text-[11px] text-text-muted mb-0.5 ml-3 list-decimal">{line.substring(line.indexOf('.') + 2)}</li>
      if (line.trim() === '') return <div key={i} className="mb-1" />
      if (line.trim() === '---') return <hr key={i} className="border-desktop-border my-3" />
      return <p key={i} className="text-[11px] text-text-muted mb-1.5 leading-relaxed">{line}</p>
    })
  }

  return (
    <div className="fixed inset-0 bg-black/60 z-50 flex items-center justify-center p-4" onClick={onClose}>
      <div className="desktop-panel w-full max-w-3xl max-h-[80vh] overflow-hidden" onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center justify-between px-4 py-3 border-b border-desktop-border">
          <div className="flex items-center gap-2">
            <FileText className="h-3.5 w-3.5 text-primary-400" />
            <h2 className="text-xs font-semibold text-text-primary">{content.title}</h2>
          </div>
          <button onClick={onClose} className="p-1 text-text-muted hover:text-text-primary rounded transition-colors" aria-label="Close">
            <X className="h-3.5 w-3.5" />
          </button>
        </div>
        <div className="p-4 overflow-y-auto max-h-[calc(80vh-88px)]">
          {formatContent(content.content)}
        </div>
        <div className="flex justify-end px-4 py-2.5 border-t border-desktop-border">
          <button onClick={onClose} className="btn-ghost text-xs px-3 py-1.5">Close</button>
        </div>
      </div>
    </div>
  )
}

export default LegalContentModal
