import React, { useState } from 'react'
import { Link } from 'react-router-dom'
import { Shield, Github, Mail, ExternalLink } from 'lucide-react'
import LegalContentModal from './LegalContentModal'

const Footer = () => {
  const [modalOpen, setModalOpen] = useState(false)
  const [modalContent, setModalContent] = useState(null)

  // Use package.json version if available, or hardcode
  const appVersion = "v2.0.0"

  const openModal = (contentType) => {
    setModalContent(contentType)
    setModalOpen(true)
  }

  const closeModal = () => {
    setModalOpen(false)
    setModalContent(null)
  }

  return (
    <>
      <footer className="relative mt-auto border-t border-neutral-800 bg-neutral-900/50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
          <div className="flex flex-col md:flex-row justify-between items-center gap-4">

            {/* Left Side: Copyright & Version */}
            <div className="flex flex-col md:flex-row items-center gap-4">
              <div className="flex items-center gap-2">
                <Shield className="h-4 w-4 text-cyan-500/50" />
                <span className="text-sm text-neutral-500">
                  ByteGuardX {appVersion}
                </span>
              </div>
              <span className="hidden md:inline text-neutral-700">|</span>
              <span className="text-sm text-neutral-500">
                Offline Security Scanner
              </span>
            </div>

            {/* Right Side: Links */}
            <div className="flex items-center gap-6">
              <button
                onClick={() => openModal('license')}
                className="text-sm text-neutral-500 hover:text-neutral-300 transition-colors"
              >
                License
              </button>
              <a
                href="https://github.com/byteguardx/byteguardx"
                target="_blank"
                rel="noreferrer"
                className="text-neutral-500 hover:text-white transition-colors"
                aria-label="GitHub"
              >
                <Github className="h-4 w-4" />
              </a>
            </div>

          </div>
        </div>
      </footer>

      {/* Legal Output Modal */}
      <LegalContentModal
        isOpen={modalOpen}
        onClose={closeModal}
        contentType={modalContent}
      />
    </>
  )
}

export default Footer
