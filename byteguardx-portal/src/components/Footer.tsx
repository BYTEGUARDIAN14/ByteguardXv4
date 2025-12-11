import React, { useState } from 'react'
import { motion } from 'framer-motion'
import { Shield, Github, Twitter, Mail, ExternalLink } from 'lucide-react'
import LegalContentModal from './LegalContentModal'
import { legalContent } from '../legal/legalContent'

const Footer: React.FC = () => {
  const [modalOpen, setModalOpen] = useState(false)
  const [modalContent, setModalContent] = useState<keyof typeof legalContent | null>(null)
  const currentYear = new Date().getFullYear()

  const openModal = (contentType: keyof typeof legalContent) => {
    setModalContent(contentType)
    setModalOpen(true)
  }

  const closeModal = () => {
    setModalOpen(false)
    setModalContent(null)
  }

  // Smooth scroll to section
  const scrollToSection = (sectionId: string) => {
    const element = document.getElementById(sectionId.replace('#', ''))
    if (element) {
      element.scrollIntoView({ behavior: 'smooth' })
    }
  }

  type FooterLink = {
    name: string
    href: string
    external?: boolean
    action?: () => void
  }

  const footerLinks: Record<string, FooterLink[]> = {
    product: [
      { name: 'Download', href: '#download' },
      { name: 'Platforms', href: '#platforms' },
      { name: 'Compare', href: '#comparison' },
      { name: 'Pricing', href: '#pricing' },
    ],
    resources: [
      { name: 'Features', href: '#features' },
      { name: 'Gallery', href: '#gallery' },
      { name: 'Documentation', href: 'https://docs.byteguardx.com', external: true },
      { name: 'API Reference', href: 'https://api.byteguardx.com', external: true },
    ],
    support: [
      { name: 'Help Center', href: '#support' },
      { name: 'Contact Us', href: '#support' },
      { name: 'Bug Reports', href: 'https://github.com/byteguardx/byteguardx/issues', external: true },
      { name: 'Feature Requests', href: 'https://github.com/byteguardx/byteguardx/discussions', external: true },
    ],
    legal: [
      { name: 'Privacy Policy', href: '', action: () => openModal('privacy') },
      { name: 'Terms of Service', href: '', action: () => openModal('terms') },
      { name: 'Security Policy', href: '', action: () => openModal('security') },
      { name: 'License', href: '', action: () => openModal('license') },
    ],
  }

  const socialLinks = [
    { name: 'GitHub', href: 'https://github.com/byteguardx/byteguardx', icon: Github },
    { name: 'Twitter', href: 'https://twitter.com/byteguardx', icon: Twitter },
    { name: 'Email', href: 'mailto:hello@byteguardx.com', icon: Mail },
  ]

  return (
    <>
    <footer className="relative mt-20">
      <div className="glass-panel border-t border-white/10">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-16">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-6 gap-8">
            {/* Brand */}
            <div className="lg:col-span-2">
              <motion.button
                onClick={() => scrollToSection('#hero')}
                className="flex items-center space-x-3 group mb-6"
                whileHover={{ scale: 1.02 }}
                whileTap={{ scale: 0.98 }}
              >
                <div className="glass-panel p-3 rounded-xl group-hover:border-cyan-400/30 transition-all duration-300">
                  <Shield className="h-6 w-6 text-cyan-400" />
                </div>
                <div className="flex flex-col">
                  <span className="text-xl font-bold gradient-text">ByteGuardX</span>
                  <span className="text-xs text-gray-400 -mt-1">AI-Powered Scanner</span>
                </div>
              </motion.button>
              <p className="text-gray-400 text-sm mb-6 max-w-sm">
                Comprehensive, offline-first security vulnerability scanner with AI-powered pattern detection for developers and security teams.
              </p>
              <div className="flex space-x-4">
                {socialLinks.map((social) => {
                  const Icon = social.icon
                  return (
                    <a
                      key={social.name}
                      href={social.href}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="p-2 text-gray-400 hover:text-cyan-400 hover:bg-gray-800 rounded-lg transition-all duration-200"
                      aria-label={social.name}
                    >
                      <Icon className="h-5 w-5" />
                    </a>
                  )
                })}
              </div>
            </div>

            {/* Links */}
            {Object.entries(footerLinks).map(([category, links]) => (
              <div key={category}>
                <h3 className="text-white font-semibold mb-4 capitalize">{category}</h3>
                <ul className="space-y-3">
                  {links.map((link) => (
                    <li key={link.name}>
                      {'external' in link && link.external ? (
                        <a
                          href={link.href}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-gray-400 hover:text-white text-sm transition-colors duration-200 flex items-center space-x-1"
                        >
                          <span>{link.name}</span>
                          <ExternalLink className="h-3 w-3" />
                        </a>
                      ) : 'action' in link && link.action ? (
                        <button
                          onClick={link.action}
                          className="text-gray-400 hover:text-white text-sm transition-colors duration-200 text-left"
                        >
                          {link.name}
                        </button>
                      ) : (
                        <motion.button
                          onClick={() => scrollToSection(link.href)}
                          className="text-gray-400 hover:text-white text-sm transition-colors duration-200 text-left"
                          whileHover={{ x: 2 }}
                        >
                          {link.name}
                        </motion.button>
                      )}
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </div>

          {/* Bottom */}
          <div className="mt-12 pt-8 border-t border-gray-800 flex flex-col md:flex-row justify-between items-center">
            <p className="text-gray-400 text-sm">
              © {currentYear} ByteGuardX. All rights reserved.
            </p>
            <div className="flex items-center space-x-2 mt-4 md:mt-0">
              <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse"></div>
              <span className="text-gray-400 text-sm">All systems operational</span>
            </div>
          </div>
        </div>
      </div>
    </footer>

    {/* Legal Content Modal */}
    <LegalContentModal
      isOpen={modalOpen}
      onClose={closeModal}
      contentType={modalContent}
    />
    </>
  )
}

export default Footer
