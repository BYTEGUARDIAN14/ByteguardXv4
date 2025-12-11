import React, { useState } from 'react'
import { Link } from 'react-router-dom'
import { Shield, Github, Twitter, Mail, ExternalLink } from 'lucide-react'
import LegalContentModal from './LegalContentModal'

const Footer = () => {
  const [modalOpen, setModalOpen] = useState(false)
  const [modalContent, setModalContent] = useState(null)
  const currentYear = new Date().getFullYear()

  const openModal = (contentType) => {
    setModalContent(contentType)
    setModalOpen(true)
  }

  const closeModal = () => {
    setModalOpen(false)
    setModalContent(null)
  }

  const footerLinks = {
    product: [
      { name: 'Scan', href: '/scan' },
      { name: 'Reports', href: '/reports' },
      { name: 'Dashboard', href: '/dashboard' },
      { name: 'Plugins', href: '/plugins' },
    ],
    resources: [
      { name: 'Documentation', href: 'https://docs.byteguardx.com', external: true },
      { name: 'API Reference', href: 'https://docs.byteguardx.com/api', external: true },
      { name: 'CLI Guide', href: 'https://docs.byteguardx.com/cli', external: true },
      { name: 'Examples', href: 'https://docs.byteguardx.com/examples', external: true },
    ],
    support: [
      { name: 'Help Center', href: 'https://support.byteguardx.com', external: true },
      { name: 'Contact Us', href: 'mailto:support@byteguardx.com', external: true },
      { name: 'Bug Reports', href: 'https://github.com/byteguardx/byteguardx/issues', external: true },
      { name: 'Feature Requests', href: 'https://github.com/byteguardx/byteguardx/discussions', external: true },
    ],
    legal: [
      { name: 'Privacy Policy', action: () => openModal('privacy') },
      { name: 'Terms of Service', action: () => openModal('terms') },
      { name: 'Security Policy', action: () => openModal('security') },
      { name: 'License', action: () => openModal('license') },
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
                <Link to="/" className="flex items-center space-x-3 group mb-6">
                  <div className="glass-panel p-3 rounded-xl group-hover:border-cyan-400/30 transition-all duration-300">
                    <Shield className="h-6 w-6 text-cyan-400" />
                  </div>
                  <div className="flex flex-col">
                    <span className="text-xl font-bold gradient-text">ByteGuardX</span>
                    <span className="text-xs text-gray-400 -mt-1">AI-Powered Scanner</span>
                  </div>
                </Link>
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
                        {link.external ? (
                          <a
                            href={link.href}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-gray-400 hover:text-white text-sm transition-colors duration-200 flex items-center space-x-1"
                          >
                            <span>{link.name}</span>
                            <ExternalLink className="h-3 w-3" />
                          </a>
                        ) : link.action ? (
                          <button
                            onClick={link.action}
                            className="text-gray-400 hover:text-white text-sm transition-colors duration-200 text-left"
                          >
                            {link.name}
                          </button>
                        ) : (
                          <Link
                            to={link.href}
                            className="text-gray-400 hover:text-white text-sm transition-colors duration-200"
                          >
                            {link.name}
                          </Link>
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
