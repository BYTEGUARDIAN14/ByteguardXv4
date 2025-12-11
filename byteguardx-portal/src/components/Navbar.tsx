import React, { useState, useEffect } from 'react'
import { motion } from 'framer-motion'
import { Shield, Menu, X, Download, Zap, Monitor, Crown, Headphones, Image, BarChart3 } from 'lucide-react'

const Navbar: React.FC = () => {
  const [isOpen, setIsOpen] = useState(false)
  const [activeSection, setActiveSection] = useState('hero')

  const navigation = [
    { name: 'Home', href: '#hero', icon: Shield },
    { name: 'Features', href: '#features', icon: Zap },
    { name: 'Platforms', href: '#platforms', icon: Monitor },
    { name: 'Gallery', href: '#gallery', icon: Image },
    { name: 'Download', href: '#download', icon: Download },
    { name: 'Compare', href: '#comparison', icon: BarChart3 },
    { name: 'Pricing', href: '#pricing', icon: Crown },
    { name: 'Support', href: '#support', icon: Headphones },
  ]

  // Smooth scroll to section
  const scrollToSection = (sectionId: string) => {
    const element = document.getElementById(sectionId.replace('#', ''))
    if (element) {
      element.scrollIntoView({ behavior: 'smooth' })
    }
    setIsOpen(false)
  }

  // Track active section
  useEffect(() => {
    const handleScroll = () => {
      const sections = ['hero', 'features', 'platforms', 'gallery', 'download', 'comparison', 'pricing', 'support']
      const scrollPosition = window.scrollY + 100

      for (const section of sections) {
        const element = document.getElementById(section)
        if (element) {
          const { offsetTop, offsetHeight } = element
          if (scrollPosition >= offsetTop && scrollPosition < offsetTop + offsetHeight) {
            setActiveSection(section)
            break
          }
        }
      }
    }

    window.addEventListener('scroll', handleScroll)
    return () => window.removeEventListener('scroll', handleScroll)
  }, [])

  const isActive = (href: string) => activeSection === href.replace('#', '')

  return (
    <nav className="fixed top-0 left-0 right-0 z-50 glass-nav border-b border-white/15">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex justify-between items-center h-16">
          {/* Logo */}
          <motion.button
            onClick={() => scrollToSection('#hero')}
            className="flex items-center space-x-3 group"
            whileHover={{ scale: 1.02 }}
            whileTap={{ scale: 0.98 }}
          >
            <motion.div
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.95 }}
              className="p-2 glass-panel rounded-xl group-hover:bg-white/10 transition-all duration-300"
            >
              <Shield className="h-6 w-6 text-white group-hover:text-cyan-400 transition-colors duration-300" />
            </motion.div>
            <div className="flex flex-col">
              <span className="text-xl font-bold gradient-text">ByteGuardX</span>
              <span className="text-xs text-gray-300 -mt-1 font-light">AI-Powered Scanner</span>
            </div>
          </motion.button>

          {/* Desktop Navigation */}
          <div className="hidden md:flex items-center space-x-2">
            {navigation.map((item) => {
              const Icon = item.icon
              return (
                <motion.button
                  key={item.name}
                  onClick={() => scrollToSection(item.href)}
                  className={`
                    flex items-center space-x-2 px-4 py-2 rounded-xl text-sm font-medium transition-all duration-300
                    ${isActive(item.href)
                      ? 'text-cyan-400 bg-cyan-400/10 border border-cyan-400/20 backdrop-blur-10'
                      : 'text-gray-300 hover:text-cyan-400 hover:bg-white/5 border border-transparent hover:border-cyan-400/20 backdrop-blur-10'
                    }
                  `}
                  whileHover={{ scale: 1.05 }}
                  whileTap={{ scale: 0.95 }}
                >
                  <Icon className="h-4 w-4" />
                  <span>{item.name}</span>
                </motion.button>
              )
            })}
          </div>

          {/* CTA Button */}
          <div className="hidden md:flex items-center space-x-4">
            <motion.button
              onClick={() => scrollToSection('#download')}
              className="glass-card px-6 py-2 text-cyan-400 hover:text-white hover:border-cyan-400/50 transition-all duration-300 flex items-center space-x-2"
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.95 }}
            >
              <Download className="h-4 w-4" />
              <span>Get Started</span>
            </motion.button>
          </div>

          {/* Mobile menu button */}
          <div className="md:hidden">
            <button
              onClick={() => setIsOpen(!isOpen)}
              className="p-2 rounded-lg text-gray-400 hover:text-white hover:bg-gray-800 transition-colors"
            >
              {isOpen ? <X className="h-6 w-6" /> : <Menu className="h-6 w-6" />}
            </button>
          </div>
        </div>

        {/* Mobile Navigation */}
        {isOpen && (
          <motion.div
            initial={{ opacity: 0, y: -10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -10 }}
            className="md:hidden py-4 border-t border-gray-800"
          >
            <div className="flex flex-col space-y-2">
              {navigation.map((item) => {
                const Icon = item.icon
                return (
                  <motion.button
                    key={item.name}
                    onClick={() => scrollToSection(item.href)}
                    className={`
                      flex items-center space-x-3 px-4 py-3 rounded-xl text-sm font-medium transition-all duration-300
                      ${isActive(item.href)
                        ? 'text-cyan-400 bg-cyan-400/10 border border-cyan-400/20'
                        : 'text-gray-300 hover:text-cyan-400 hover:bg-white/5 border border-transparent hover:border-cyan-400/20'
                      }
                    `}
                    whileHover={{ scale: 1.02 }}
                    whileTap={{ scale: 0.98 }}
                  >
                    <Icon className="h-4 w-4" />
                    <span>{item.name}</span>
                  </motion.button>
                )
              })}
              <div className="pt-4 border-t border-gray-800">
                <motion.button
                  onClick={() => scrollToSection('#download')}
                  className="flex items-center justify-center space-x-2 w-full px-4 py-3 bg-cyan-600 hover:bg-cyan-700 text-white rounded-xl font-medium transition-colors"
                  whileHover={{ scale: 1.02 }}
                  whileTap={{ scale: 0.98 }}
                >
                  <Download className="h-4 w-4" />
                  <span>Get Started</span>
                </motion.button>
              </div>
            </div>
          </motion.div>
        )}
      </div>
    </nav>
  )
}

export default Navbar
