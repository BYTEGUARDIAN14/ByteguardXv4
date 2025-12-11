import React, { useState, useEffect } from 'react'
import { motion } from 'framer-motion'
import {
  Download as DownloadIcon,
  Monitor,
  Smartphone,
  Terminal,
  Chrome,
  Code,
  CheckCircle,
  ExternalLink,
  Apple,
  Zap
} from 'lucide-react'

const Download: React.FC = () => {
  const [detectedOS, setDetectedOS] = useState<string>('Unknown')

  useEffect(() => {
    const userAgent = navigator.userAgent
    if (userAgent.includes('Windows')) setDetectedOS('Windows')
    else if (userAgent.includes('Mac')) setDetectedOS('macOS')
    else if (userAgent.includes('Linux')) setDetectedOS('Linux')
    else setDetectedOS('Unknown')
  }, [])

  const desktopDownloads = [
    {
      os: 'Windows',
      icon: Monitor,
      primary: true,
      downloads: [
        { name: 'Windows Installer (.exe)', size: '45 MB', href: '#', recommended: true },
        { name: 'Portable (.zip)', size: '42 MB', href: '#' },
        { name: 'Windows Store', size: 'Auto', href: '#' },
      ]
    },
    {
      os: 'macOS',
      icon: Apple,
      primary: true,
      downloads: [
        { name: 'macOS Installer (.dmg)', size: '48 MB', href: '#', recommended: true },
        { name: 'Homebrew', size: 'Auto', href: '#', command: 'brew install byteguardx' },
        { name: 'App Store', size: 'Auto', href: '#' },
      ]
    },
    {
      os: 'Linux',
      icon: Terminal,
      primary: true,
      downloads: [
        { name: 'AppImage (Universal)', size: '52 MB', href: '#', recommended: true },
        { name: 'Debian Package (.deb)', size: '44 MB', href: '#' },
        { name: 'RPM Package (.rpm)', size: '46 MB', href: '#' },
        { name: 'Snap Package', size: 'Auto', href: '#', command: 'sudo snap install byteguardx' },
      ]
    }
  ]

  const otherDownloads = [
    {
      category: 'Mobile Apps',
      icon: Smartphone,
      items: [
        { name: 'iOS App', href: '#', badge: 'App Store' },
        { name: 'Android App', href: '#', badge: 'Google Play' },
        { name: 'React Native (Beta)', href: '#', badge: 'TestFlight' },
      ]
    },
    {
      category: 'Browser Extensions',
      icon: Chrome,
      items: [
        { name: 'Chrome Extension', href: '#', badge: 'Chrome Store' },
        { name: 'Firefox Extension', href: '#', badge: 'Firefox Add-ons' },
        { name: 'Edge Extension', href: '#', badge: 'Edge Store' },
      ]
    },
    {
      category: 'Developer Tools',
      icon: Code,
      items: [
        { name: 'VS Code Extension', href: '#', badge: 'Marketplace' },
        { name: 'CLI Tool (pip)', href: '#', command: 'pip install byteguardx' },
        { name: 'CLI Tool (npm)', href: '#', command: 'npm install -g byteguardx' },
      ]
    }
  ]

  const features = [
    'AI-powered vulnerability detection',
    'Offline-first architecture',
    'Enterprise security features',
    'Multi-language support (50+)',
    'Professional PDF reports',
    'Git hooks integration',
    'CI/CD pipeline support',
    'Plugin system & extensibility'
  ]

  return (
    <div className="relative min-h-screen py-20 bg-gradient-to-br from-black via-gray-950 to-black overflow-hidden">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Header */}
        <div className="text-center mb-20">
          <motion.div
            initial={{ opacity: 0, y: 30 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.8 }}
          >
            <div className="flex justify-center mb-8">
              <div className="glass-panel p-6 rounded-3xl">
                <DownloadIcon className="h-16 w-16 text-cyan-400" />
              </div>
            </div>
            <h1 className="text-4xl md:text-5xl font-bold mb-8">
              Download <span className="gradient-text">ByteGuardX</span>
            </h1>
            <p className="text-xl text-gray-300 max-w-2xl mx-auto mb-10 font-light leading-relaxed">
              Get started with ByteGuardX on your preferred platform. All downloads are free and include enterprise features.
            </p>

            {detectedOS !== 'Unknown' && (
              <motion.div
                className="inline-flex items-center space-x-3 glass-panel px-6 py-3 rounded-2xl"
                initial={{ opacity: 0, scale: 0.9 }}
                animate={{ opacity: 1, scale: 1 }}
                transition={{ duration: 0.5, delay: 0.3 }}
              >
                <Zap className="h-5 w-5 text-cyan-400" />
                <span className="text-sm text-gray-300">We detected you're using <strong className="text-white">{detectedOS}</strong></span>
              </motion.div>
            )}
          </motion.div>
        </div>

        {/* Primary Downloads */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8 mb-20">
          {desktopDownloads.map((platform, index) => {
            const Icon = platform.icon
            const isDetected = platform.os === detectedOS

            return (
              <motion.div
                key={platform.os}
                initial={{ opacity: 0, y: 30 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.8, delay: index * 0.1 }}
                className={`glass-card hover-lift ${isDetected ? 'border-cyan-400/30 hover-glow' : ''}`}
              >
                <div className="flex items-center space-x-3 mb-6">
                  <div className="p-3 bg-primary-500/10 rounded-lg">
                    <Icon className="h-6 w-6 text-primary-400" />
                  </div>
                  <div>
                    <h3 className="text-xl font-semibold">{platform.os}</h3>
                    {isDetected && (
                      <span className="text-sm text-primary-400">Recommended for you</span>
                    )}
                  </div>
                </div>

                <div className="space-y-3">
                  {platform.downloads.map((download) => (
                    <div key={download.name} className="flex items-center justify-between p-3 bg-gray-800/50 rounded-lg hover:bg-gray-800 transition-colors">
                      <div className="flex-1">
                        <div className="flex items-center space-x-2">
                          <span className="font-medium">{download.name}</span>
                          {download.recommended && (
                            <span className="text-xs bg-primary-500 text-white px-2 py-1 rounded">
                              Recommended
                            </span>
                          )}
                        </div>
                        <div className="text-sm text-gray-400">
                          {download.command ? (
                            <code className="bg-gray-900 px-2 py-1 rounded text-xs">
                              {download.command}
                            </code>
                          ) : (
                            `Size: ${download.size}`
                          )}
                        </div>
                      </div>
                      <a
                        href={download.href}
                        className="btn-primary py-2 px-4 text-sm"
                      >
                        <DownloadIcon className="h-4 w-4 mr-1" />
                        Download
                      </a>
                    </div>
                  ))}
                </div>
              </motion.div>
            )
          })}
        </div>

        {/* Other Downloads */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-8 mb-16">
          {otherDownloads.map((category, index) => {
            const Icon = category.icon
            return (
              <motion.div
                key={category.category}
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.6, delay: 0.3 + index * 0.1 }}
                className="card p-6"
              >
                <div className="flex items-center space-x-3 mb-4">
                  <div className="p-2 bg-primary-500/10 rounded-lg">
                    <Icon className="h-5 w-5 text-primary-400" />
                  </div>
                  <h3 className="text-lg font-semibold">{category.category}</h3>
                </div>

                <div className="space-y-3">
                  {category.items.map((item) => (
                    <div key={item.name} className="flex items-center justify-between">
                      <div>
                        <div className="font-medium">{item.name}</div>
                        {item.command && (
                          <code className="text-xs bg-gray-900 px-2 py-1 rounded text-gray-400">
                            {item.command}
                          </code>
                        )}
                      </div>
                      <a
                        href={item.href}
                        className="flex items-center space-x-1 text-primary-400 hover:text-primary-300 text-sm"
                      >
                        <span>{item.badge}</span>
                        <ExternalLink className="h-3 w-3" />
                      </a>
                    </div>
                  ))}
                </div>
              </motion.div>
            )
          })}
        </div>

        {/* Features */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8, delay: 0.6 }}
          className="card p-8"
        >
          <h3 className="text-2xl font-bold mb-6 text-center">What's Included</h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {features.map((feature) => (
              <div key={feature} className="flex items-center space-x-3">
                <CheckCircle className="h-5 w-5 text-green-500 flex-shrink-0" />
                <span>{feature}</span>
              </div>
            ))}
          </div>
        </motion.div>

        {/* System Requirements */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8, delay: 0.8 }}
          className="mt-16 text-center"
        >
          <h3 className="text-xl font-semibold mb-4">System Requirements</h3>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-8 text-sm text-gray-400">
            <div>
              <h4 className="font-medium text-white mb-2">Windows</h4>
              <p>Windows 10/11 (64-bit)<br />4GB RAM, 500MB disk space</p>
            </div>
            <div>
              <h4 className="font-medium text-white mb-2">macOS</h4>
              <p>macOS 10.15+ (Intel/Apple Silicon)<br />4GB RAM, 500MB disk space</p>
            </div>
            <div>
              <h4 className="font-medium text-white mb-2">Linux</h4>
              <p>Ubuntu 18.04+, CentOS 7+<br />4GB RAM, 500MB disk space</p>
            </div>
          </div>
        </motion.div>
      </div>
    </div>
  )
}

export default Download
